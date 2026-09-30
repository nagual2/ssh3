package client

// ControlMaster server side (stage 3.5): ServeControlMaster shares one
// authenticated connection across CLI invocations. Slaves open sessions and
// attach their streams over the UDS control channel (client/cm); the master
// relays session bytes between the attached streams and the ssh3 channels.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client/cm"
)

// ListenControlMaster creates and prepares the control-master UDS listener
// with 0600 permissions.
func ListenControlMaster(path string) (net.Listener, error) {
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// cmSession is one slave-requested session awaiting or running its bridge.
type cmSession struct {
	token        cm.Token
	channel      ssh3.Channel
	ptyRequested bool
	control      net.Conn

	mu      sync.Mutex
	stderr  net.Conn
	started bool
}

// ServeControlMaster serves the control channel on ln until ctx is done or
// a slave sends EXIT. The connection must be an authenticated Client; every
// slave session then runs as a channel on this connection.
func ServeControlMaster(ctx context.Context, c *Client, ln net.Listener) error {
	var mu sync.Mutex
	sessions := make(map[cm.Token]*cmSession)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go handleMasterConn(ctx, c, conn, sessions, &mu, ln)
	}
}

func masterSendError(conn net.Conn, msg string) {
	cm.WriteFrame(conn, cm.MsgError, []byte(msg))
}

// handleMasterConn drives one control or stream attachment connection.
// Connections whose ownership moves to a session bridge (attach conns, and
// the control conn of a started session) are closed by the bridge, not here.
func handleMasterConn(ctx context.Context, c *Client, conn net.Conn,
	sessions map[cm.Token]*cmSession, mu *sync.Mutex, ln net.Listener) {

	moved := false
	defer func() {
		if !moved {
			conn.Close()
		}
	}()

	typ, _, err := cm.ReadFrame(conn)
	if err != nil {
		return
	}
	if typ != cm.MsgHello {
		masterSendError(conn, "expected HELLO")
		return
	}
	if err := cm.WriteFrame(conn, cm.MsgOK, nil); err != nil {
		return
	}

	for {
		typ, payload, err := cm.ReadFrame(conn)
		if err != nil {
			return
		}
		switch typ {
		case cm.MsgOpenSession:
			var req cm.OpenSession
			if err := req.Decode(payload); err != nil {
				masterSendError(conn, fmt.Sprintf("malformed OPEN_SESSION: %v", err))
				continue
			}
			sess, err := masterOpenSession(ctx, c, &req)
			if err != nil {
				masterSendError(conn, err.Error())
				continue
			}
			sess.control = conn
			mu.Lock()
			sessions[sess.token] = sess
			mu.Unlock()
			if err := cm.WriteFrame(conn, cm.MsgOK, sess.token[:]); err != nil {
				return
			}
			log.Debug().Msgf("master: opened session %.8x for slave", sess.token)

		case cm.MsgAttach:
			var att cm.Attach
			if err := att.Decode(payload); err != nil {
				masterSendError(conn, fmt.Sprintf("malformed ATTACH: %v", err))
				return
			}
			mu.Lock()
			sess := sessions[att.Token]
			mu.Unlock()
			if sess == nil {
				masterSendError(conn, "unknown session token")
				return
			}
			switch att.Stream {
			case cm.StreamStderr:
				sess.mu.Lock()
				if sess.started || sess.stderr != nil {
					sess.mu.Unlock()
					masterSendError(conn, "stderr stream already attached")
					return
				}
				sess.stderr = conn
				sess.mu.Unlock()
				if err := cm.WriteFrame(conn, cm.MsgOK, nil); err != nil {
					return
				}
				moved = true // the bridge owns this connection now
				log.Debug().Msgf("master: attached stderr stream for session %.8x", att.Token)

			case cm.StreamIO:
				sess.mu.Lock()
				if sess.started {
					sess.mu.Unlock()
					masterSendError(conn, "session already started")
					return
				}
				sess.started = true
				errConn := sess.stderr
				sess.mu.Unlock()
				if errConn == nil {
					masterSendError(conn, "the stderr stream must attach before the io stream")
					return
				}
				if err := cm.WriteFrame(conn, cm.MsgOK, nil); err != nil {
					return
				}
				moved = true
				log.Debug().Msgf("master: attached io stream for session %.8x, starting bridge", att.Token)
				go runMasterBridge(sess, conn, errConn, sessions, mu)
				return // the control conn also belongs to the bridge now

			default:
				masterSendError(conn, "unknown stream kind")
				return
			}

		case cm.MsgExit:
			if err := cm.WriteFrame(conn, cm.MsgOK, nil); err == nil {
				log.Debug().Msgf("master: shutdown requested, closing control socket")
				ln.Close()
			}
			return

		default:
			masterSendError(conn, fmt.Sprintf("unexpected message %v", typ))
			return
		}
	}
}

func masterOpenSession(ctx context.Context, c *Client, req *cm.OpenSession) (*cmSession, error) {
	if req.ForwardAgent {
		return nil, errors.New("agent forwarding through the master is not supported yet")
	}
	token, err := cm.NewToken()
	if err != nil {
		return nil, err
	}
	spec := SessionSpec{Command: req.Command}
	if req.Pty != nil {
		spec.Pty = &PtySpec{
			Term:        req.Pty.Term,
			Columns:     uint64(req.Pty.Columns),
			Rows:        uint64(req.Pty.Rows),
			PixelWidth:  uint64(req.Pty.PixelWidth),
			PixelHeight: uint64(req.Pty.PixelHeight),
		}
	}
	channel, ptyRequested, err := c.OpenSession(ctx, spec)
	if err != nil {
		if channel != nil {
			channel.Close()
		}
		return nil, err
	}
	return &cmSession{token: token, channel: channel, ptyRequested: ptyRequested}, nil
}

// runMasterBridge relays one session: the io attachment carries slave stdin
// upstream and session stdout downstream, the stderr attachment carries the
// session's stderr. When the channel ends, the exit status goes back on the
// control connection.
func runMasterBridge(sess *cmSession, ioConn, errConn net.Conn,
	sessions map[cm.Token]*cmSession, mu *sync.Mutex) {

	defer func() {
		ioConn.Close()
		errConn.Close()
		sess.control.Close()
		mu.Lock()
		delete(sessions, sess.token)
		mu.Unlock()
	}()

	err := pumpSessionStreams(sess.channel, sessionIO{
		stdin:  ioConn,
		stdout: ioConn,
		stderr: errConn,
	}, sess.ptyRequested)

	code := 255
	var es ExitStatus
	if errors.As(err, &es) {
		code = es.StatusCode
	} else if err == nil {
		code = 0
	} else {
		log.Debug().Msgf("master: session %.8x bridge ended: %v", sess.token, err)
	}
	if err := cm.WriteFrame(sess.control, cm.MsgExitStatus, cm.EncodeExitStatus(uint64(code))); err != nil {
		log.Debug().Msgf("master: could not deliver exit status for session %.8x: %v", sess.token, err)
	}
	log.Debug().Msgf("master: session %.8x finished with status %d", sess.token, code)
}
