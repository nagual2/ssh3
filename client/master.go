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
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client/cm"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

// MasterOptions configures the control-master lifecycle (stage 3.5,
// increment 4: ControlPersist semantics).
type MasterOptions struct {
	// IdleTimeout stops the master after this much inactivity: no control
	// connection traffic and no running sessions. Zero (default) persists
	// until the context ends or a slave sends EXIT.
	IdleTimeout time.Duration
}

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

// ServeControlMaster serves the control channel on ln until ctx is done, a
// slave sends EXIT, or (with MasterOptions.IdleTimeout) the master idles out
// with no running sessions. The connection must be an authenticated Client;
// every slave session then runs as a channel on this connection. On return
// the socket file is removed (clean teardown). Already-running bridges are
// not interrupted by EXIT; closing the underlying Client (typically via the
// caller's ctx) ends them.
func ServeControlMaster(ctx context.Context, c *Client, ln net.Listener, opts *MasterOptions) error {
	if opts == nil {
		opts = &MasterOptions{}
	}
	var mu sync.Mutex
	sessions := make(map[cm.Token]*cmSession)

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	if opts.IdleTimeout > 0 {
		tick := opts.IdleTimeout / 4
		if tick > time.Second {
			tick = time.Second
		}
		if tick < 50*time.Millisecond {
			tick = 50 * time.Millisecond
		}
		go func() {
			ticker := time.NewTicker(tick)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					mu.Lock()
					running := len(sessions)
					mu.Unlock()
					idle := time.Since(time.Unix(0, lastActivity.Load()))
					if running == 0 && idle >= opts.IdleTimeout {
						log.Debug().Msgf("master: idle for %v, closing control socket", idle.Truncate(time.Millisecond))
						ln.Close()
						return
					}
				}
			}
		}()
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	defer func() {
		ln.Close()
		if addr, ok := ln.Addr().(*net.UnixAddr); ok && addr.Name != "" {
			os.Remove(addr.Name) // clean teardown: no stale socket file
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return nil // EXIT and idle timeout are orderly shutdowns too
			}
		}
		lastActivity.Store(time.Now().UnixNano())
		go handleMasterConn(ctx, c, conn, sessions, &mu, ln, &lastActivity)
	}
}

func masterSendError(conn net.Conn, msg string) {
	cm.WriteFrame(conn, cm.MsgError, []byte(msg))
}

// handleMasterConn drives one control or stream attachment connection.
// Connections whose ownership moves to a session bridge (attach conns, and
// the control conn of a started session) are closed by the bridge, not here.
func handleMasterConn(ctx context.Context, c *Client, conn net.Conn,
	sessions map[cm.Token]*cmSession, mu *sync.Mutex, ln net.Listener,
	lastActivity *atomic.Int64) {

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
		lastActivity.Store(time.Now().UnixNano())
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

		case cm.MsgOpenForwardTCP, cm.MsgOpenForwardUDP:
			var fwd cm.OpenForward
			if err := fwd.Decode(payload); err != nil {
				masterSendError(conn, fmt.Sprintf("malformed OPEN_FORWARD: %v", err))
				continue
			}
			bound, err := masterOpenForward(ctx, c, typ, &fwd)
			if err != nil {
				masterSendError(conn, err.Error())
				continue
			}
			if err := cm.WriteFrame(conn, cm.MsgOK, []byte(bound)); err != nil {
				return
			}
			log.Debug().Msgf("master: forwarding %v from %s to %s (bound %s)", typ, fwd.ListenAddr, fwd.TargetAddr, bound)

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
	token, err := cm.NewToken()
	if err != nil {
		return nil, err
	}
	spec := SessionSpec{Command: req.Command, ForwardAgent: req.ForwardAgent}
	if req.Pty != nil {
		spec.Pty = &PtySpec{
			Term:        req.Pty.Term,
			Columns:     uint64(req.Pty.Columns),
			Rows:        uint64(req.Pty.Rows),
			PixelWidth:  uint64(req.Pty.PixelWidth),
			PixelHeight: uint64(req.Pty.PixelHeight),
		}
	}
	// ForwardAgent passes through: the agent bridge in OpenSession dials
	// SSH_AUTH_SOCK from the master's environment, which is the same socket
	// the slave would reach (same user, same host).
	channel, ptyRequested, err := c.OpenSession(ctx, spec)
	if err != nil {
		if channel != nil {
			channel.Close()
		}
		return nil, err
	}
	return &cmSession{token: token, channel: channel, ptyRequested: ptyRequested}, nil
}

// masterOpenForward starts a local forward on the master: it listens on the
// requested local address and relays connections/datagrams to the target
// through the shared connection. Returns the bound local address.
func masterOpenForward(ctx context.Context, c *Client, typ cm.MsgType, fwd *cm.OpenForward) (string, error) {
	if fwd.ListenAddr == "" || fwd.TargetAddr == "" {
		return "", errors.New("listen and target addresses are required")
	}
	switch typ {
	case cm.MsgOpenForwardTCP:
		local, err := net.ResolveTCPAddr("tcp", fwd.ListenAddr)
		if err != nil {
			return "", fmt.Errorf("bad listen address: %w", err)
		}
		remote, err := net.ResolveTCPAddr("tcp", fwd.TargetAddr)
		if err != nil {
			return "", fmt.Errorf("bad target address: %w", err)
		}
		bound, err := c.ForwardTCP(ctx, local, remote)
		if err != nil {
			return "", err
		}
		return bound.String(), nil
	case cm.MsgOpenForwardUDP:
		local, err := net.ResolveUDPAddr("udp", fwd.ListenAddr)
		if err != nil {
			return "", fmt.Errorf("bad listen address: %w", err)
		}
		remote, err := net.ResolveUDPAddr("udp", fwd.TargetAddr)
		if err != nil {
			return "", fmt.Errorf("bad target address: %w", err)
		}
		bound, err := c.ForwardUDP(ctx, local, remote)
		if err != nil {
			return "", err
		}
		return bound.String(), nil
	default:
		return "", fmt.Errorf("unsupported forward type %v", typ)
	}
}

// relaySlaveInteractions dispatches slave interaction frames (window
// changes, signals) from the session control connection to the ssh3 channel,
// mirroring what a direct client sends itself.
func relaySlaveInteractions(control net.Conn, channel ssh3.Channel) {
	for {
		typ, payload, err := cm.ReadFrame(control)
		if err != nil {
			return
		}
		switch typ {
		case cm.MsgWindowChange:
			var wc cm.WindowChange
			if err := wc.Decode(payload); err != nil {
				log.Debug().Msgf("master: malformed WINDOW_CHANGE: %v", err)
				continue
			}
			if err := channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
				WantReply: false,
				ChannelRequest: &ssh3Messages.WindowChangeRequest{
					CharWidth:   uint64(wc.Columns),
					CharHeight:  uint64(wc.Rows),
					PixelWidth:  uint64(wc.PixelWidth),
					PixelHeight: uint64(wc.PixelHeight),
				},
			}); err != nil {
				log.Debug().Msgf("master: could not forward window change: %v", err)
				return
			}
		case cm.MsgSignal:
			var sig cm.Signal
			if err := sig.Decode(payload); err != nil {
				log.Debug().Msgf("master: malformed SIGNAL: %v", err)
				continue
			}
			if err := channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
				WantReply: false,
				ChannelRequest: &ssh3Messages.SignalRequest{
					SignalNameWithoutSig: sig.Name,
				},
			}); err != nil {
				log.Debug().Msgf("master: could not forward signal %s: %v", sig.Name, err)
				return
			}
		default:
			// not an interaction frame (or from a newer protocol): ignore
		}
	}
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

	// slave interaction frames (window changes, signals) arrive on the
	// control connection while the bridge pumps the streams; an old slave
	// sends nothing here and an unknown frame type is ignored
	go relaySlaveInteractions(sess.control, sess.channel)

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
