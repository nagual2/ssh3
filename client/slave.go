package client

// ControlMaster slave side (stage 3.5): RunSlaveSession runs one session
// through a listening master. The control connection carries the session
// request and the final exit status; two dedicated connections carry the
// session streams (stderr attaches first, then the full-duplex io stream).

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/francoismichel/ssh3/client/cm"
)

// RunSlaveSession requests a session from the ControlMaster listening on
// controlPath and bridges the given local streams into it. tty (may be nil)
// enables interaction relay for pty sessions: terminal resizes and
// out-of-band signals are forwarded to the master as control frames. It
// returns the remote exit status (255 for signals or transport failures).
func RunSlaveSession(ctx context.Context, controlPath string, spec SessionSpec,
	stdin io.Reader, stdout, stderr io.Writer, tty *os.File) (int, error) {

	payload, err := encodeOpenSessionRequest(spec)
	if err != nil {
		return -1, err
	}

	control, err := dialCM(ctx, controlPath)
	if err != nil {
		return -1, fmt.Errorf("could not reach the control master: %w", err)
	}
	defer control.Close()
	if err := cm.Hello(control); err != nil {
		return -1, err
	}
	tokenBytes, err := cm.Call(control, cm.MsgOpenSession, payload)
	if err != nil {
		return -1, err
	}
	if len(tokenBytes) != len(cm.Token{}) {
		return -1, fmt.Errorf("cm: malformed session token reply (%d bytes)", len(tokenBytes))
	}
	var token cm.Token
	copy(token[:], tokenBytes)

	// the master starts the pump on the io attachment and needs the stderr
	// sink by then, so stderr must attach first
	errConn, err := attachCM(ctx, controlPath, token, cm.StreamStderr)
	if err != nil {
		return -1, err
	}
	defer errConn.Close()
	ioConn, err := attachCM(ctx, controlPath, token, cm.StreamIO)
	if err != nil {
		return -1, err
	}
	defer ioConn.Close()

	if spec.Pty != nil && tty != nil {
		if stopRelay := relaySlaveTTYEvents(control, tty); stopRelay != nil {
			defer stopRelay()
		}
	}

	// slave stdin upstream; a closed write half tells the master's pump the
	// input is complete without tearing down the stdout direction
	go func() {
		io.Copy(ioConn, stdin)
		if unix, ok := ioConn.(*net.UnixConn); ok {
			unix.CloseWrite()
		}
	}()

	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		io.Copy(stdout, ioConn)
	}()
	go io.Copy(stderr, errConn)

	type result struct {
		code int
		err  error
	}
	res := make(chan result, 1)
	go func() {
		for {
			typ, payload, err := cm.ReadFrame(control)
			if err != nil {
				res <- result{-1, fmt.Errorf("control channel ended: %w", err)}
				return
			}
			if typ == cm.MsgExitStatus {
				code, err := cm.DecodeExitStatus(payload)
				if err != nil {
					res <- result{-1, err}
					return
				}
				res <- result{int(code), nil}
				return
			}
		}
	}()

	select {
	case r := <-res:
		<-pumpDone // the exit status implies the output tail is already sent
		return r.code, r.err
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

// PingMaster reports whether a control master is serving on controlPath.
func PingMaster(ctx context.Context, controlPath string) bool {
	conn, err := dialCM(ctx, controlPath)
	if err != nil {
		return false
	}
	defer conn.Close()
	return cm.Hello(conn) == nil
}

// ExitMaster asks the ControlMaster listening on controlPath to shut down
// cleanly (the -O exit control op). The master stops accepting new slaves
// and removes its socket; already-running sessions finish on their channel.
func ExitMaster(ctx context.Context, controlPath string) error {
	conn, err := dialCM(ctx, controlPath)
	if err != nil {
		return fmt.Errorf("could not reach the control master: %w", err)
	}
	defer conn.Close()
	if err := cm.Hello(conn); err != nil {
		return err
	}
	_, err = cm.Call(conn, cm.MsgExit, nil)
	return err
}

// OpenMasterForwardTCP asks the master to listen on listenAddr and forward
// accepted connections to targetAddr through the shared connection. Returns
// the bound local address (useful when listenAddr has a zero port).
func OpenMasterForwardTCP(ctx context.Context, controlPath, listenAddr, targetAddr string) (string, error) {
	return callMasterForward(ctx, controlPath, cm.MsgOpenForwardTCP, listenAddr, targetAddr)
}

// OpenMasterForwardUDP is the UDP counterpart of OpenMasterForwardTCP.
func OpenMasterForwardUDP(ctx context.Context, controlPath, listenAddr, targetAddr string) (string, error) {
	return callMasterForward(ctx, controlPath, cm.MsgOpenForwardUDP, listenAddr, targetAddr)
}

func callMasterForward(ctx context.Context, controlPath string, typ cm.MsgType, listenAddr, targetAddr string) (string, error) {
	conn, err := dialCM(ctx, controlPath)
	if err != nil {
		return "", fmt.Errorf("could not reach the control master: %w", err)
	}
	defer conn.Close()
	if err := cm.Hello(conn); err != nil {
		return "", err
	}
	resp, err := cm.Call(conn, typ, (&cm.OpenForward{ListenAddr: listenAddr, TargetAddr: targetAddr}).Encode())
	if err != nil {
		return "", err
	}
	return string(resp), nil
}

func encodeOpenSessionRequest(spec SessionSpec) ([]byte, error) {
	req := cm.OpenSession{Command: spec.Command, ForwardAgent: spec.ForwardAgent}
	if spec.Pty != nil {
		req.Pty = &cm.PtySpec{
			Term:        spec.Pty.Term,
			Columns:     uint32(spec.Pty.Columns),
			Rows:        uint32(spec.Pty.Rows),
			PixelWidth:  uint32(spec.Pty.PixelWidth),
			PixelHeight: uint32(spec.Pty.PixelHeight),
		}
	}
	return req.Encode()
}

func dialCM(ctx context.Context, controlPath string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", controlPath)
}

func attachCM(ctx context.Context, controlPath string, token cm.Token, stream cm.StreamKind) (net.Conn, error) {
	conn, err := dialCM(ctx, controlPath)
	if err != nil {
		return nil, err
	}
	if err := cm.Hello(conn); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := cm.Call(conn, cm.MsgAttach, cm.AttachPayload(token, stream)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
