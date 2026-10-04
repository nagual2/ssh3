package client

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/francoismichel/ssh3/client/cm"
)

// A master killed with SIGKILL leaves its socket file behind; the next
// master must recover by unlinking the stale path (no listener answers the
// dial) instead of failing to bind forever (stage 3.5 follow-up).
func TestListenControlMasterRecoversStaleSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path semantics")
	}
	path := filepath.Join(t.TempDir(), "cm.sock")
	// dead artifact on the path: something bind refuses, nothing dials
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("could not create the stale artifact: %v", err)
	}
	f.Close()
	if _, err := net.Listen("unix", path); err == nil {
		t.Fatal("expected the raw bind to refuse the occupied path")
	}
	ln, err := ListenControlMaster(path)
	if err != nil {
		t.Fatalf("ListenControlMaster did not recover the stale socket: %v", err)
	}
	defer ln.Close()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the recovered listener does not answer: %v", err)
	}
	conn.Close()
}

// A live master owns its socket path even if it is momentarily too busy to
// complete a handshake: as long as a dial connects, ListenControlMaster must
// refuse the path instead of unlinking a serving socket.
func TestListenControlMasterRefusesLivePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path semantics")
	}
	path := filepath.Join(t.TempDir(), "cm.sock")
	live, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("could not bind the live listener: %v", err)
	}
	defer live.Close()
	if _, err := ListenControlMaster(path); err == nil {
		t.Fatal("must not steal a live control socket path")
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the live listener stopped answering: %v", err)
	}
	conn.Close()
}

// startControlMaster serves a master that only answers control ops. No
// session is ever opened, so no ssh3 connection is needed (nil *Client).
func startControlMaster(t *testing.T, path string) chan error {
	t.Helper()
	ln, err := ListenControlMaster(path)
	if err != nil {
		t.Fatalf("ListenControlMaster: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- ServeControlMaster(ctx, nil, ln, nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if PingMaster(ctx, path) {
			return done
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the control master never started serving on %s", path)
	return nil
}

// opContext bounds every control op so a regression shows up as a test
// failure instead of a hung test binary.
func opContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// A live master answers a check with its status snapshot; the CLI needs this
// without opening a session.
func TestControlOpCheckLiveMaster(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path semantics")
	}
	path := filepath.Join(t.TempDir(), "cm.sock")
	startControlMaster(t, path)

	status, err := CheckMaster(opContext(t), path)
	if err != nil {
		t.Fatalf("check against a live master: %v", err)
	}
	if status.PID != os.Getpid() {
		t.Fatalf("PID = %d, want %d (the test process serves the master)", status.PID, os.Getpid())
	}
	if status.Path != path {
		t.Fatalf("Path = %q, want %q", status.Path, path)
	}
	if status.Protocol != cm.Version {
		t.Fatalf("Protocol = %d, want the protocol version %d", status.Protocol, cm.Version)
	}
	if status.Sessions != 0 {
		t.Fatalf("Sessions = %d, want 0", status.Sessions)
	}
	if status.Uptime < 0 {
		t.Fatalf("Uptime = %v, want a non-negative uptime", status.Uptime)
	}
	if !strings.Contains(status.String(), "pid=") {
		t.Fatalf("String() = %q, want a printable status line", status.String())
	}
}

// Without a master the check must fail with a clear message and no wait.
func TestControlOpCheckWithoutMaster(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path semantics")
	}
	path := filepath.Join(t.TempDir(), "cm.sock")
	if _, err := CheckMaster(opContext(t), path); err == nil {
		t.Fatal("check without a master must fail")
	} else if !strings.Contains(err.Error(), "no control master is listening on") {
		t.Fatalf("unclear error for a missing master: %v", err)
	}
}

// The stop op shuts the master down and leaves no socket file behind, so a
// fresh master can bind the same path right away.
func TestControlOpStopClosesMasterAndUnlinksSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path semantics")
	}
	path := filepath.Join(t.TempDir(), "cm.sock")
	ctx := opContext(t)
	done := startControlMaster(t, path)

	if err := StopMaster(ctx, path); err != nil {
		t.Fatalf("stop op: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the master did not stop after the stop op")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket file still present after the stop op (stat err = %v)", err)
	}
	if PingMaster(ctx, path) {
		t.Fatal("the master still answers after the stop op")
	}
	// no stale socket left behind: the released path binds again
	ln, err := ListenControlMaster(path)
	if err != nil {
		t.Fatalf("re-binding the released control path: %v", err)
	}
	ln.Close()
}

// The exit op keeps working through the shared entry point: it must still use
// the MsgExit frame a v0.1.22/v0.1.23 master understands.
func TestControlOpExitClosesMasterAndUnlinksSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path semantics")
	}
	path := filepath.Join(t.TempDir(), "cm.sock")
	ctx := opContext(t)
	done := startControlMaster(t, path)

	if _, err := RunControlOp(ctx, path, ControlOpExit); err != nil {
		t.Fatalf("exit op: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the master did not stop after the exit op")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket file still present after the exit op (stat err = %v)", err)
	}
}

// An operation the master does not know is refused with a clear message and
// the control connection stays usable for a correct retry.
func TestControlOpUnknownCommandKeepsConnectionUsable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path semantics")
	}
	path := filepath.Join(t.TempDir(), "cm.sock")
	ctx := opContext(t)
	startControlMaster(t, path)

	if _, err := SendControlCommand(ctx, path, "bogus"); err == nil {
		t.Fatal("an unknown control operation must be refused")
	} else if !strings.Contains(err.Error(), `unknown control operation "bogus"`) {
		t.Fatalf("unclear refusal for an unknown op: %v", err)
	}
	if _, err := CheckMaster(ctx, path); err != nil {
		t.Fatalf("the master is unusable after a refused op: %v", err)
	}
}

// Wire compatibility: a master predating the control-op extension refuses the
// unknown frame with the generic v0.1.23 handler error. The client must turn
// that into an explicit "unsupported" error instead of hanging.
func TestControlOpsAgainstLegacyMaster(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix socket path semantics")
	}
	path := filepath.Join(t.TempDir(), "cm.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("bind the legacy stand-in master: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go serveLegacyMaster(ln)

	ctx := opContext(t)
	done := make(chan error, 1)
	go func() {
		_, err := CheckMaster(ctx, path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a master predating the control ops must refuse the check")
		}
		if !strings.Contains(err.Error(), "does not support") {
			t.Fatalf("unclear refusal from a legacy master: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("check hung against a master that refuses the operation")
	}
}

// serveLegacyMaster mimics the v0.1.23 control handler: it completes the
// handshake and answers every later frame with the generic "unexpected
// message" error of its default branch, then drops the connection.
func serveLegacyMaster(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			typ, _, err := cm.ReadFrame(conn)
			if err != nil || typ != cm.MsgHello {
				return
			}
			if err := cm.WriteFrame(conn, cm.MsgOK, nil); err != nil {
				return
			}
			typ, _, err = cm.ReadFrame(conn)
			if err != nil {
				return
			}
			cm.WriteFrame(conn, cm.MsgError, []byte(fmt.Sprintf("unexpected message %v", typ)))
		}(conn)
	}
}
