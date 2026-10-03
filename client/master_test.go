package client

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
