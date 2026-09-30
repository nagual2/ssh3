package client

// Tests for pumpSessionStreams: the transport-agnostic core of a session
// (stdin pump + message drain), exercised against an in-memory fake channel.

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ssh3Messages "github.com/francoismichel/ssh3/message"
)

func TestMain(m *testing.M) {
	// keep the grace waits short so tests stay fast and deterministic
	oldTruncation := truncationGrace
	oldPty := ptyExitGrace
	truncationGrace = 100 * time.Millisecond
	ptyExitGrace = 100 * time.Millisecond
	defer func() { truncationGrace = oldTruncation; ptyExitGrace = oldPty }()
	m.Run()
}

// fakeChannel implements sessionChannel in-memory: it records what the stdin
// pump wrote and replays scripted messages to the drain loop.
type fakeChannel struct {
	msgs       chan ssh3Messages.Message
	written    [][]byte
	writeErr   error
	closed     atomic.Bool
	closeOnFin bool
	finOnce    sync.Once
	abort      chan struct{}
	abortOnce  sync.Once
	maxPacket  uint64
}

func newFakeChannel() *fakeChannel {
	return &fakeChannel{msgs: make(chan ssh3Messages.Message, 16), abort: make(chan struct{}), maxPacket: 32768}
}

func (f *fakeChannel) MaxPacketSize() uint64 { return f.maxPacket }

func (f *fakeChannel) WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.written = append(f.written, append([]byte(nil), dataBuf...))
	return len(dataBuf), nil
}

func (f *fakeChannel) NextMessage() (ssh3Messages.Message, error) {
	select {
	case m, ok := <-f.msgs:
		if !ok {
			// a closed channel ends the post-exit-status drain (nil message)
			return nil, nil
		}
		return m, nil
	case <-f.abort:
		// read canceled after the grace window; the drain treats any error
		// as the end of the channel
		return nil, io.ErrClosedPipe
	}
}

func (f *fakeChannel) Close() {
	f.closed.Store(true)
	if f.closeOnFin {
		// cooperative-server mode: the channel ends once the client FINs
		f.finOnce.Do(func() { close(f.msgs) })
	}
}

func (f *fakeChannel) CancelRead() {
	f.abortOnce.Do(func() { close(f.abort) })
}

func dataMsg(s string) *ssh3Messages.DataOrExtendedDataMessage {
	return &ssh3Messages.DataOrExtendedDataMessage{DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE, Data: s}
}

func stderrMsg(s string) *ssh3Messages.DataOrExtendedDataMessage {
	return &ssh3Messages.DataOrExtendedDataMessage{DataType: ssh3Messages.SSH_EXTENDED_DATA_STDERR, Data: s}
}

func exitStatusMsg(code uint64) *ssh3Messages.ChannelRequestMessage {
	return &ssh3Messages.ChannelRequestMessage{ChannelRequest: &ssh3Messages.ExitStatusRequest{ExitStatus: code}}
}

// exec flow: stdout/stderr data reaches the right writers, stdin is piped into
// the channel and its EOF half-closes the send side, exit status is returned.
func TestPumpExecStreamsDataAndExit(t *testing.T) {
	fc := newFakeChannel()
	fc.msgs <- dataMsg("hello ")
	fc.msgs <- stderrMsg("warn")
	fc.msgs <- exitStatusMsg(7)
	// output still in flight after the exit status must not be dropped
	fc.msgs <- dataMsg("tail")
	close(fc.msgs)

	var out, errBuf bytes.Buffer
	err := pumpSessionStreams(fc, sessionIO{
		stdin:  strings.NewReader("ping"),
		stdout: &out,
		stderr: &errBuf,
	}, false)

	var es ExitStatus
	if !errors.As(err, &es) {
		t.Fatalf("expected ExitStatus, got %v", err)
	}
	if es.StatusCode != 7 {
		t.Fatalf("expected exit status 7, got %d", es.StatusCode)
	}
	if out.String() != "hello tail" {
		t.Fatalf("stdout = %q, want %q", out.String(), "hello tail")
	}
	if errBuf.String() != "warn" {
		t.Fatalf("stderr = %q, want %q", errBuf.String(), "warn")
	}
	if len(fc.written) != 1 || string(fc.written[0]) != "ping" {
		t.Fatalf("channel input = %v, want [ping]", fc.written)
	}
	if !fc.closed.Load() {
		t.Fatal("stdin EOF must half-close the channel")
	}
}

// current semantics: a stdin write error leaves inputSent unset, so the exit
// status is classified as a truncated transfer (exit 255); the channel must
// not be half-closed by a failed write
func TestPumpStdinWriteErrorKeepsChannelOpen(t *testing.T) {
	fc := newFakeChannel()
	fc.writeErr = errors.New("flow control")
	fc.msgs <- exitStatusMsg(0)
	close(fc.msgs)

	var out, errBuf bytes.Buffer
	err := pumpSessionStreams(fc, sessionIO{
		stdin:  strings.NewReader("data"),
		stdout: &out,
		stderr: &errBuf,
	}, false)

	var es ExitStatus
	if !errors.As(err, &es) || es.StatusCode != 255 {
		t.Fatalf("expected truncation exit status 255, got %v", err)
	}
	if fc.closed.Load() {
		t.Fatal("a failed stdin write must not half-close the channel")
	}
	if len(fc.written) != 0 {
		t.Fatalf("failed writes must not be recorded, got %v", fc.written)
	}
}

// exit status with stdin still pending = truncated transfer, exit code 255
func TestPumpTruncatedTransferDetected(t *testing.T) {
	fc := newFakeChannel()
	fc.msgs <- exitStatusMsg(0)
	close(fc.msgs)

	pr, pw := io.Pipe() // never closed: the pump stays blocked on Read
	defer pw.Close()

	var out bytes.Buffer
	err := pumpSessionStreams(fc, sessionIO{stdin: pr, stdout: &out, stderr: &out}, false)

	var es ExitStatus
	if !errors.As(err, &es) {
		t.Fatalf("expected ExitStatus, got %v", err)
	}
	if es.StatusCode != 255 {
		t.Fatalf("expected truncation exit status 255, got %d", es.StatusCode)
	}
}

// Non-PTY truncated transfer with a never-EOF stdin: the client must FIN its
// send half when the truncation verdict fires. A server only ends the channel
// after the client's send side closes, so without the FIN the drain waits
// forever and the process hangs (docs/BUG-STDIN-DRAIN-DEADLOCK.md).
func TestPumpTruncatedTransferHalfClosesChannel(t *testing.T) {
	fc := newFakeChannel()
	fc.closeOnFin = true // cooperative server: ends the channel upon client FIN
	fc.msgs <- exitStatusMsg(0)
	// msgs is never closed: without the client FIN this server never ends the channel

	pr, pw := io.Pipe() // harness-style stdin: never EOFs
	defer pw.Close()

	var out, errBuf bytes.Buffer
	resCh := make(chan error, 1)
	go func() {
		resCh <- pumpSessionStreams(fc, sessionIO{stdin: pr, stdout: &out, stderr: &errBuf}, false)
	}()
	select {
	case err := <-resCh:
		var es ExitStatus
		if !errors.As(err, &es) || es.StatusCode != 255 {
			t.Fatalf("expected truncation exit status 255, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client hung in the post-exit drain: no FIN was sent for a never-EOF stdin")
	}
	if !fc.closed.Load() {
		t.Fatal("truncation verdict must half-close the channel (FIN)")
	}
}

// PTY session (stage 1, bug 5): the remote shell exited and the exit status
// arrived, but a raw console stdin never EOFs, so the server can keep the
// channel open and never send the trailing EOF. The drain must give up after
// the grace window instead of hanging forever.
func TestPumpPtyExitDrainIsBounded(t *testing.T) {
	fc := newFakeChannel()
	fc.msgs <- exitStatusMsg(7)
	fc.msgs <- dataMsg("bye")
	// msgs is never closed: this server never ends the channel

	pr, pw := io.Pipe() // raw console stdin: never EOFs
	defer pw.Close()

	var out, errBuf bytes.Buffer
	start := time.Now()
	err := pumpSessionStreams(fc, sessionIO{stdin: pr, stdout: &out, stderr: &errBuf}, true)
	elapsed := time.Since(start)

	var es ExitStatus
	if !errors.As(err, &es) {
		t.Fatalf("expected ExitStatus, got %v", err)
	}
	if es.StatusCode != 7 {
		t.Fatalf("expected exit status 7, got %d", es.StatusCode)
	}
	if elapsed < 95*time.Millisecond {
		t.Fatalf("drain returned after %v, before the %v grace window elapsed", elapsed, ptyExitGrace)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("drain returned after %v, grace window is %v", elapsed, ptyExitGrace)
	}
	if !strings.Contains(out.String(), "bye") {
		t.Fatalf("stdout = %q, want the post-exit output %q drained", out.String(), "bye")
	}
	if strings.Contains(errBuf.String(), "truncated") {
		t.Fatal("PTY sessions must not be classified as truncated transfers")
	}
}

// A PTY client must FIN its send half when the exit status arrives: the
// server only ends the channel after the client's send side closes, which a
// raw console stdin never does on its own (stage 1, bug 5).
func TestPumpPtyExitHalfClosesChannel(t *testing.T) {
	fc := newFakeChannel()
	fc.closeOnFin = true // cooperative server: ends the channel upon client FIN
	fc.msgs <- exitStatusMsg(7)
	fc.msgs <- dataMsg("tail")

	pr, pw := io.Pipe()
	defer pw.Close()

	var out, errBuf bytes.Buffer
	start := time.Now()
	err := pumpSessionStreams(fc, sessionIO{stdin: pr, stdout: &out, stderr: &errBuf}, true)
	elapsed := time.Since(start)

	var es ExitStatus
	if !errors.As(err, &es) || es.StatusCode != 7 {
		t.Fatalf("expected exit status 7, got %v", err)
	}
	if !fc.closed.Load() {
		t.Fatal("PTY exit status must half-close the channel (FIN)")
	}
	if elapsed >= 95*time.Millisecond {
		t.Fatalf("a cooperative server must end the drain right after the FIN, took %v", elapsed)
	}
	if !strings.Contains(out.String(), "tail") {
		t.Fatalf("stdout = %q, want %q", out.String(), "tail")
	}
}
