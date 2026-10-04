//go:build !windows

package cmd

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

// fakeDynamicForwardStream is an in-process implementation of the
// dynamicForwardStream interface: msgs feeds the server (client -> server
// direction) and outs collects what the server writes back (server -> client
// direction). It lets the dynamic-forward data plane be tested without a QUIC
// session.
type fakeDynamicForwardStream struct {
	msgs          chan ssh3Messages.Message
	outs          chan []byte
	closed        chan struct{}
	maxPacketSize uint64
}

func newFakeDynamicForwardStream() *fakeDynamicForwardStream {
	return &fakeDynamicForwardStream{
		msgs:          make(chan ssh3Messages.Message, 16),
		outs:          make(chan []byte, 16),
		closed:        make(chan struct{}),
		maxPacketSize: 30000,
	}
}

func (f *fakeDynamicForwardStream) ChannelID() util.ChannelID { return 42 }

func (f *fakeDynamicForwardStream) NextMessage() (ssh3Messages.Message, error) {
	select {
	case message := <-f.msgs:
		return message, nil
	case <-f.closed:
		return nil, io.EOF
	}
}

func (f *fakeDynamicForwardStream) WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error) {
	if dataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
		return 0, net.ErrClosed
	}
	buf := append([]byte(nil), dataBuf...)
	select {
	case f.outs <- buf:
		return len(dataBuf), nil
	case <-f.closed:
		return 0, net.ErrClosed
	}
}

func (f *fakeDynamicForwardStream) Close() {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
}

func (f *fakeDynamicForwardStream) CancelRead() {}

func (f *fakeDynamicForwardStream) MaxPacketSize() uint64 { return f.maxPacketSize }

func (f *fakeDynamicForwardStream) isClosed() bool {
	select {
	case <-f.closed:
		return true
	default:
		return false
	}
}

// sendChannelData frames payload as a channel data message, the way the client
// does on a "dynamic-forward-tcp" channel.
func (f *fakeDynamicForwardStream) sendChannelData(t *testing.T, payload interface {
	Length() int
	Write([]byte) (int, error)
},
) {
	t.Helper()
	buf := make([]byte, payload.Length())
	if _, err := payload.Write(buf); err != nil {
		t.Fatalf("Write(%T): %v", payload, err)
	}
	f.msgs <- &ssh3Messages.DataOrExtendedDataMessage{
		DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE,
		Data:     string(buf),
	}
}

func (f *fakeDynamicForwardStream) nextOut(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	select {
	case buf := <-f.outs:
		return buf
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for data written on the channel", timeout)
		return nil
	}
}

// startEchoEndpoint starts a local TCP endpoint echoing back whatever it
// receives; it plays the role of the target of a dynamic forward.
func startEchoEndpoint(t *testing.T) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start the echo endpoint: %s", err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(conn)
		}
	}()
	host, portString, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("bad echo endpoint address %s: %s", listener.Addr(), err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatalf("bad echo endpoint port %q: %s", portString, err)
	}
	return host, port
}

func parseTargetReply(t *testing.T, buf []byte) *ssh3Messages.DynamicForwardTargetReply {
	t.Helper()
	reply, err := ssh3Messages.ParseDynamicForwardTargetReply(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
	if err != nil {
		t.Fatalf("could not parse the target reply %x: %s", buf, err)
	}
	return reply
}

// TestDynamicForwardDataChannelEcho drives a full dynamic-forward data channel
// against a local echo endpoint: the server must acknowledge the target, pump
// the payload in both directions and close the channel once the peer is done.
func TestDynamicForwardDataChannelEcho(t *testing.T) {
	host, port := startEchoEndpoint(t)

	stream := newFakeDynamicForwardStream()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveDynamicForwardDataChannel(ctx, &dynamicForwardState{}, stream)
	}()

	stream.sendChannelData(t, &ssh3Messages.DynamicForwardTarget{Address: host, Port: uint16(port)})
	if reply := parseTargetReply(t, stream.nextOut(t, 5*time.Second)); !reply.Success() {
		t.Fatalf("target refused: %s", reply.ErrorUTF8)
	}

	// raw channel data, i.e. what the client streams once the target was
	// acknowledged
	stream.msgs <- &ssh3Messages.DataOrExtendedDataMessage{
		DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE,
		Data:     "ping",
	}
	if got := stream.nextOut(t, 5*time.Second); string(got) != "ping" {
		t.Errorf("echoed data = %q, want %q", got, "ping")
	}

	// the peer stops sending: the server must finish and close the channel
	close(stream.msgs)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the dynamic-forward data channel did not terminate on peer EOF")
	}
	if !stream.isClosed() {
		t.Error("the dynamic-forward data channel was not closed at the end")
	}
}

// A failing dial must be reported as a readable error in the reply, without
// panicking and without leaving the channel open.
func TestDynamicForwardDataChannelDialFailure(t *testing.T) {
	// bind then immediately release a port so that nothing listens on it
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not reserve a port: %s", err)
	}
	address := listener.Addr().(*net.TCPAddr)
	listener.Close()

	stream := newFakeDynamicForwardStream()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveDynamicForwardDataChannel(ctx, &dynamicForwardState{}, stream)
	}()

	stream.sendChannelData(t, &ssh3Messages.DynamicForwardTarget{
		Address: address.IP.String(),
		Port:    uint16(address.Port),
	})
	reply := parseTargetReply(t, stream.nextOut(t, 10*time.Second))
	if reply.Success() {
		t.Fatal("dialing a closed port reported a success")
	}
	if reply.ErrorUTF8 == "" {
		t.Error("the failed dial reported an empty error")
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the data channel did not terminate after a failed dial")
	}
	if !stream.isClosed() {
		t.Error("the data channel was not closed after a failed dial")
	}
}

// A garbage or truncated target must not dial anything and must not leave the
// channel open.
func TestDynamicForwardDataChannelInvalidTarget(t *testing.T) {
	for name, buf := range map[string][]byte{
		"empty":            {},
		"truncated":        {0x01},
		"bad version":      {0x02, 0x03, 0x01, 'a', 0x00, 0x50},
		"bad kind":         {0x01, 0x09, 0x01, 'a', 0x00, 0x50},
		"truncated target": {0x01, 0x03, 0x01, 'a'},
		"zero port target": {0x01, 0x03, 0x01, 'a', 0x00, 0x00},
		"empty address":    {0x01, 0x03, 0x00, 0x00, 0x50},
	} {
		stream := newFakeDynamicForwardStream()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			serveDynamicForwardDataChannel(ctx, &dynamicForwardState{}, stream)
		}()
		stream.msgs <- &ssh3Messages.DataOrExtendedDataMessage{
			DataType: ssh3Messages.SSH_EXTENDED_DATA_NONE,
			Data:     string(buf),
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatalf("%s: the data channel did not terminate", name)
		}
		if !stream.isClosed() {
			t.Errorf("%s: the data channel was not closed", name)
		}
		cancel()
	}
}

// A data channel that arrives without an active control channel must be
// refused with a readable reason instead of being served.
func TestDynamicForwardDataChannelWithoutControlChannel(t *testing.T) {
	stream := newFakeDynamicForwardStream()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveDynamicForwardDataChannel(ctx, nil, stream)
	}()

	stream.sendChannelData(t, &ssh3Messages.DynamicForwardTarget{Address: "192.0.2.10", Port: 80})
	reply := parseTargetReply(t, stream.nextOut(t, 5*time.Second))
	if reply.Success() {
		t.Fatal("a data channel without control channel reported a success")
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the data channel did not terminate")
	}
	if !stream.isClosed() {
		t.Error("the data channel was not closed")
	}
}

// Closing the control channel must release every bridged connection.
func TestDynamicForwardStateRelease(t *testing.T) {
	host, port := startEchoEndpoint(t)
	state := &dynamicForwardState{}
	addr := &net.TCPAddr{IP: net.ParseIP(host), Port: port}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		t.Fatalf("could not dial the echo endpoint: %s", err)
	}
	release, err := state.trackConn(conn)
	if err != nil {
		t.Fatalf("trackConn: %s", err)
	}
	if n := state.openConns(); n != 1 {
		t.Fatalf("openConns() = %d, want 1", n)
	}
	state.releaseConns()
	release()
	if n := state.openConns(); n != 0 {
		t.Errorf("openConns() after release = %d, want 0", n)
	}
	// the tracked connection must have been closed by the release
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("the released connection is still readable")
	}
}
