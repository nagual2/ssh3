package message

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/francoismichel/ssh3/util"
)

// Round-trip and golden-byte tests for the reverse forwarding (-R) payloads.
// The payloads travel as channel data on a "reverse-forward" control channel,
// so their encoding is fully covered by these unit tests without a session.

func TestRequestReverseForwardRoundTrip(t *testing.T) {
	for _, request := range []*RequestReverseForward{
		{
			Protocol:      util.SSHForwardingProtocolTCP,
			BindAddress:   "127.0.0.1",
			BindPort:      8080,
			TargetAddress: "192.0.2.10",
			TargetPort:    80,
		},
		{
			Protocol:      util.SSHProtocolUDP,
			BindAddress:   "",
			BindPort:      53,
			TargetAddress: "2001:db8::1",
			TargetPort:    53,
		},
		{
			Protocol:      util.SSHForwardingProtocolTCP,
			BindAddress:   "*",
			BindPort:      0,
			TargetAddress: "127.0.0.1",
			TargetPort:    65535,
		},
	} {
		buf := make([]byte, request.Length())
		n, err := request.Write(buf)
		if err != nil {
			t.Fatalf("Write(%+v): %v", request, err)
		}
		if n != len(buf) {
			t.Fatalf("Write(%+v) consumed %d bytes, want %d", request, n, len(buf))
		}
		parsed, err := ParseRequestReverseForward(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
		if err != nil {
			t.Fatalf("ParseRequestReverseForward(%+v): %v", request, err)
		}
		if *parsed != *request {
			t.Errorf("round-trip mismatch: sent %+v, parsed %+v", request, parsed)
		}
	}
}

func TestRequestReverseForwardGoldenBytes(t *testing.T) {
	// varint(1) | sshstring("127.0.0.1") | be16(8080) | sshstring("192.0.2.10") | be16(80)
	want, err := hex.DecodeString(
		"01" +
			"09" + hex.EncodeToString([]byte("127.0.0.1")) +
			"1f90" +
			"0a" + hex.EncodeToString([]byte("192.0.2.10")) +
			"0050")
	if err != nil {
		t.Fatalf("bad golden vector: %v", err)
	}
	request := &RequestReverseForward{
		Protocol:      util.SSHForwardingProtocolTCP,
		BindAddress:   "127.0.0.1",
		BindPort:      8080,
		TargetAddress: "192.0.2.10",
		TargetPort:    80,
	}
	buf := make([]byte, request.Length())
	if _, err := request.Write(buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(buf, want) {
		t.Errorf("encoded request = %s, want %s", hex.EncodeToString(buf), hex.EncodeToString(want))
	}
}

func TestRequestReverseForwardInvalidProtocol(t *testing.T) {
	buf := util.AppendVarInt(nil, 17)
	buf = util.AppendVarInt(buf, 0) // empty bind address
	parsed, err := ParseRequestReverseForward(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
	if err == nil {
		t.Errorf("protocol 17 accepted, parsed %+v", parsed)
	}
}

func TestRequestReverseForwardTruncated(t *testing.T) {
	request := &RequestReverseForward{
		Protocol:      util.SSHForwardingProtocolTCP,
		BindAddress:   "127.0.0.1",
		BindPort:      8080,
		TargetAddress: "192.0.2.10",
		TargetPort:    80,
	}
	buf := make([]byte, request.Length())
	if _, err := request.Write(buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for cut := 0; cut < len(buf); cut++ {
		if _, err := ParseRequestReverseForward(&util.BytesReadCloser{Reader: bytes.NewReader(buf[:cut])}); err == nil {
			t.Errorf("truncated input of %d bytes accepted", cut)
		}
	}
}

func TestReverseForwardReplyRoundTrip(t *testing.T) {
	for _, reply := range []*ReverseForwardReply{
		{BoundPort: 8080, ErrorUTF8: ""},
		{BoundPort: 0, ErrorUTF8: "bind: address already in use"},
		{BoundPort: 443, ErrorUTF8: "permission denied"},
	} {
		buf := make([]byte, reply.Length())
		n, err := reply.Write(buf)
		if err != nil {
			t.Fatalf("Write(%+v): %v", reply, err)
		}
		if n != len(buf) {
			t.Fatalf("Write(%+v) consumed %d bytes, want %d", reply, n, len(buf))
		}
		parsed, err := ParseReverseForwardReply(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
		if err != nil {
			t.Fatalf("ParseReverseForwardReply(%+v): %v", reply, err)
		}
		if *parsed != *reply {
			t.Errorf("round-trip mismatch: sent %+v, parsed %+v", reply, parsed)
		}
	}
}

func TestReverseForwardReplySuccess(t *testing.T) {
	if !(&ReverseForwardReply{BoundPort: 1}).Success() {
		t.Error("empty error must be a success")
	}
	if (&ReverseForwardReply{BoundPort: 1, ErrorUTF8: "port busy"}).Success() {
		t.Error("non-empty error must not be a success")
	}
}

func TestReverseForwardReplyTruncated(t *testing.T) {
	reply := &ReverseForwardReply{BoundPort: 8080, ErrorUTF8: "boom"}
	buf := make([]byte, reply.Length())
	if _, err := reply.Write(buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for cut := 0; cut < len(buf); cut++ {
		if _, err := ParseReverseForwardReply(&util.BytesReadCloser{Reader: bytes.NewReader(buf[:cut])}); err == nil {
			t.Errorf("truncated input of %d bytes accepted", cut)
		}
	}
}
