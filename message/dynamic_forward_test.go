package message

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/francoismichel/ssh3/util"
)

// Round-trip and golden-byte tests for the dynamic SOCKS forwarding (-D)
// payloads. Like the reverse forwarding (-R) ones, they travel as channel data
// (on a "dynamic-forward" control channel and on each "dynamic-forward-tcp"
// channel) behind a varint version + varint kind prefix, so their encoding is
// fully covered by these unit tests without a session.

func encodeDynamicForward(t *testing.T, payload interface {
	Length() int
	Write([]byte) (int, error)
},
) []byte {
	t.Helper()
	buf := make([]byte, payload.Length())
	n, err := payload.Write(buf)
	if err != nil {
		t.Fatalf("Write(%T): %v", payload, err)
	}
	if n != len(buf) {
		t.Fatalf("Write(%T) consumed %d bytes, want %d", payload, n, len(buf))
	}
	return buf
}

func parseDynamicForward(t *testing.T, buf []byte, parse func(util.Reader) error) error {
	t.Helper()
	return parse(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
}

func TestRequestDynamicForwardRoundTrip(t *testing.T) {
	for _, request := range []*RequestDynamicForward{
		{BindAddress: "127.0.0.1", BindPort: 1080},
		{BindAddress: "", BindPort: 1080},
		{BindAddress: "*", BindPort: 0},
		{BindAddress: "::1", BindPort: 65535},
	} {
		buf := encodeDynamicForward(t, request)
		parsed, err := ParseRequestDynamicForward(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
		if err != nil {
			t.Fatalf("ParseRequestDynamicForward(%+v): %v", request, err)
		}
		if *parsed != *request {
			t.Errorf("round-trip mismatch: sent %+v, parsed %+v", request, parsed)
		}
	}
}

// The control-channel request must keep the exact v0.1.23-compatible layout:
//
//	varint(version) | varint(kind) | sshstring(bind_address) | be16(bind_port)
func TestRequestDynamicForwardGoldenBytes(t *testing.T) {
	want, err := hex.DecodeString(
		"01" + // version
			"01" + // kind = request
			"09" + hex.EncodeToString([]byte("127.0.0.1")) +
			"0438") // 1080
	if err != nil {
		t.Fatalf("bad golden vector: %v", err)
	}
	buf := encodeDynamicForward(t, &RequestDynamicForward{BindAddress: "127.0.0.1", BindPort: 1080})
	if !bytes.Equal(buf, want) {
		t.Errorf("encoded request = %s, want %s", hex.EncodeToString(buf), hex.EncodeToString(want))
	}
}

func TestDynamicForwardReplyRoundTrip(t *testing.T) {
	for _, reply := range []*DynamicForwardReply{
		{BoundPort: 1080, ErrorUTF8: ""},
		{BoundPort: 0, ErrorUTF8: "dynamic forwarding not requested"},
		{BoundPort: 65535, ErrorUTF8: "bind: permission denied"},
	} {
		buf := encodeDynamicForward(t, reply)
		parsed, err := ParseDynamicForwardReply(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
		if err != nil {
			t.Fatalf("ParseDynamicForwardReply(%+v): %v", reply, err)
		}
		if *parsed != *reply {
			t.Errorf("round-trip mismatch: sent %+v, parsed %+v", reply, parsed)
		}
	}
}

func TestDynamicForwardReplyGoldenBytes(t *testing.T) {
	want, err := hex.DecodeString(
		"01" + // version
			"02" + // kind = request reply
			"0438" + // bound port 1080
			"00") // empty error
	if err != nil {
		t.Fatalf("bad golden vector: %v", err)
	}
	buf := encodeDynamicForward(t, &DynamicForwardReply{BoundPort: 1080})
	if !bytes.Equal(buf, want) {
		t.Errorf("encoded reply = %s, want %s", hex.EncodeToString(buf), hex.EncodeToString(want))
	}
}

func TestDynamicForwardReplySuccess(t *testing.T) {
	if !(&DynamicForwardReply{BoundPort: 1}).Success() {
		t.Error("empty error must be a success")
	}
	if (&DynamicForwardReply{BoundPort: 1, ErrorUTF8: "nope"}).Success() {
		t.Error("non-empty error must not be a success")
	}
}

func TestDynamicForwardTargetRoundTrip(t *testing.T) {
	for _, target := range []*DynamicForwardTarget{
		{Address: "192.0.2.10", Port: 80},
		{Address: "example.com", Port: 443},
		{Address: "2001:db8::1", Port: 65535},
	} {
		buf := encodeDynamicForward(t, target)
		parsed, err := ParseDynamicForwardTarget(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
		if err != nil {
			t.Fatalf("ParseDynamicForwardTarget(%+v): %v", target, err)
		}
		if *parsed != *target {
			t.Errorf("round-trip mismatch: sent %+v, parsed %+v", target, parsed)
		}
	}
}

// The per-connection target must keep the exact layout:
//
//	varint(version) | varint(kind) | sshstring(address) | be16(port)
func TestDynamicForwardTargetGoldenBytes(t *testing.T) {
	want, err := hex.DecodeString(
		"01" + // version
			"03" + // kind = target
			"0b" + hex.EncodeToString([]byte("example.com")) +
			"01bb") // 443
	if err != nil {
		t.Fatalf("bad golden vector: %v", err)
	}
	buf := encodeDynamicForward(t, &DynamicForwardTarget{Address: "example.com", Port: 443})
	if !bytes.Equal(buf, want) {
		t.Errorf("encoded target = %s, want %s", hex.EncodeToString(buf), hex.EncodeToString(want))
	}
}

func TestDynamicForwardTargetReplyRoundTrip(t *testing.T) {
	for _, reply := range []*DynamicForwardTargetReply{
		{ErrorUTF8: ""},
		{ErrorUTF8: "dial tcp 192.0.2.10:80: connect: connection refused"},
	} {
		buf := encodeDynamicForward(t, reply)
		parsed, err := ParseDynamicForwardTargetReply(&util.BytesReadCloser{Reader: bytes.NewReader(buf)})
		if err != nil {
			t.Fatalf("ParseDynamicForwardTargetReply(%+v): %v", reply, err)
		}
		if *parsed != *reply {
			t.Errorf("round-trip mismatch: sent %+v, parsed %+v", reply, parsed)
		}
	}
}

func TestDynamicForwardTargetReplyGoldenBytes(t *testing.T) {
	want, err := hex.DecodeString(
		"01" + // version
			"04" + // kind = target reply
			"00") // empty error
	if err != nil {
		t.Fatalf("bad golden vector: %v", err)
	}
	buf := encodeDynamicForward(t, &DynamicForwardTargetReply{})
	if !bytes.Equal(buf, want) {
		t.Errorf("encoded target reply = %s, want %s", hex.EncodeToString(buf), hex.EncodeToString(want))
	}
}

// A payload carrying an unsupported version byte must be rejected by every
// parser instead of being silently misinterpreted.
func TestDynamicForwardUnsupportedVersion(t *testing.T) {
	for _, version := range []byte{0x00, 0x02, 0x03, 0x7f} {
		// request
		buf := append([]byte{version, byte(DynamicForwardKindRequest)}, 0x01, 0x00, 0x00)
		if _, err := ParseRequestDynamicForward(&util.BytesReadCloser{Reader: bytes.NewReader(buf)}); err == nil {
			t.Errorf("request with version byte %#x accepted", version)
		}
		// request reply
		buf = append([]byte{version, byte(DynamicForwardKindRequestReply)}, 0x00, 0x00, 0x00)
		if _, err := ParseDynamicForwardReply(&util.BytesReadCloser{Reader: bytes.NewReader(buf)}); err == nil {
			t.Errorf("request reply with version byte %#x accepted", version)
		}
		// target
		buf = append([]byte{version, byte(DynamicForwardKindTarget)}, 0x01, 'a', 0x00, 0x50)
		if _, err := ParseDynamicForwardTarget(&util.BytesReadCloser{Reader: bytes.NewReader(buf)}); err == nil {
			t.Errorf("target with version byte %#x accepted", version)
		}
		// target reply
		buf = append([]byte{version, byte(DynamicForwardKindTargetReply)}, 0x00)
		if _, err := ParseDynamicForwardTargetReply(&util.BytesReadCloser{Reader: bytes.NewReader(buf)}); err == nil {
			t.Errorf("target reply with version byte %#x accepted", version)
		}
	}
}

// The parsers are kind-strict: a target payload must not be accepted by the
// control-channel request parser, and vice versa.
func TestDynamicForwardUnexpectedKind(t *testing.T) {
	targetBuf := encodeDynamicForward(t, &DynamicForwardTarget{Address: "example.com", Port: 443})
	if _, err := ParseRequestDynamicForward(&util.BytesReadCloser{Reader: bytes.NewReader(targetBuf)}); err == nil {
		t.Error("target payload accepted as a control-channel request")
	}
	requestBuf := encodeDynamicForward(t, &RequestDynamicForward{BindAddress: "127.0.0.1", BindPort: 1080})
	if _, err := ParseDynamicForwardTarget(&util.BytesReadCloser{Reader: bytes.NewReader(requestBuf)}); err == nil {
		t.Error("control-channel request payload accepted as a target")
	}
	replyBuf := encodeDynamicForward(t, &DynamicForwardReply{BoundPort: 1080})
	if _, err := ParseDynamicForwardTargetReply(&util.BytesReadCloser{Reader: bytes.NewReader(replyBuf)}); err == nil {
		t.Error("control-channel reply payload accepted as a target reply")
	}
}

// Every truncation of a valid payload must be rejected.
func TestDynamicForwardTruncated(t *testing.T) {
	payloads := map[string]struct {
		buf   []byte
		parse func(util.Reader) error
	}{
		"request": {
			encodeDynamicForward(t, &RequestDynamicForward{BindAddress: "127.0.0.1", BindPort: 1080}),
			func(r util.Reader) error {
				_, err := ParseRequestDynamicForward(r)
				return err
			},
		},
		"request reply": {
			encodeDynamicForward(t, &DynamicForwardReply{BoundPort: 1080, ErrorUTF8: "boom"}),
			func(r util.Reader) error {
				_, err := ParseDynamicForwardReply(r)
				return err
			},
		},
		"target": {
			encodeDynamicForward(t, &DynamicForwardTarget{Address: "example.com", Port: 443}),
			func(r util.Reader) error {
				_, err := ParseDynamicForwardTarget(r)
				return err
			},
		},
		"target reply": {
			encodeDynamicForward(t, &DynamicForwardTargetReply{ErrorUTF8: "boom"}),
			func(r util.Reader) error {
				_, err := ParseDynamicForwardTargetReply(r)
				return err
			},
		},
	}
	for name, payload := range payloads {
		for cut := 0; cut < len(payload.buf); cut++ {
			if err := parseDynamicForward(t, payload.buf[:cut], payload.parse); err == nil {
				t.Errorf("%s: truncated input of %d bytes accepted", name, cut)
			}
		}
	}
}

// A target must carry an address and a non-zero port.
func TestDynamicForwardTargetEmptyAddress(t *testing.T) {
	buf := encodeDynamicForward(t, &DynamicForwardTarget{Address: "", Port: 80})
	if _, err := ParseDynamicForwardTarget(&util.BytesReadCloser{Reader: bytes.NewReader(buf)}); err == nil {
		t.Error("empty target address accepted")
	}
	buf = encodeDynamicForward(t, &DynamicForwardTarget{Address: "example.com", Port: 0})
	if _, err := ParseDynamicForwardTarget(&util.BytesReadCloser{Reader: bytes.NewReader(buf)}); err == nil {
		t.Error("zero target port accepted")
	}
}
