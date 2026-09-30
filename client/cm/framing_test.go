package cm

// Codec tests for the ControlMaster framing: round-trip, version mismatch,
// garbage input, truncation (CTO_TASK §6b increment 2).

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello control master")
	if err := WriteFrame(&buf, MsgOpenSession, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	typ, got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != MsgOpenSession {
		t.Fatalf("type = %v, want %v", typ, MsgOpenSession)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

func TestFrameEmptyPayloadRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	for _, typ := range []MsgType{MsgHello, MsgExit, MsgOK} {
		if err := WriteFrame(&buf, typ, nil); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, payload, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if got != typ || len(payload) != 0 {
			t.Fatalf("got (%v, %d bytes), want (%v, 0 bytes)", got, len(payload), typ)
		}
	}
}

func TestFrameMaxPayloadAccepted(t *testing.T) {
	payload := make([]byte, maxFrame)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, MsgError, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != maxFrame {
		t.Fatalf("payload len = %d, want %d", len(got), maxFrame)
	}
}

func TestFrameOversizeWriteRejected(t *testing.T) {
	if err := WriteFrame(io.Discard, MsgError, make([]byte, maxFrame+1)); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("err = %v, want ErrFrameSize", err)
	}
}

func TestFrameRejectsBadMagic(t *testing.T) {
	// a stray HTTP probe is the realistic garbage dialer
	garbage := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n" + "0000000000")
	_, _, err := ReadFrame(bytes.NewReader(garbage))
	if !errors.Is(err, ErrBadMagic) {
		t.Fatalf("err = %v, want ErrBadMagic", err)
	}
}

func TestFrameRejectsVersionMismatch(t *testing.T) {
	hdr := make([]byte, headerLen)
	copy(hdr, magic[:])
	hdr[4] = Version + 1
	hdr[5] = byte(MsgHello)
	_, _, err := ReadFrame(bytes.NewReader(hdr))
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("err = %v, want ErrVersion", err)
	}
}

func TestFrameRejectsOversizeRead(t *testing.T) {
	hdr := make([]byte, headerLen)
	copy(hdr, magic[:])
	hdr[4] = Version
	hdr[5] = byte(MsgHello)
	binary.BigEndian.PutUint32(hdr[6:], maxFrame+1)
	_, _, err := ReadFrame(bytes.NewReader(hdr))
	if !errors.Is(err, ErrFrameSize) {
		t.Fatalf("err = %v, want ErrFrameSize", err)
	}
}

func TestFrameCleanEOFAfterFullFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, MsgExit, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := ReadFrame(&buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
}

func TestFrameTruncatedIsNotEOF(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, MsgError, []byte("abcde")); err != nil {
		t.Fatalf("write: %v", err)
	}
	full := buf.Bytes()
	for _, cut := range []int{headerLen / 2, headerLen + 2} {
		_, _, err := ReadFrame(bytes.NewReader(full[:cut]))
		if !errors.Is(err, ErrTruncated) {
			t.Fatalf("cut %d: err = %v, want ErrTruncated", cut, err)
		}
	}
}
