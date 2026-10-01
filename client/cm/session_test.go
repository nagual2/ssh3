package cm

// Session-bridging message tests (increment 3).

import (
	"bytes"
	"testing"
)

func TestAttachRoundTrip(t *testing.T) {
	in := Attach{Token: Token{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, Stream: StreamStderr}
	b := in.Encode()
	out := Attach{}
	if err := out.Decode(b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if in != out {
		t.Fatalf("round trip mismatch: in = %+v, out = %+v", in, out)
	}
	in.Stream = StreamIO
	out = Attach{}
	if err := out.Decode(in.Encode()); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if in != out {
		t.Fatalf("round trip mismatch: in = %+v, out = %+v", in, out)
	}
}

func TestAttachRejectsGarbage(t *testing.T) {
	for _, payload := range [][]byte{
		{},               // empty
		{1, 2, 3},        // short token
		make([]byte, 15), // token without stream byte
		make([]byte, 18), // trailing byte
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2}, // unknown stream kind
	} {
		if err := (&Attach{}).Decode(payload); err == nil {
			t.Fatalf("decode(% x) succeeded, want error", payload)
		}
	}
}

func TestExitStatusRoundTrip(t *testing.T) {
	for _, code := range []uint64{0, 7, 42, 255, 1 << 32} {
		b := EncodeExitStatus(code)
		got, err := DecodeExitStatus(b)
		if err != nil {
			t.Fatalf("decode(%d): %v", code, err)
		}
		if got != code {
			t.Fatalf("got %d, want %d", got, code)
		}
	}
}

func TestExitStatusRejectsBadPayload(t *testing.T) {
	for _, payload := range [][]byte{nil, {1, 2, 3}, make([]byte, 9)} {
		if _, err := DecodeExitStatus(payload); err == nil {
			t.Fatalf("decode(% x) succeeded, want error", payload)
		}
	}
}

func TestFrameCarriesAttach(t *testing.T) {
	var buf bytes.Buffer
	att := Attach{Token: Token{0xaa}, Stream: StreamIO}
	if err := WriteFrame(&buf, MsgAttach, att.Encode()); err != nil {
		t.Fatalf("write: %v", err)
	}
	typ, payload, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if typ != MsgAttach {
		t.Fatalf("type = %v, want %v", typ, MsgAttach)
	}
	out := Attach{}
	if err := out.Decode(payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out != att {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, att)
	}
}
