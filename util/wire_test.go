package util

import (
	"bytes"
	"errors"
	"testing"
)

// QUIC variable-length integers use 1, 2, 4 or 8 bytes and can only encode
// values up to 2^62-1. The 62-bit limit is a wire-format invariant, so
// VarIntLen panics beyond it: callers must never hand it a wider value.
func TestVarIntLenEdges(t *testing.T) {
	edges := []struct {
		value uint64
		want  uint64
	}{
		{0, 1},
		{63, 1},
		{64, 2},
		{16383, 2},
		{16384, 4},
		{1<<30 - 1, 4},
		{1 << 30, 8},
		{1<<62 - 1, 8},
	}
	for _, e := range edges {
		if got := VarIntLen(e.value); got != e.want {
			t.Errorf("VarIntLen(%d) = %d, want %d", e.value, got, e.want)
		}
	}
}

func TestVarIntLenPanicsBeyond62Bits(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected VarIntLen to panic for values above 2^62-1")
		}
	}()
	VarIntLen(1 << 62)
}

// A peer-controlled string length must never drive an allocation: above the
// cap ParseSSHString must reject without allocating (the old make([]byte,
// length) turned 8 attacker bytes into a makeslice panic or an OOM kill).
func TestParseSSHStringRejectsOversizedLength(t *testing.T) {
	cases := []uint64{MaxSSHStringLen + 1, 1 << 40, 1<<62 - 1}
	for _, length := range cases {
		buf := AppendVarInt(nil, length)
		_, err := ParseSSHString(NewReader(bytes.NewReader(buf)))
		var invalid InvalidSSHString
		if err == nil {
			t.Errorf("length %d: expected InvalidSSHString, got no error", length)
		} else if !errors.As(err, &invalid) {
			t.Errorf("length %d: expected InvalidSSHString, got %v", length, err)
		}
	}
}

// lengths up to the cap stay accepted
func TestParseSSHStringAcceptsLengthsUpToCap(t *testing.T) {
	for _, length := range []uint64{0, 1, 1024, MaxSSHStringLen} {
		payload := bytes.Repeat([]byte("a"), int(length))
		buf := AppendVarInt(nil, length)
		got, err := ParseSSHString(NewReader(bytes.NewReader(append(buf, payload...))))
		if err != nil {
			t.Fatalf("length %d: unexpected error %v", length, err)
		}
		if len(got) != int(length) {
			t.Errorf("length %d: parsed %d bytes", length, len(got))
		}
	}
}

func TestVarIntAppendReadRoundtrip(t *testing.T) {
	edges := []uint64{0, 1, 63, 64, 16383, 16384, 1<<30 - 1, 1 << 30, 1<<62 - 1}
	for _, v := range edges {
		buf := AppendVarInt(nil, v)
		got, err := ReadVarInt(bytes.NewReader(buf))
		if err != nil {
			t.Fatalf("ReadVarInt(AppendVarInt(%d)): %s", v, err)
		}
		if got != v {
			t.Errorf("roundtrip of %d returned %d", v, got)
		}
	}
}

// Fuzz the length-encoding roundtrip. Values above 2^62-1 cannot be encoded
// on the wire and are skipped: they must never reach the encoder (the caller's
// invariant, see the exit-status clamping in cmd/ssh3-server.go).
func FuzzVarIntAppendReadRoundtrip(f *testing.F) {
	for _, v := range []uint64{0, 1, 63, 64, 16383, 16384, 1 << 30, 1<<62 - 1} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v uint64) {
		if v > 1<<62-1 {
			t.Skip("not encodable: above the 62-bit varint limit")
		}
		buf := AppendVarInt(nil, v)
		got, err := ReadVarInt(bytes.NewReader(buf))
		if err != nil || got != v {
			t.Fatalf("roundtrip of %d returned (%d, %v)", v, got, err)
		}
	})
}
