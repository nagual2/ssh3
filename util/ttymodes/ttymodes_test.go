// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

// Package ttymodes parses, marshals and applies the SSH terminal modes of
// the pty-req body (RFC 4254 section 8). The wire format is a sequence of
// (opcode byte, uint32 big-endian argument) entries terminated by the
// TTY_OP_END opcode.
package ttymodes

import (
	"encoding/binary"
	"testing"
)

func TestParseSSHTerminalModes(t *testing.T) {
	// two entries then the end marker: ECHO(55)=0, ISPEED(192)=38400
	data := []byte{
		55, 0, 0, 0, 0,
		192, 0, 0, 0x96, 0x00,
		0,
	}

	modes, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := modes[55]; got != 0 {
		t.Errorf("ECHO = %d, want 0", got)
	}

	if got := modes[192]; got != 38400 {
		t.Errorf("ISPEED = %d, want 38400", got)
	}

	if _, ok := modes[0]; ok {
		t.Error("the end marker must not appear as a mode")
	}
}

func TestParseSSHTerminalModesEmpty(t *testing.T) {
	modes, err := Parse(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(modes) != 0 {
		t.Errorf("want an empty mode set, got %v", modes)
	}

	if modes, err = Parse([]byte{0}); err != nil || len(modes) != 0 {
		t.Errorf("a bare end marker must parse to no modes: %v %v", modes, err)
	}
}

func TestParseSSHTerminalModesTruncated(t *testing.T) {
	for _, bad := range [][]byte{
		{55, 0, 0, 0},        // the argument is cut
		{55},                 // the argument is missing
		{55, 0, 0, 0, 0, 55}, // a tail opcode without an argument
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(% x): want a truncation error", bad)
		}
	}
}

func TestMarshalSSHTerminalModesRoundTrip(t *testing.T) {
	want := map[uint8]uint32{
		55:  1,      // ECHO
		54:  0,      // ICANON
		192: 115200, // ISPEED
		193: 115200, // OSPEED
		5:   'e',    // VEOF
	}

	wire := Marshal(want)

	got, err := Parse(wire)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("round trip lost modes: got %v, want %v", got, want)
	}

	for op, arg := range want {
		if got[op] != arg {
			t.Errorf("opcode %d: got %d, want %d", op, got[op], arg)
		}
	}
}

func TestMarshalSSHTerminalModesEndsAndSizes(t *testing.T) {
	wire := Marshal(map[uint8]uint32{55: 1})

	if len(wire) != 5+1 {
		t.Fatalf("want 5 entry bytes + the end marker, got %d", len(wire))
	}

	if wire[5] != 0 {
		t.Errorf("the wire must end with the end marker, got opcode %d", wire[5])
	}

	if binary.BigEndian.Uint32(wire[1:5]) != 1 {
		t.Errorf("the argument must be big-endian, got % x", wire[1:5])
	}
}
