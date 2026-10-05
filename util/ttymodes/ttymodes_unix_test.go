//go:build linux

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package ttymodes

// The unix side: the RFC 4254 section 8 opcodes mapped onto the termios
// fields, applied to a pty slave and read back off a local terminal.

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestTermiosRoundTrip(t *testing.T) {
	// a plausible raw-ish terminal
	var base unix.Termios

	base.Iflag = unix.ICRNL | unix.IXON | unix.IMAXBEL | unix.IUTF8
	base.Oflag = unix.OPOST | unix.ONLCR
	base.Cflag = unix.CS8 | unix.CREAD | unix.B38400
	base.Lflag = unix.ISIG | unix.ICANON | unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHOCTL | unix.ECHOKE | unix.IEXTEN

	cc := [20]uint8{}
	cc[unix.VINTR] = 3 // ^C
	cc[unix.VEOF] = 4  // ^D
	cc[unix.VMIN] = 1
	cc[unix.VTIME] = 0
	copy(base.Cc[:], cc[:])

	modes := FromTermios(&base)
	if len(modes) == 0 {
		t.Fatal("FromTermios produced no modes")
	}

	// the flags the SSH wire carries must survive the round trip onto a
	// different base: start from an all-clear termios and apply the modes
	var blank unix.Termios
	blank.Cflag = unix.CREAD
	blank.Cc[unix.VMIN] = 1
	blank.Cc[unix.VTIME] = 0

	applied, err := ApplyToTermios(&blank, modes)
	if err != nil {
		t.Fatalf("ApplyToTermios: %v", err)
	}

	if applied.Iflag&unix.ICRNL == 0 || applied.Iflag&unix.IXON == 0 || applied.Iflag&unix.IUTF8 == 0 {
		t.Errorf("iflag lost bits: %x", applied.Iflag)
	}

	if applied.Oflag&unix.OPOST == 0 || applied.Oflag&unix.ONLCR == 0 {
		t.Errorf("oflag lost bits: %x", applied.Oflag)
	}

	if applied.Lflag&unix.ICANON == 0 || applied.Lflag&unix.ECHO == 0 || applied.Lflag&unix.ISIG == 0 {
		t.Errorf("lflag lost bits: %x", applied.Lflag)
	}

	if applied.Cflag&unix.CS8 == 0 {
		t.Errorf("cflag lost CS8: %x", applied.Cflag)
	}

	if applied.Cc[unix.VINTR] != 3 || applied.Cc[unix.VEOF] != 4 {
		t.Errorf("control characters lost: VINTR=%d VEOF=%d", applied.Cc[unix.VINTR], applied.Cc[unix.VEOF])
	}

	if applied.Cc[unix.VMIN] != 1 {
		t.Errorf("VMIN must survive the apply: %d", applied.Cc[unix.VMIN])
	}
}

func TestApplyToTermiosClearsAndUnknownOpcodes(t *testing.T) {
	var base unix.Termios
	base.Lflag = unix.ICANON | unix.ECHO
	base.Iflag = unix.ICRNL

	modes := map[uint8]uint32{
		55:  0, // ECHO off
		54:  0, // ICANON off
		36:  0, // ICRNL off
		99:  1, // an unknown opcode, must be skipped
		192: 0, // speed 0: leave the baud alone
	}

	applied, err := ApplyToTermios(&base, modes)
	if err != nil {
		t.Fatalf("ApplyToTermios: %v", err)
	}

	if applied.Lflag&unix.ECHO != 0 || applied.Lflag&unix.ICANON != 0 {
		t.Errorf("lflag bits must be cleared: %x", applied.Lflag)
	}

	if applied.Iflag&unix.ICRNL != 0 {
		t.Errorf("iflag ICRNL must be cleared: %x", applied.Iflag)
	}

	if applied.Cflag&unix.CBAUD != base.Cflag&unix.CBAUD {
		t.Errorf("a zero speed must leave the baud alone: %x", applied.Cflag)
	}
}

func TestApplyToTermiosSpeedsAndCharDisable(t *testing.T) {
	var base unix.Termios
	base.Cflag = unix.CS8 | unix.B9600
	base.Cc[unix.VINTR] = 3

	modes := map[uint8]uint32{
		192: 115200, // ISPEED
		193: 115200, // OSPEED
		1:   255,    // VINTR = the disabled marker
	}

	applied, err := ApplyToTermios(&base, modes)
	if err != nil {
		t.Fatalf("ApplyToTermios: %v", err)
	}

	if got := applied.Cflag & (unix.CBAUD | unix.CBAUDEX); got != unix.B115200 {
		t.Errorf("the baud must move to B115200, got %x", got)
	}

	if applied.Cc[unix.VINTR] != posixDisabled {
		t.Errorf("VINTR must map 255 to the disable value, got %d", applied.Cc[unix.VINTR])
	}
}
