//go:build unix

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package ttymodes

// The unix side of the terminal modes: the RFC 4254 section 8 opcodes mapped
// onto the termios fields, applied to a pty slave and read back off a local
// terminal. The mapping follows OpenSSH ttymodes.h: flags set or clear their
// bit, control characters copy the code (255 = disabled), the speeds move
// the baud field and a zero speed leaves it alone.

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// flagOps maps a flag opcode onto its termios flag field accessor.
var flagOps = map[uint8]func(t *unix.Termios) *uint32{
	OpIGNPAR:  func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpPARMRK:  func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpINPCK:   func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpISTRIP:  func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpINLCR:   func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpIGNCR:   func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpICRNL:   func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpIUCLC:   func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpIXON:    func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpIXANY:   func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpIXOFF:   func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpIMAXBEL: func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpIUTF8:   func(t *unix.Termios) *uint32 { return &t.Iflag },
	OpISIG:    func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpICANON:  func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpECHO:    func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpECHOE:   func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpECHOK:   func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpECHONL:  func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpNOFLSH:  func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpTOSTOP:  func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpIEXTEN:  func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpECHOCTL: func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpECHOKE:  func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpPENDIN:  func(t *unix.Termios) *uint32 { return &t.Lflag },
	OpOPOST:   func(t *unix.Termios) *uint32 { return &t.Oflag },
	OpOLCUC:   func(t *unix.Termios) *uint32 { return &t.Oflag },
	OpONLCR:   func(t *unix.Termios) *uint32 { return &t.Oflag },
	OpOCRNL:   func(t *unix.Termios) *uint32 { return &t.Oflag },
	OpONOCR:   func(t *unix.Termios) *uint32 { return &t.Oflag },
	OpONLRET:  func(t *unix.Termios) *uint32 { return &t.Oflag },
}

// flagBits maps a flag opcode onto its termios bit.
var flagBits = map[uint8]uint32{
	OpIGNPAR:  unix.IGNPAR,
	OpPARMRK:  unix.PARMRK,
	OpINPCK:   unix.INPCK,
	OpISTRIP:  unix.ISTRIP,
	OpINLCR:   unix.INLCR,
	OpIGNCR:   unix.IGNCR,
	OpICRNL:   unix.ICRNL,
	OpIUCLC:   unix.IUCLC,
	OpIXON:    unix.IXON,
	OpIXANY:   unix.IXANY,
	OpIXOFF:   unix.IXOFF,
	OpIMAXBEL: unix.IMAXBEL,
	OpIUTF8:   unix.IUTF8,
	OpISIG:    unix.ISIG,
	OpICANON:  unix.ICANON,
	OpECHO:    unix.ECHO,
	OpECHOE:   unix.ECHOE,
	OpECHOK:   unix.ECHOK,
	OpECHONL:  unix.ECHONL,
	OpNOFLSH:  unix.NOFLSH,
	OpTOSTOP:  unix.TOSTOP,
	OpIEXTEN:  unix.IEXTEN,
	OpECHOCTL: unix.ECHOCTL,
	OpECHOKE:  unix.ECHOKE,
	OpPENDIN:  unix.PENDIN,
	OpOPOST:   unix.OPOST,
	OpOLCUC:   unix.OLCUC,
	OpONLCR:   unix.ONLCR,
	OpOCRNL:   unix.OCRNL,
	OpONOCR:   unix.ONOCR,
	OpONLRET:  unix.ONLRET,
	OpPARENB:  unix.PARENB,
	OpPARODD:  unix.PARODD,
}

// ccIndex maps a control-character opcode onto the termios cc slot.
var ccIndex = map[uint8]int{
	OpVINTR:    unix.VINTR,
	OpVQUIT:    unix.VQUIT,
	OpVERASE:   unix.VERASE,
	OpVKILL:    unix.VKILL,
	OpVEOF:     unix.VEOF,
	OpVTIME:    unix.VTIME,
	OpVMIN:     unix.VMIN,
	OpVSWTC:    unix.VSWTC,
	OpVSTART:   unix.VSTART,
	OpVSTOP:    unix.VSTOP,
	OpVSUSP:    unix.VSUSP,
	OpVEOL:     unix.VEOL,
	OpVREPRINT: unix.VREPRINT,
	OpVDISCARD: unix.VDISCARD,
	OpVWERASE:  unix.VWERASE,
	OpVLNEXT:   unix.VLNEXT,
	OpVEOL2:    unix.VEOL2,
}

// posixDisabled is the Linux _POSIX_VDISABLE: the cc value marking a
// disabled control character.
const posixDisabled = 0

// baudBits maps the common SSH speeds onto the termios baud constants.
var baudBits = map[uint32]uint32{
	50:      unix.B50,
	75:      unix.B75,
	110:     unix.B110,
	134:     unix.B134,
	150:     unix.B150,
	200:     unix.B200,
	300:     unix.B300,
	600:     unix.B600,
	1200:    unix.B1200,
	1800:    unix.B1800,
	2400:    unix.B2400,
	4800:    unix.B4800,
	9600:    unix.B9600,
	19200:   unix.B19200,
	38400:   unix.B38400,
	57600:   unix.B57600,
	115200:  unix.B115200,
	230400:  unix.B230400,
	460800:  unix.B460800,
	500000:  unix.B500000,
	921600:  unix.B921600,
	1000000: unix.B1000000,
	2000000: unix.B2000000,
	4000000: unix.B4000000,
}

// ApplyToTermios applies the mode set onto a termios snapshot and returns
// it: flags set or clear their bit, CS7/CS8 reshape CSIZE, control
// characters copy their code with 255 meaning disabled, the speeds move the
// baud field (a zero speed leaves it alone). Unknown opcodes are skipped.
func ApplyToTermios(base *unix.Termios, modes Modes) (*unix.Termios, error) {
	t := *base

	for opcode, arg := range modes {
		switch opcode {
		case OpCS7:
			t.Cflag = (t.Cflag &^ unix.CSIZE) | unix.CS7
			continue
		case OpCS8:
			t.Cflag = (t.Cflag &^ unix.CSIZE) | unix.CS8
			continue
		case OpISPEED, OpOSPEED:
			if arg == 0 {
				continue // a zero speed leaves the baud alone
			}

			bits, ok := baudBits[arg]
			if !ok {
				continue // an unknown rate is skipped, like OpenSSH
			}

			t.Cflag = (t.Cflag &^ (unix.CBAUD | unix.CBAUDEX)) | bits
			continue
		}

		if idx, ok := ccIndex[opcode]; ok {
			if arg == charDisabled {
				t.Cc[idx] = posixDisabled
			} else {
				t.Cc[idx] = uint8(arg)
			}
			continue
		}

		field, ok := flagOps[opcode]
		if !ok {
			continue // an unknown opcode is skipped, like OpenSSH
		}

		bit := flagBits[opcode]
		if arg != 0 {
			*field(&t) |= bit
		} else {
			*field(&t) &^= bit
		}
	}

	return &t, nil
}

// ApplyToFile applies the mode set to the open terminal file (the pty slave
// on the server side).
func ApplyToFile(f *os.File, modes Modes) error {
	if len(modes) == 0 {
		return nil
	}

	base, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		return fmt.Errorf("could not read the terminal modes: %w", err)
	}

	applied, err := ApplyToTermios(base, modes)
	if err != nil {
		return err
	}

	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, applied); err != nil {
		return fmt.Errorf("could not set the terminal modes: %w", err)
	}

	return nil
}

// FromTermios reads a termios snapshot into a mode set, the inverse of
// ApplyToTermios for everything the wire can carry.
func FromTermios(t *unix.Termios) Modes {
	modes := Modes{}

	for opcode, bit := range flagBits {
		// the control flags (PARENB/PARODD) live in Cflag, the rest were
		// registered through their field accessor
		var value uint32

		if opcode == OpPARENB || opcode == OpPARODD {
			value = t.Cflag & bit
		} else if field, ok := flagOps[opcode]; ok {
			value = *field(t) & bit
		}

		if value != 0 {
			modes[opcode] = 1
		} else {
			modes[opcode] = 0
		}
	}

	modes[OpCS8] = 0
	if t.Cflag&unix.CS8 != 0 {
		modes[OpCS8] = 1
	} else {
		modes[OpCS7] = 1
	}

	for opcode, idx := range ccIndex {
		if int(t.Cc[idx]) == posixDisabled {
			modes[opcode] = charDisabled
		} else {
			modes[opcode] = uint32(t.Cc[idx])
		}
	}

	if baud := t.Cflag & (unix.CBAUD | unix.CBAUDEX); baud != 0 && baudToBps[baud] != 0 {
		modes[OpISPEED] = baudToBps[baud]
		modes[OpOSPEED] = baudToBps[baud]
	}

	return modes
}

// baudToBps inverts baudBits for the reader side.
var baudToBps = func() map[uint32]uint32 {
	inv := make(map[uint32]uint32, len(baudBits))
	for bps, bits := range baudBits {
		inv[bits] = bps
	}
	return inv
}()

// LocalTermiosModes reads the modes of the open local terminal file and
// encodes them for the pty request; an empty string when the terminal
// cannot be read.
func LocalTermiosModes(f *os.File) string {
	if f == nil {
		return ""
	}

	t, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		return ""
	}

	return string(Marshal(FromTermios(t)))
}
