// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

// Package ttymodes parses, marshals and applies the SSH terminal modes of
// the pty-req body (RFC 4254 section 8). The wire format is a sequence of
// (opcode byte, uint32 big-endian argument) entries terminated by the
// TTY_OP_END opcode; the opcode numbering follows the RFC (control
// characters 1-17, input flags 30-42, local flags 53-64, output flags
// 70-75, control flags 90-93, speeds 192/193).
package ttymodes

// The wire opcodes of RFC 4254 section 8. Only the opcodes with a termios
// mapping on this platform are interpreted; unknown ones are skipped, like
// OpenSSH skips what its ttymodes table does not carry.
const (
	OpEnd = 0

	// control characters (argument: the character code, 255 = disabled)
	OpVINTR    = 1
	OpVQUIT    = 2
	OpVERASE   = 3
	OpVKILL    = 4
	OpVEOF     = 5
	OpVTIME    = 6
	OpVMIN     = 7
	OpVSWTC    = 8
	OpVSTART   = 9
	OpVSTOP    = 10
	OpVSUSP    = 11
	OpVEOL     = 12
	OpVREPRINT = 13
	OpVDISCARD = 14
	OpVWERASE  = 15
	OpVLNEXT   = 16
	OpVEOL2    = 17

	// input flags
	OpIGNPAR  = 30
	OpPARMRK  = 31
	OpINPCK   = 32
	OpISTRIP  = 33
	OpINLCR   = 34
	OpIGNCR   = 35
	OpICRNL   = 36
	OpIUCLC   = 37
	OpIXON    = 38
	OpIXANY   = 39
	OpIXOFF   = 40
	OpIMAXBEL = 41
	OpIUTF8   = 42

	// local flags
	OpISIG    = 53
	OpICANON  = 54
	OpECHO    = 55
	OpECHOE   = 56
	OpECHOK   = 57
	OpECHONL  = 58
	OpNOFLSH  = 59
	OpTOSTOP  = 60
	OpIEXTEN  = 61
	OpECHOCTL = 62
	OpECHOKE  = 63
	OpPENDIN  = 64

	// output flags
	OpOPOST  = 70
	OpOLCUC  = 71
	OpONLCR  = 72
	OpOCRNL  = 73
	OpONOCR  = 74
	OpONLRET = 75

	// control flags
	OpCS7    = 90
	OpCS8    = 91
	OpPARENB = 92
	OpPARODD = 93

	OpISPEED = 192
	OpOSPEED = 193
)

// charDisabled is the SSH argument meaning "this control character is
// disabled"; OpenSSH maps it onto _POSIX_VDISABLE.
const charDisabled = 255

// Modes is one parsed terminal mode set: opcode -> argument.
type Modes map[uint8]uint32

// Parse decodes the EncodedTerminalModes payload of a pty request. A
// truncated entry is an error; everything behind the end marker is ignored.
func Parse(data []byte) (Modes, error) {
	modes := Modes{}

	for i := 0; i < len(data); {
		opcode := data[i]
		i++

		if opcode == OpEnd {
			return modes, nil
		}

		if len(data)-i < 4 {
			return nil, ErrTruncated
		}

		arg := uint32(data[i])<<24 | uint32(data[i+1])<<16 | uint32(data[i+2])<<8 | uint32(data[i+3])
		i += 4

		modes[opcode] = arg
	}

	// no end marker: OpenSSH accepts the stream as over, so do we
	return modes, nil
}

// Marshal encodes a mode set on the wire, a terminator on top.
func Marshal(modes Modes) []byte {
	wire := make([]byte, 0, len(modes)*5+1)

	for opcode, arg := range modes {
		wire = append(wire, opcode,
			byte(arg>>24), byte(arg>>16), byte(arg>>8), byte(arg))
	}

	return append(wire, OpEnd)
}

// ErrTruncated reports a mode entry whose argument is cut short.
var ErrTruncated = errorString("terminal modes: truncated mode entry")

type errorString string

func (e errorString) Error() string { return string(e) }
