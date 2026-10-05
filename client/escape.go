// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

// The OpenSSH-style escape filter of the interactive stdin pump: an escape
// character at the start of a line introduces the sequences
//
//	~.    disconnect (a clean client-side teardown)
//	~^Z   suspend the client locally (only when a Suspend callback exists;
//	      unix restores the terminal, SIGTSTPs itself and re-enters raw mode
//	      on resume; elsewhere the sequence forwards literally)
//	~~    one literal escape character
//
// anything else after the escape character forwards literally. The filter is
// a pure state machine over the stdin chunks, so a sequence split across
// reads still fires and byte-exact exec traffic is untouched (the filter
// only arms for interactive pty sessions).

import (
	"errors"
)

// ErrEscapeDisconnect is the terminal error of a session ended by the ~.
// escape sequence.
var ErrEscapeDisconnect = errors.New("connection closed by escape sequence")

// EscapeConfig carries the interactive escape wiring: Char is the escape
// character (0 disables the filter), Suspend runs on ~^Z (nil where the
// console cannot suspend), Disconnect runs on ~. and owns the teardown.
type EscapeConfig struct {
	Char       byte
	Suspend    func() error
	Disconnect func() error
}

type escapeFilter struct {
	cfg       *EscapeConfig
	lineStart bool
	pending   bool // the escape character was seen at a line start
}

func newEscapeFilter(cfg *EscapeConfig) *escapeFilter {
	return &escapeFilter{cfg: cfg, lineStart: true}
}

// Feed filters one stdin chunk and returns the bytes to forward plus the
// action that fired, if any ("disconnect" or "suspend"). After a disconnect
// the caller must stop pumping; after a suspend the pump continues.
func (f *escapeFilter) Feed(chunk []byte) (forwarded []byte, action string) {
	if f.cfg == nil || f.cfg.Char == 0 {
		return chunk, ""
	}

	out := make([]byte, 0, len(chunk))

	for _, b := range chunk {
		if f.pending {
			f.pending = false

			switch {
			case b == '.':
				return out, "disconnect"

			case b == 0x1a && f.cfg.Suspend != nil:
				return out, "suspend"

			case b == f.cfg.Char:
				// ~~ collapses to one literal escape character; the
				// emitted one does not re-arm at the line start
				out = append(out, f.cfg.Char)

			default:
				// an unknown sequence forwards literally, the escape
				// character on top of the action byte
				out = append(out, f.cfg.Char, b)
				f.lineStart = b == '\n' || b == '\r'
			}

			continue
		}

		if b == f.cfg.Char && f.lineStart {
			f.pending = true
			continue
		}

		out = append(out, b)
		f.lineStart = b == '\n' || b == '\r'
	}

	return out, ""
}
