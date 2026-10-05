//go:build unix && !linux

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package ttymodes

import "os"

// LocalTermiosModes reads the modes of the local terminal; the termios
// mapping lives in the linux file (the x/sys/unix constants differ across
// the BSDs and darwin), other unix clients send no terminal modes and the
// server applies its defaults.
func LocalTermiosModes(_ *os.File) string {
	return ""
}

// ApplyToFile applies the mode set to an open terminal; on non-linux unix
// the full mapping is not built, the server does not ship here.
func ApplyToFile(_ *os.File, _ Modes) error {
	return nil
}
