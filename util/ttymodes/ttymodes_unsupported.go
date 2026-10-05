//go:build !unix

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package ttymodes

import "os"

// LocalTermiosModes reads the modes of the local terminal; Windows has no
// termios, the pty request carries no modes there.
func LocalTermiosModes(_ *os.File) string {
	return ""
}
