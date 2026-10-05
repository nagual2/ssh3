//go:build !unix

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

// Windows has no SIGTSTP: the ~^Z escape sequence forwards literally (the
// EscapeConfig.Suspend callback stays nil).

import (
	"os"

	"golang.org/x/term"
)

// LocalSuspendFunc returns nil on windows: there is no console suspend.
func LocalSuspendFunc(_ *os.File, _ *term.State) func() error {
	return nil
}
