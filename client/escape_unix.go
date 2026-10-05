//go:build unix

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

// The ~^Z suspend callback of the interactive escape sequences: the console
// owner hands in the raw state it captured, the callback restores the
// terminal, SIGTSTPs the client (the process stops here until the shell
// continues it) and re-enters raw mode on resume.

import (
	"os"
	"syscall"

	"golang.org/x/term"
)

// LocalSuspendFunc builds the Suspend callback of EscapeConfig for the
// console behind tty; nil when there is no captured raw state.
func LocalSuspendFunc(tty *os.File, oldState *term.State) func() error {
	if oldState == nil || tty == nil {
		return nil
	}

	return func() error {
		if err := term.Restore(int(tty.Fd()), oldState); err != nil {
			return err
		}

		// the process stops here; the callback returns after SIGCONT
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGTSTP); err != nil {
			return err
		}

		_, err := term.MakeRaw(int(tty.Fd()))
		return err
	}
}
