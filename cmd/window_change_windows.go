// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmd

// Window size propagation for the forced-pty session. Go's Windows syscall
// package has no SIGWINCH (the console reports a resize through an event, not a
// signal), so there is nothing to forward here: the geometry sent with the pty
// request stands for the whole session.

import (
	"context"
	"os"

	"github.com/francoismichel/ssh3"
)

func forwardForcedPtyWindowChanges(_ context.Context, _ ssh3.Channel, _ *os.File) {}
