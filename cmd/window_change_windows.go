// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmd

// Window size propagation for the forced-pty session. Go's Windows syscall
// package has no SIGWINCH, and draining console input events for resize
// notifications would steal keystrokes from the stdin pump, so the console
// geometry is polled and a window-change request rides out on a change.

import (
	"context"
	"os"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client/winsize"
)

const forcedPtyResizePollInterval = 500 * time.Millisecond

func forwardForcedPtyWindowChanges(ctx context.Context, channel ssh3.Channel, tty *os.File) {
	if tty == nil {
		return
	}
	if _, err := winsize.GetWinsize(tty); err != nil {
		log.Debug().Msgf("window size is not available, window changes are not forwarded: %s", err)
		return
	}

	err := winsize.PollChanges(ctx, tty, forcedPtyResizePollInterval, func() error {
		return sendForcedPtyWindowChange(channel, tty)
	})
	if err != nil {
		log.Warn().Msgf("could not send window change request: %s", err)
	}
}
