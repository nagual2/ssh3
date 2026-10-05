// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winsize

import (
	"context"
	"os"
	"time"

	"golang.org/x/term"
)

// PollChanges polls the console geometry on a ticker — Windows has no
// SIGWINCH and draining console input events for resize notifications would
// steal keystrokes from the stdin pump — and calls onChange on every actual
// size change. It returns when the context ends or onChange fails. The
// first observation only primes the baseline: the pty request already
// carried that geometry.
func PollChanges(ctx context.Context, tty *os.File, every time.Duration, onChange func() error) error {
	lastCols, lastRows := -1, -1

	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		ws, err := GetWinsize(tty)
		if err != nil {
			continue
		}

		cols, rows := int(ws.NCols), int(ws.NRows)
		if cols == lastCols && rows == lastRows {
			continue
		}

		first := lastCols == -1
		lastCols, lastRows = cols, rows

		if first {
			continue
		}

		if err := onChange(); err != nil {
			return err
		}
	}
}

func GetWinsize(tty *os.File) (ws WindowSize, err error) {
	// on Windows the input handle (CONIN$) carries no screen buffer, so the
	// query on it fails: fall back to the output handles, which have one
	for _, f := range []*os.File{tty, os.Stdout, os.Stderr} {
		if f == nil {
			continue
		}
		var width, height int
		width, height, err = term.GetSize(int(f.Fd()))
		if err != nil {
			continue
		}
		ws.NCols = uint16(width)
		ws.NRows = uint16(height)
		ws.PixelWidth = 0
		ws.PixelHeight = 0
		return ws, nil
	}
	return ws, err
}
