// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The window-change request sender, shared by the SIGWINCH relay (unix) and
// the console-geometry poller (Windows).

import (
	"os"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client/winsize"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

func sendForcedPtyWindowChange(channel ssh3.Channel, tty *os.File) error {
	windowSize, err := winsize.GetWinsize(tty)
	if err != nil {
		return err
	}
	return channel.SendRequest(
		&ssh3Messages.ChannelRequestMessage{
			WantReply: false,
			ChannelRequest: &ssh3Messages.WindowChangeRequest{
				CharWidth:   uint64(windowSize.NCols),
				CharHeight:  uint64(windowSize.NRows),
				PixelWidth:  uint64(windowSize.PixelWidth),
				PixelHeight: uint64(windowSize.PixelHeight),
			},
		},
	)
}
