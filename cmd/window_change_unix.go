// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

// Window size propagation for the forced-pty session. On unix the terminal
// reports its new size through SIGWINCH, which is what turns "ssh3 -t host top"
// into a resizable session.

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client/winsize"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

func forwardForcedPtyWindowChanges(ctx context.Context, channel ssh3.Channel, tty *os.File) {
	if tty == nil {
		return
	}
	if _, err := winsize.GetWinsize(tty); err != nil {
		log.Debug().Msgf("window size is not available, window changes are not forwarded: %s", err)
		return
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGWINCH)
	defer signal.Stop(signals)

	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			if err := sendForcedPtyWindowChange(channel, tty); err != nil {
				log.Warn().Msgf("could not send window change request: %s", err)
				return
			}
		}
	}
}

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
