// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package client

// Slave-side interaction relay: forwards terminal events from the local tty
// to the control master as cm frames. Raw-mode input bytes reach the remote
// pty through the io stream, so ^C/^Z never produce local signals; what is
// relayed is SIGWINCH-driven resizes and out-of-band signals (HUP, TERM...)
// that still hit the slave process.

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3/client/cm"
	"github.com/francoismichel/ssh3/client/winsize"
)

// relaySlaveTTYEvents forwards SIGWINCH resizes as WINDOW_CHANGE frames and
// out-of-band signals as SIGNAL frames on the session control connection.
// Returns a stop func releasing the signal handlers and the relay goroutine.
func relaySlaveTTYEvents(control net.Conn, tty *os.File) (stop func()) {
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	sigs := make(chan os.Signal, len(forwardedSignals))
	notified := make([]os.Signal, 0, len(forwardedSignals))
	for s := range forwardedSignals {
		notified = append(notified, s)
	}
	signal.Notify(sigs, notified...)

	stopCh := make(chan struct{})
	go func() {
		for {
			select {
			case <-winch:
				ws, err := winsize.GetWinsize(tty)
				if err != nil {
					continue
				}
				frame := (&cm.WindowChange{
					Columns:     uint32(ws.NCols),
					Rows:        uint32(ws.NRows),
					PixelWidth:  uint32(ws.PixelWidth),
					PixelHeight: uint32(ws.PixelHeight),
				}).Encode()
				if err := cm.WriteFrame(control, cm.MsgWindowChange, frame); err != nil {
					log.Debug().Msgf("slave: could not send window change: %s", err)
					return
				}
			case s := <-sigs:
				name, ok := forwardedSignals[s.(syscall.Signal)]
				if !ok {
					continue
				}
				if err := cm.WriteFrame(control, cm.MsgSignal, (&cm.Signal{Name: name}).Encode()); err != nil {
					log.Debug().Msgf("slave: could not send signal %s: %s", name, err)
					return
				}
			case <-stopCh:
				return
			}
		}
	}()

	return func() {
		signal.Stop(winch)
		signal.Stop(sigs)
		close(stopCh)
	}
}
