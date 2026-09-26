// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package client

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"

	"github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

// enableConsoleVT turns on ANSI escape processing for the console output
// handles (silent no-op on consoles without VT support) and returns a
// function restoring the previous console modes. It also switches the
// console code pages to UTF-8 so that remote UTF-8 text renders correctly.
func enableConsoleVT() (restore func()) {
	var (
		kernel32               = windows.NewLazySystemDLL("kernel32.dll")
		procGetConsoleCP       = kernel32.NewProc("GetConsoleCP")
		procSetConsoleCP       = kernel32.NewProc("SetConsoleCP")
		procGetConsoleOutputCP = kernel32.NewProc("GetConsoleOutputCP")
		procSetConsoleOutputCP = kernel32.NewProc("SetConsoleOutputCP")
	)
	const cpUTF8 = 65001
	oldInCP, _, _ := procGetConsoleCP.Call()
	oldOutCP, _, _ := procGetConsoleOutputCP.Call()
	procSetConsoleCP.Call(cpUTF8)
	procSetConsoleOutputCP.Call(cpUTF8)

	type handleMode struct {
		h    windows.Handle
		mode uint32
	}
	var saved []handleMode
	updates := []struct {
		f    *os.File
		flag uint32
	}{
		// input: arrow keys etc. must arrive as VT sequences, not INPUT_RECORDs
		{os.Stdin, windows.ENABLE_VIRTUAL_TERMINAL_INPUT},
		// output: remote ANSI must be interpreted, not printed literally
		{os.Stdout, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING},
		{os.Stderr, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING},
	}
	for _, u := range updates {
		h := windows.Handle(u.f.Fd())
		var mode uint32
		if err := windows.GetConsoleMode(h, &mode); err != nil {
			continue
		}
		if err := windows.SetConsoleMode(h, mode|u.flag); err != nil {
			continue
		}
		saved = append(saved, handleMode{h: h, mode: mode})
	}
	return func() {
		procSetConsoleCP.Call(oldInCP)
		procSetConsoleOutputCP.Call(oldOutCP)
		for _, s := range saved {
			_ = windows.SetConsoleMode(s.h, s.mode)
		}
	}
}

// Windows has no SIGHUP/SIGQUIT/SIGUSR* nor a SIGWINCH equivalent.
var forwardedSignals = map[syscall.Signal]string{
	syscall.SIGINT:  "INT",
	syscall.SIGTERM: "TERM",
}

func forwardWindowChanges(ctx context.Context, channel ssh3.Channel, tty *os.File) {
	// no resize signal to listen for: unwind on cancellation only
	<-ctx.Done()
}

func forwardSessionSignals(ctx context.Context, channel ssh3.Channel) {
	signals := make(chan os.Signal, len(forwardedSignals))
	notifiedSignals := make([]os.Signal, 0, len(forwardedSignals))
	for signal := range forwardedSignals {
		notifiedSignals = append(notifiedSignals, signal)
	}
	signal.Notify(signals, notifiedSignals...)
	defer signal.Stop(signals)

	for {
		select {
		case <-ctx.Done():
			return
		case receivedSignal := <-signals:
			signalName, ok := forwardedSignals[receivedSignal.(syscall.Signal)]
			if !ok {
				continue
			}
			err := channel.SendRequest(
				&ssh3Messages.ChannelRequestMessage{
					WantReply: false,
					ChannelRequest: &ssh3Messages.SignalRequest{
						SignalNameWithoutSig: signalName,
					},
				},
			)
			if err != nil {
				log.Warn().Msgf("could not send signal request for %s: %s", signalName, err)
				return
			}
		}
	}
}
