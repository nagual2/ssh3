//go:build !windows

package client

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

var forwardedSignals = map[syscall.Signal]string{
	syscall.SIGHUP:  "HUP",
	syscall.SIGINT:  "INT",
	syscall.SIGQUIT: "QUIT",
	syscall.SIGTERM: "TERM",
	syscall.SIGUSR1: "USR1",
	syscall.SIGUSR2: "USR2",
}

// enableConsoleVT is a no-op: unix terminals process escape sequences natively.
func enableConsoleVT() (restore func()) {
	return func() {}
}

func forwardWindowChanges(ctx context.Context, channel ssh3.Channel, tty *os.File) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGWINCH)
	defer signal.Stop(signals)

	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			if err := sendWindowChangeRequest(channel, tty); err != nil {
				log.Warn().Msgf("could not send window change request: %s", err)
				return
			}
		}
	}
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
