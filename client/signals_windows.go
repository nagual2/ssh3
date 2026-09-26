//go:build windows

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
