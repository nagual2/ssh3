package cmd

// Forced PTY (-t): request a remote pseudo-terminal even when the local side is
// not a terminal, or when a remote command was given. Without -t the default
// behaviour is untouched: a pty is requested only for an interactive session
// driven by a local terminal, as client.RunSession does.
//
// The session is driven here instead of through client.RunSession because that
// one decides on the pty from the local console alone and cannot be told
// otherwise.

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
	"golang.org/x/term"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client"
	"github.com/francoismichel/ssh3/client/winsize"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

const (
	// defaultPtyColumns and defaultPtyRows are used when the local geometry
	// cannot be queried (no terminal at all, or a Windows console that does
	// not answer the query). A pty with a default geometry still beats a raw
	// pipe session: remote ncurses programs refuse to start without one.
	defaultPtyColumns = 80
	defaultPtyRows    = 24
	// defaultPtyTerm is the terminal type reported when TERM is unset; remote
	// ncurses programs expect one.
	defaultPtyTerm = "xterm"
)

// forwardedPtySignals maps the local signals worth propagating to the remote
// pty. The set is deliberately the intersection of the unix and the Windows
// signal lists, so one table serves both platforms: SIGUSR1/SIGUSR2 and
// SIGWINCH do not exist on Windows.
var forwardedPtySignals = map[syscall.Signal]string{
	syscall.SIGHUP:  "HUP",
	syscall.SIGINT:  "INT",
	syscall.SIGQUIT: "QUIT",
	syscall.SIGTERM: "TERM",
}

// newForcedPtySpec builds the pty request for a forced-pty session. tty may be
// nil: the geometry then falls back to 80x24 and the terminal type to $TERM or
// "xterm".
func newForcedPtySpec(tty *os.File) (*client.PtySpec, error) {
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = defaultPtyTerm
	}

	columns, rows := defaultPtyColumns, defaultPtyRows
	var pixelWidth, pixelHeight uint64
	if tty != nil {
		windowSize, err := winsize.GetWinsize(tty)
		if err != nil {
			log.Warn().Msgf("could not get window size: %+v, using %dx%d", err, defaultPtyColumns, defaultPtyRows)
		} else {
			columns, rows = int(windowSize.NCols), int(windowSize.NRows)
			pixelWidth, pixelHeight = uint64(windowSize.PixelWidth), uint64(windowSize.PixelHeight)
		}
	}

	return &client.PtySpec{
		Term:        termType,
		Columns:     uint64(columns),
		Rows:        uint64(rows),
		PixelWidth:  pixelWidth,
		PixelHeight: pixelHeight,
	}, nil
}

// runForcedPtySession opens a session channel with a pty and bridges the
// process stdio into it, returning the terminal event of the session.
func runForcedPtySession(ctx context.Context, c *client.Client, tty *os.File, forwardSSHAgent bool, command ...string) error {
	ptySpec, err := newForcedPtySpec(tty)
	if err != nil {
		return err
	}
	channel, ptyRequested, err := c.OpenSession(ctx, client.SessionSpec{
		Command:      command,
		Pty:          ptySpec,
		ForwardAgent: forwardSSHAgent,
	})
	if err != nil {
		if channel == nil {
			return fmt.Errorf("could not open channel: %w", err)
		}
		return err
	}

	// The console is only put in raw mode when there is one: with a pipe on
	// stdin the remote program owns the terminal side, and touching the local
	// console would corrupt the caller's output.
	if tty != nil && term.IsTerminal(int(tty.Fd())) {
		if oldState, err := term.MakeRaw(int(os.Stdin.Fd())); err != nil {
			log.Warn().Msgf("cannot make tty raw: %s", err)
		} else {
			defer term.Restore(int(os.Stdin.Fd()), oldState)
		}
	}
	if ptyRequested {
		// a trailing carriage return restores the prompt position of an
		// interactive session once the remote program is done
		defer fmt.Printf("\r")
	}
	go forwardForcedPtySignals(ctx, channel)
	go forwardForcedPtyWindowChanges(ctx, channel, tty)

	err = c.PumpSession(channel, os.Stdin, os.Stdout, os.Stderr, ptyRequested)
	switch err.(type) {
	case nil, client.ExitStatus, client.ExitSignal:
		return err
	default:
		return fmt.Errorf("could not get message: %w", err)
	}
}

// forwardForcedPtySignals propagates the local terminal signals to the remote
// pty: without it Ctrl-C would be handled by the local shell and never reach
// the remote program.
func forwardForcedPtySignals(ctx context.Context, channel ssh3.Channel) {
	signals := make(chan os.Signal, len(forwardedPtySignals))
	notifiedSignals := make([]os.Signal, 0, len(forwardedPtySignals))
	for signal := range forwardedPtySignals {
		notifiedSignals = append(notifiedSignals, signal)
	}
	signal.Notify(signals, notifiedSignals...)
	defer signal.Stop(signals)

	for {
		select {
		case <-ctx.Done():
			return
		case receivedSignal := <-signals:
			signalName, ok := forwardedPtySignals[receivedSignal.(syscall.Signal)]
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
