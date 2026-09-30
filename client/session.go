package client

// Session setup over arbitrary local streams (stage 3.5, increment 1):
// OpenSession issues the wire requests for one session channel, PumpSession
// bridges any reader/writer pair into it. Both are free of console and
// process assumptions so a ControlMaster can serve slave sessions over
// non-process pipes; the CLI keeps the tty/raw-mode/signal concerns.

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

// SessionSpec describes one session channel request. Command is the remote
// command line; empty means a remote shell. Pty, when non-nil, requests a
// remote pty with this geometry before the shell/exec request. ForwardAgent
// requests ssh-agent forwarding on the session channel.
type SessionSpec struct {
	Command      []string
	Pty          *PtySpec
	ForwardAgent bool
}

// PtySpec is the payload of a remote pty request.
type PtySpec struct {
	Term        string
	Columns     uint64
	Rows        uint64
	PixelWidth  uint64
	PixelHeight uint64
}

// OpenSession opens a session channel and issues the pty/shell/exec requests
// described by spec, in that order. It returns the opened channel (non-nil
// even on a post-open error) and whether a pty was requested, for the
// caller's local console handling. When ForwardAgent is set, incoming agent
// channels are served in the background against ctx.
func (c *Client) OpenSession(ctx context.Context, spec SessionSpec) (ssh3.Channel, bool, error) {
	channel, err := c.OpenChannel("session", 30000, 0)
	if err != nil {
		return nil, false, err
	}
	log.Debug().Msgf("opened new session channel")

	if spec.ForwardAgent {
		_, err := channel.WriteData([]byte("forward-agent"), ssh3Messages.SSH_EXTENDED_DATA_NONE)
		if err != nil {
			log.Error().Msgf("could not forward agent: %s", err.Error())
			return channel, false, err
		}
		go func() {
			for {
				forwardChannel, err := c.AcceptChannel(ctx)
				if err != nil {
					if err != context.Canceled {
						log.Error().Msgf("could not accept forwarding channel: %s", err.Error())
					}
					return
				} else if forwardChannel.ChannelType() != "agent-connection" {
					log.Error().Msgf("unexpected server-initiated channel: %s", channel.ChannelType())
					return
				}
				log.Debug().Msg("new agent connection, forwarding")
				go func() {
					err = forwardAgent(ctx, forwardChannel)
					if err != nil {
						log.Error().Msgf("agent forwarding error: %s", err.Error())
						c.Close()
					}
				}()
			}
		}()
	}

	ptyRequested := false
	if spec.Pty != nil {
		err = channel.SendRequest(
			&ssh3Messages.ChannelRequestMessage{
				WantReply: true,
				ChannelRequest: &ssh3Messages.PtyRequest{
					Term:        spec.Pty.Term,
					CharWidth:   spec.Pty.Columns,
					CharHeight:  spec.Pty.Rows,
					PixelWidth:  spec.Pty.PixelWidth,
					PixelHeight: spec.Pty.PixelHeight,
				},
			},
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could send pty request: %+v", err)
			return channel, ptyRequested, err
		}
		ptyRequested = true
		log.Debug().Msgf("sent pty request for session")
	}

	if len(spec.Command) == 0 {
		err = channel.SendRequest(
			&ssh3Messages.ChannelRequestMessage{
				WantReply:      true,
				ChannelRequest: &ssh3Messages.ShellRequest{},
			},
		)
		if err != nil {
			log.Error().Msgf("could not send shell request: %s", err)
			return channel, ptyRequested, err
		}
		log.Debug().Msgf("sent shell request")
	} else {
		// the return value is deliberately ignored: the exec result surfaces
		// through the pump, and the pre-refactor client shipped it this way
		channel.SendRequest(
			&ssh3Messages.ChannelRequestMessage{
				WantReply:      true,
				ChannelRequest: &ssh3Messages.ExecRequest{Command: strings.Join(spec.Command, " ")},
			},
		)
		log.Debug().Msgf("sent exec request for command \"%s\"", strings.Join(spec.Command, " "))
	}
	return channel, ptyRequested, nil
}

// PumpSession bridges local streams to an opened session channel until the
// remote side terminates it. The returned error is the terminal event
// (ExitStatus/ExitSignal) or a transport failure.
func (c *Client) PumpSession(channel ssh3.Channel, stdin io.Reader, stdout, stderr io.Writer, ptyRequested bool) error {
	return pumpSessionStreams(channel, sessionIO{stdin: stdin, stdout: stdout, stderr: stderr}, ptyRequested)
}
