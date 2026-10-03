package client

// Reverse port forwarding (-R): the client asks the server, over a
// "reverse-forward" control channel, to bind a listener on its side; every
// connection or datagram the server accepts there is mirrored back as a
// server-initiated "forwarded-tcp"/"forwarded-udp" channel whose additional
// header bytes carry the local target. This file performs the request and
// bridges the incoming channels to that target.
//
// The request and its reply travel as channel data, not as new message-type
// ids: an older server treats the control channel as an unknown session
// channel, rejects the unexpected data in its LARVAL state and closes the
// channel, which surfaces here as a graceful "unsupported by server" error.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

// ReverseForward describes one parsed -R specification: bind a listener on
// the server and bridge every accepted connection/datagram to the local
// target host:port. BindHost is "", "*", "localhost" or an IP literal (""
// lets the server pick its loopback default; "*" requests a wildcard bind,
// which the server allows but warns about). Protocol selects TCP or UDP.
type ReverseForward struct {
	BindHost   string
	BindPort   uint16
	TargetHost string
	TargetPort uint16
	Protocol   util.SSHForwardingProtocol

	// resolvedTarget is filled in by SetReverseForwards (client-side
	// resolution, like OpenSSH resolving the -R target locally).
	resolvedTarget net.Addr
}

// SpecString renders the forward back into its -R form, for logs.
func (f ReverseForward) SpecString() string {
	protoSuffix := ""
	if f.Protocol == util.SSHProtocolUDP {
		protoSuffix = "/udp"
	}
	bindPrefix := ""
	if f.BindHost != "" {
		bindPrefix = f.BindHost + ":"
	}
	return fmt.Sprintf("%s%d%s:%s:%d", bindPrefix, f.BindPort, protoSuffix, f.TargetHost, f.TargetPort)
}

// resolveTarget resolves TargetHost:TargetPort locally, like OpenSSH resolves
// the -R target on the machine where the client runs.
func (f *ReverseForward) resolveTarget() error {
	if f.TargetHost == "" {
		return fmt.Errorf("empty reverse forwarding target host")
	}
	port := strconv.Itoa(int(f.TargetPort))
	switch f.Protocol {
	case util.SSHForwardingProtocolTCP:
		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(f.TargetHost, port))
		if err != nil {
			return err
		}
		f.resolvedTarget = addr
	case util.SSHProtocolUDP:
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(f.TargetHost, port))
		if err != nil {
			return err
		}
		f.resolvedTarget = addr
	default:
		return fmt.Errorf("invalid reverse forwarding protocol %d", f.Protocol)
	}
	return nil
}

// SetReverseForwards registers the -R forwards (already parsed from the CLI).
// Targets are resolved here so a bad target fails before anything is sent to
// the server. Must be called before the first session or StartAcceptLoop.
func (c *Client) SetReverseForwards(forwards []ReverseForward) error {
	resolved := make([]ReverseForward, len(forwards))
	for i, forward := range forwards {
		resolved[i] = forward
		if err := resolved[i].resolveTarget(); err != nil {
			return fmt.Errorf("could not resolve target of -R %s: %s", forward.SpecString(), err)
		}
	}
	c.reverseForwards = resolved
	return nil
}

// StartAcceptLoop starts the dispatch loop for server-initiated channels
// (reverse-forwarding bridges and, when agent forwarding was requested,
// agent connections). Only needed without a session (ssh3 -N -R ...); a
// session starts it implicitly. Idempotent.
func (c *Client) StartAcceptLoop() { c.startAcceptLoop() }

func (c *Client) startAcceptLoop() {
	c.acceptOnce.Do(func() {
		go c.acceptLoop(c.Context())
	})
}

// RequestReverseForward sends one -R request on its own control channel and
// waits for the server's bind result. The returned error carries the server's
// reason (port busy, permission denied) or "unsupported" when the peer closed
// the channel without replying (an older server).
func (c *Client) RequestReverseForward(forward ReverseForward) error {
	if forward.resolvedTarget == nil {
		if err := forward.resolveTarget(); err != nil {
			return err
		}
	}
	channel, err := c.OpenChannel(ssh3Messages.ChannelTypeReverseForward, 30000, 0)
	if err != nil {
		return fmt.Errorf("could not open the reverse-forwarding control channel: %s", err)
	}
	defer channel.Close()

	var bindPort, targetPort uint16
	var targetAddress string
	switch addr := forward.resolvedTarget.(type) {
	case *net.TCPAddr:
		targetAddress, targetPort = addr.IP.String(), uint16(addr.Port)
	case *net.UDPAddr:
		targetAddress, targetPort = addr.IP.String(), uint16(addr.Port)
	default:
		return fmt.Errorf("unresolved reverse forwarding target %v", forward.resolvedTarget)
	}
	bindPort = forward.BindPort

	request := &ssh3Messages.RequestReverseForward{
		Protocol:      forward.Protocol,
		BindAddress:   forward.BindHost,
		BindPort:      bindPort,
		TargetAddress: targetAddress,
		TargetPort:    targetPort,
	}
	buf := make([]byte, request.Length())
	if _, err := request.Write(buf); err != nil {
		return err
	}
	if _, err := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_NONE); err != nil {
		return fmt.Errorf("could not send the reverse-forwarding request: %s", err)
	}

	replyMessage, err := channel.NextMessage()
	if err != nil {
		if errors.Is(err, io.EOF) {
			// the peer closed the request channel without replying: an older
			// server rejects the unknown channel data this way
			return fmt.Errorf("the server does not support reverse forwarding (it closed the request channel without a reply); a newer ssh3-server is required")
		}
		return fmt.Errorf("error while waiting for the reverse-forwarding reply: %s", err)
	}
	dataMessage, ok := replyMessage.(*ssh3Messages.DataOrExtendedDataMessage)
	if !ok || dataMessage.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
		return fmt.Errorf("unexpected reply of type %T on the reverse-forwarding channel", replyMessage)
	}
	reply, err := ssh3Messages.ParseReverseForwardReply(&util.BytesReadCloser{Reader: bytes.NewReader([]byte(dataMessage.Data))})
	if err != nil {
		return fmt.Errorf("could not parse the reverse-forwarding reply: %s", err)
	}
	if !reply.Success() {
		return fmt.Errorf("the server refused the reverse forwarding: %s", reply.ErrorUTF8)
	}
	if reply.BoundPort != forward.BindPort {
		log.Info().Msgf("server bound -R %s on ephemeral port %d", forward.SpecString(), reply.BoundPort)
	} else {
		log.Info().Msgf("server bound -R %s", forward.SpecString())
	}
	return nil
}

// acceptLoop dispatches every server-initiated channel of the conversation:
// reverse-forwarding channels are bridged to the local targets, agent
// connections go to the agent forwarder when agent forwarding is active, and
// anything else is rejected (and no longer kills the whole loop, unlike the
// historical agent-only accept loop).
func (c *Client) acceptLoop(ctx context.Context) {
	for {
		channel, err := c.AcceptChannel(ctx)
		if err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				log.Error().Msgf("could not accept server-initiated channel: %s", err)
			}
			return
		}
		switch accepted := channel.(type) {
		case *ssh3.TCPForwardingChannelImpl:
			if channel.ChannelType() != ssh3Messages.ChannelTypeForwardedTCP ||
				!c.authorizeForwardedTarget(util.SSHForwardingProtocolTCP, accepted.RemoteAddr) {
				log.Error().Msgf("rejecting unexpected server-initiated channel %d of type %s towards %s",
					channel.ChannelID(), channel.ChannelType(), accepted.RemoteAddr)
				channel.Close()
				continue
			}
			go c.bridgeForwardedTCP(ctx, accepted)
		case *ssh3.UDPForwardingChannelImpl:
			if channel.ChannelType() != ssh3Messages.ChannelTypeForwardedUDP ||
				!c.authorizeForwardedTarget(util.SSHProtocolUDP, accepted.RemoteAddr) {
				log.Error().Msgf("rejecting unexpected server-initiated channel %d of type %s towards %s",
					channel.ChannelID(), channel.ChannelType(), accepted.RemoteAddr)
				channel.Close()
				continue
			}
			go bridgeForwardedUDP(ctx, accepted)
		default:
			if channel.ChannelType() == "agent-connection" && c.forwardAgent.Load() {
				log.Debug().Msg("new agent connection, forwarding")
				go func() {
					if err := forwardAgent(ctx, channel); err != nil {
						log.Error().Msgf("agent forwarding error: %s", err.Error())
						c.Close()
					}
				}()
			} else {
				log.Error().Msgf("rejecting unexpected server-initiated channel %d of type %s",
					channel.ChannelID(), channel.ChannelType())
				channel.Close()
			}
		}
	}
}

// authorizeForwardedTarget only bridges forwarded-* channels whose target was
// actually requested with -R: a compromised or buggy server must not be able
// to make the client connect to arbitrary local endpoints.
func (c *Client) authorizeForwardedTarget(protocol util.SSHForwardingProtocol, target net.Addr) bool {
	for _, forward := range c.reverseForwards {
		if forward.Protocol == protocol && forward.resolvedTarget.String() == target.String() {
			return true
		}
	}
	return false
}

// bridgeForwardedTCP connects the channel to the local TCP target and relays
// in both directions until either side closes.
func (c *Client) bridgeForwardedTCP(ctx context.Context, channel *ssh3.TCPForwardingChannelImpl) {
	conn, err := net.DialTCP("tcp", nil, channel.RemoteAddr)
	if err != nil {
		log.Error().Msgf("could not connect to the local -R target %s: %s", channel.RemoteAddr, err)
		channel.Close()
		return
	}
	log.Debug().Msgf("bridging forwarded-tcp channel %d to %s", channel.ChannelID(), channel.RemoteAddr)
	forwardTCPInBackground(ctx, channel, conn)
}

// bridgeForwardedUDP connects the channel to the local UDP target and relays
// datagrams in both directions until either side closes.
func bridgeForwardedUDP(ctx context.Context, channel *ssh3.UDPForwardingChannelImpl) {
	conn, err := net.DialUDP("udp", nil, channel.RemoteAddr)
	if err != nil {
		log.Error().Msgf("could not connect to the local -R target %s: %s", channel.RemoteAddr, err)
		channel.Close()
		return
	}
	log.Debug().Msgf("bridging forwarded-udp channel %d to %s", channel.ChannelID(), channel.RemoteAddr)

	// either pump tearing the bridge down unblocks the other one: conn.Close
	// fails the pending Read/Write, cancel unblocks ReceiveDatagram
	bridgeCtx, cancel := context.WithCancelCause(ctx)
	stop := func(cause error) {
		cancel(cause)
		conn.Close()
		channel.Close()
	}

	go func() {
		defer cancel(nil)
		for {
			datagram, err := channel.ReceiveDatagram(bridgeCtx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Debug().Msgf("forwarded-udp channel %d closed: %s", channel.ChannelID(), err)
				}
				stop(nil)
				return
			}
			if _, err := conn.Write(datagram); err != nil {
				log.Debug().Msgf("could not write datagram to the local -R target %s: %s", channel.RemoteAddr, err)
				stop(err)
				return
			}
		}
	}()

	go func() {
		defer cancel(nil)
		buf := make([]byte, 1500)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				log.Debug().Msgf("local -R target socket %s closed: %s", channel.RemoteAddr, err)
				stop(nil)
				return
			}
			if err := channel.SendDatagram(buf[:n]); err != nil {
				log.Debug().Msgf("could not send datagram on forwarded-udp channel %d: %s", channel.ChannelID(), err)
				stop(err)
				return
			}
		}
	}()
}
