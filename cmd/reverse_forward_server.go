//go:build !windows

package cmd

// Server side of reverse port forwarding (-R): each client "reverse-forward"
// control channel carries one bind request as channel data; on success the
// server serves the bound listener and mirrors every accepted connection or
// datagram back to the client as a "forwarded-tcp"/"forwarded-udp" channel
// whose additional header bytes carry the client-side target.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	ssh3 "github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
	"github.com/rs/zerolog/log"
)

// maxForwardedChannelsPerConversation bounds the number of simultaneously
// open forwarded-* channels one conversation may consume (DoS guard).
const maxForwardedChannelsPerConversation = 64

// reverseForwardState holds the per-conversation reverse forwarding state.
type reverseForwardState struct {
	conv *ssh3.Conversation
	// openChannels counts the currently open forwarded-* channels
	openChannels atomic.Int64
}

// reverseForwardStates maps a conversation to its reverse forwarding state,
// created lazily on the first -R request. The entry is dropped when the
// conversation ends; releasing the binds is handled by the per-bind watchers.
var (
	reverseForwardStatesMu sync.Mutex
	reverseForwardStates   = make(map[*ssh3.Conversation]*reverseForwardState)
)

func getReverseForwardState(conv *ssh3.Conversation) *reverseForwardState {
	reverseForwardStatesMu.Lock()
	defer reverseForwardStatesMu.Unlock()
	if state, ok := reverseForwardStates[conv]; ok {
		return state
	}
	state := &reverseForwardState{conv: conv}
	reverseForwardStates[conv] = state
	go func() {
		<-conv.Context().Done()
		reverseForwardStatesMu.Lock()
		delete(reverseForwardStates, conv)
		reverseForwardStatesMu.Unlock()
	}()
	return state
}

// handleReverseForwardChannel serves one client "reverse-forward" control
// channel: it reads the bind request, replies with the bind result, then
// serves the bound listener until the conversation ends. Runs on its own
// goroutine so the channel accept loop stays responsive.
func handleReverseForwardChannel(conv *ssh3.Conversation, channel ssh3.Channel) {
	defer channel.Close()
	state := getReverseForwardState(conv)

	request, err := readReverseForwardRequest(channel)
	if err != nil {
		log.Error().Msgf("invalid reverse-forwarding request on channel %d: %s", channel.ChannelID(), err)
		return
	}
	log.Debug().Msgf("reverse-forwarding request on channel %d: proto=%d bind=%s:%d target=%s:%d",
		channel.ChannelID(), request.Protocol, request.BindAddress, request.BindPort, request.TargetAddress, request.TargetPort)

	bindAddress := request.BindAddress
	if bindAddress == "" {
		// loopback-only default, like OpenSSH binding localhost when no
		// bind_address is given
		bindAddress = "127.0.0.1"
	}
	targetIP := net.ParseIP(request.TargetAddress)
	if targetIP == nil {
		// the client resolves the target locally; only literals are accepted
		writeReverseForwardReply(channel, &ssh3Messages.ReverseForwardReply{
			ErrorUTF8: fmt.Sprintf("invalid target address %q", request.TargetAddress),
		})
		return
	}

	bindPortString := strconv.Itoa(int(request.BindPort))
	var listener io.Closer
	var boundPort uint16
	switch request.Protocol {
	case util.SSHForwardingProtocolTCP:
		address, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(bindAddress, bindPortString))
		if err != nil {
			writeReverseForwardReply(channel, &ssh3Messages.ReverseForwardReply{ErrorUTF8: err.Error()})
			return
		}
		warnOnWideReverseBind(address.IP)
		tcpListener, err := net.ListenTCP("tcp", address)
		if err != nil {
			writeReverseForwardReply(channel, &ssh3Messages.ReverseForwardReply{ErrorUTF8: err.Error()})
			return
		}
		listener = tcpListener
		boundPort = uint16(tcpListener.Addr().(*net.TCPAddr).Port)
		target := &net.TCPAddr{IP: targetIP, Port: int(request.TargetPort)}
		go watchConversationEnd(conv, listener)
		go serveReverseTCP(conv.Context(), state, tcpListener, target)
		log.Info().Msgf("reverse forwarding TCP %s towards client target %s (control channel %d)",
			tcpListener.Addr(), target, channel.ChannelID())
	case util.SSHProtocolUDP:
		address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bindAddress, bindPortString))
		if err != nil {
			writeReverseForwardReply(channel, &ssh3Messages.ReverseForwardReply{ErrorUTF8: err.Error()})
			return
		}
		warnOnWideReverseBind(address.IP)
		udpConn, err := net.ListenUDP("udp", address)
		if err != nil {
			writeReverseForwardReply(channel, &ssh3Messages.ReverseForwardReply{ErrorUTF8: err.Error()})
			return
		}
		listener = udpConn
		boundPort = uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
		target := &net.UDPAddr{IP: targetIP, Port: int(request.TargetPort)}
		go watchConversationEnd(conv, listener)
		go serveReverseUDP(conv.Context(), state, udpConn, target)
		log.Info().Msgf("reverse forwarding UDP %s towards client target %s (control channel %d)",
			udpConn.LocalAddr(), target, channel.ChannelID())
	default:
		writeReverseForwardReply(channel, &ssh3Messages.ReverseForwardReply{
			ErrorUTF8: fmt.Sprintf("unsupported forwarding protocol %d", request.Protocol),
		})
		return
	}

	if err := writeReverseForwardReply(channel, &ssh3Messages.ReverseForwardReply{BoundPort: boundPort}); err != nil {
		log.Error().Msgf("could not send the reverse-forwarding reply on channel %d: %s", channel.ChannelID(), err)
		return
	}
	// the reply was written; wait for the conversation to end before closing
	// the control channel, so its lifetime mirrors the forward's
	<-conv.Context().Done()
}

// readReverseForwardRequest waits for the client's bind request on the
// control channel. A closed channel (no data) means the peer went away.
func readReverseForwardRequest(channel ssh3.Channel) (*ssh3Messages.RequestReverseForward, error) {
	genericMessage, err := channel.NextMessage()
	if err != nil {
		return nil, err
	}
	dataMessage, ok := genericMessage.(*ssh3Messages.DataOrExtendedDataMessage)
	if !ok || dataMessage.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
		return nil, fmt.Errorf("unexpected message of type %T", genericMessage)
	}
	return ssh3Messages.ParseRequestReverseForward(&util.BytesReadCloser{Reader: bytes.NewReader([]byte(dataMessage.Data))})
}

func writeReverseForwardReply(channel ssh3.Channel, reply *ssh3Messages.ReverseForwardReply) error {
	buf := make([]byte, reply.Length())
	if _, err := reply.Write(buf); err != nil {
		return err
	}
	_, err := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	return err
}

// warnOnWideReverseBind logs a warning when a -R bind is not restricted to
// the loopback interfaces (parity with OpenSSH GatewayPorts visibility).
func warnOnWideReverseBind(ip net.IP) {
	if !ip.IsLoopback() {
		log.Warn().Msgf("reverse forwarding binds a non-loopback address (%s): the port is reachable from other hosts", ip)
	}
}

// watchConversationEnd closes the bound listener when the conversation ends,
// releasing the bind. The control channel itself is closed by the handler's
// defer once it observes the same context.
func watchConversationEnd(conv *ssh3.Conversation, listener io.Closer) {
	<-conv.Context().Done()
	listener.Close()
}

// serveReverseTCP accepts connections on the bound listener and mirrors each
// one to the client as a forwarded-tcp channel bridged to the local target.
func serveReverseTCP(ctx context.Context, state *reverseForwardState, listener *net.TCPListener, target *net.TCPAddr) {
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			// the listener was closed (conversation over)
			if !errors.Is(err, net.ErrClosed) {
				log.Error().Msgf("error while accepting on reverse-forwarded TCP listener %s: %s", listener.Addr(), err)
			}
			return
		}
		if state.openChannels.Load() >= maxForwardedChannelsPerConversation {
			log.Warn().Msgf("too many open forwarded channels (%d), dropping connection on %s",
				state.openChannels.Load(), listener.Addr())
			conn.Close()
			continue
		}
		channel, err := state.conv.OpenForwardedTCPChannel(30000, 10, target)
		if err != nil {
			log.Error().Msgf("could not open forwarded-tcp channel for connection on %s: %s", listener.Addr(), err)
			conn.Close()
			continue
		}
		state.openChannels.Add(1)
		go func() {
			defer state.openChannels.Add(-1)
			forwardTCPInBackground(ctx, channel, conn)
		}()
	}
}

// serveReverseUDP reads datagrams on the bound socket and mirrors them to the
// client as forwarded-udp channels, one per remote peer (like the existing
// client-side UDP forwarding), each bridged to the local target.
func serveReverseUDP(ctx context.Context, state *reverseForwardState, conn *net.UDPConn, target *net.UDPAddr) {
	channels := make(map[string]ssh3.Channel)
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			// the socket was closed (conversation over)
			if !errors.Is(err, net.ErrClosed) {
				log.Error().Msgf("error while reading on reverse-forwarded UDP socket %s: %s", conn.LocalAddr(), err)
			}
			return
		}
		key := from.String()
		channel, ok := channels[key]
		if !ok {
			if state.openChannels.Load() >= maxForwardedChannelsPerConversation {
				log.Warn().Msgf("too many open forwarded channels (%d), dropping datagram from %s",
					state.openChannels.Load(), from)
				continue
			}
			channel, err = state.conv.OpenForwardedUDPChannel(30000, 10, target)
			if err != nil {
				log.Error().Msgf("could not open forwarded-udp channel for peer %s: %s", from, err)
				continue
			}
			state.openChannels.Add(1)
			channels[key] = channel
			go func(from *net.UDPAddr, channel ssh3.Channel) {
				defer state.openChannels.Add(-1)
				defer delete(channels, from.String())
				for {
					datagram, err := channel.ReceiveDatagram(ctx)
					if err != nil {
						return
					}
					if _, err := conn.WriteToUDP(datagram, from); err != nil {
						log.Debug().Msgf("could not write datagram back to %s: %s", from, err)
						return
					}
				}
			}(from, channel)
		}
		if err := channel.SendDatagram(buf[:n]); err != nil {
			log.Error().Msgf("could not send datagram on forwarded-udp channel: %s", err)
		}
	}
}
