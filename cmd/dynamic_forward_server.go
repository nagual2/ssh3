//go:build !windows

package cmd

// Server side of dynamic SOCKS forwarding (-D): the client opens one
// "dynamic-forward" control channel carrying a bind announcement as channel
// data; every connection its SOCKS listener accepts is then mirrored to the
// server as a client-initiated "dynamic-forward-tcp" channel carrying the
// target address as channel data. The server dials that target itself and
// bridges the channel with the TCP connection.

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

// maxDynamicForwardChannelsPerConversation bounds the number of simultaneously
// open dynamic-forward-tcp channels one conversation may consume (DoS guard).
const maxDynamicForwardChannelsPerConversation = 64

// dynamicForwardState holds the per-conversation dynamic forwarding state. A
// nil *dynamicForwardState means "no dynamic forward was requested on this
// conversation" and makes the server refuse the data channels.
type dynamicForwardState struct {
	// openConns counts the currently bridged TCP connections
	openCount atomic.Int64
	// conns is the set of currently bridged TCP connections; a release (the
	// control channel or the conversation went away) closes them all
	conns sync.Map
}

// trackConn registers a freshly dialed connection so that a release closes it,
// and returns the function unregistering it once the bridge is over. It
// refuses to track more than maxDynamicForwardChannelsPerConversation
// connections at once (DoS guard).
func (s *dynamicForwardState) trackConn(conn *net.TCPConn) (release func(), err error) {
	if s == nil {
		return nil, errors.New("no dynamic forwarding session")
	}
	if s.openCount.Load() >= maxDynamicForwardChannelsPerConversation {
		return nil, fmt.Errorf("too many open dynamic forwarding connections (%d)", s.openCount.Load())
	}
	s.conns.Store(conn, struct{}{})
	s.openCount.Add(1)
	var once sync.Once
	return func() {
		once.Do(func() {
			s.conns.Delete(conn)
			s.openCount.Add(-1)
		})
	}, nil
}

// openConns returns the number of currently bridged TCP connections.
func (s *dynamicForwardState) openConns() int64 {
	if s == nil {
		return 0
	}
	return s.openCount.Load()
}

// releaseConns closes every bridged TCP connection: the bridges die with the
// dynamic forwarding session.
func (s *dynamicForwardState) releaseConns() {
	if s == nil {
		return
	}
	s.conns.Range(func(key, _ any) bool {
		if conn, ok := key.(*net.TCPConn); ok {
			conn.Close()
		}
		return true
	})
}

// dynamicForwardStates maps a conversation to its dynamic forwarding state,
// created lazily on the first -D control channel. The entry is dropped when
// the conversation ends.
var (
	dynamicForwardStatesMu sync.Mutex
	dynamicForwardStates   = make(map[*ssh3.Conversation]*dynamicForwardState)
)

func getDynamicForwardState(conv *ssh3.Conversation) *dynamicForwardState {
	dynamicForwardStatesMu.Lock()
	defer dynamicForwardStatesMu.Unlock()
	if state, ok := dynamicForwardStates[conv]; ok {
		return state
	}
	state := &dynamicForwardState{}
	dynamicForwardStates[conv] = state
	go func() {
		<-conv.Context().Done()
		dynamicForwardStatesMu.Lock()
		delete(dynamicForwardStates, conv)
		dynamicForwardStatesMu.Unlock()
		state.releaseConns()
	}()
	return state
}

// getActiveDynamicForwardState returns the dynamic forwarding state of the
// conversation, or nil when no dynamic forward is currently requested on it.
func getActiveDynamicForwardState(conv *ssh3.Conversation) *dynamicForwardState {
	dynamicForwardStatesMu.Lock()
	defer dynamicForwardStatesMu.Unlock()
	return dynamicForwardStates[conv]
}

// handleDynamicForwardChannel serves one client "dynamic-forward" control
// channel: it reads the request, replies with the acknowledgement (or a
// readable error), then keeps the dynamic forwarding session alive until the
// client closes the channel or the conversation ends. Runs on its own
// goroutine so the channel accept loop stays responsive.
func handleDynamicForwardChannel(conv *ssh3.Conversation, channel ssh3.Channel) {
	defer channel.Close()
	state := getDynamicForwardState(conv)

	request, err := readDynamicForwardRequest(channel)
	if err != nil {
		log.Error().Msgf("invalid dynamic forwarding request on channel %d: %s", channel.ChannelID(), err)
		return
	}
	bindAddress := dynamicForwardBindAddress(request.BindAddress)
	if !isLoopbackBind(bindAddress) {
		log.Warn().Msgf("dynamic forwarding announced for a non-loopback client bind (%s:%d): "+
			"the SOCKS listener is reachable from other hosts", bindAddress, request.BindPort)
	}
	// the server never binds anything for a dynamic forward: it only confirms
	// that it will serve the client's SOCKS listener
	if err := writeDynamicForwardReply(channel, &ssh3Messages.DynamicForwardReply{BoundPort: request.BindPort}); err != nil {
		log.Error().Msgf("could not send the dynamic forwarding reply on channel %d: %s", channel.ChannelID(), err)
		return
	}
	log.Info().Msgf("dynamic forwarding (-D) enabled for client bind %s:%d (control channel %d)",
		bindAddress, request.BindPort, channel.ChannelID())

	// the control channel's lifetime is the dynamic forwarding session: when the
	// client closes it (or the conversation dies), every bridged connection is
	// released
	defer state.releaseConns()
	waitForDynamicForwardControlChannel(conv, channel)
}

// dynamicForwardBindAddress normalizes the client-announced bind address.
func dynamicForwardBindAddress(bindAddress string) string {
	switch bindAddress {
	case "":
		// loopback-only default, like OpenSSH binding localhost when no
		// bind_address is given
		return "127.0.0.1"
	case "*":
		return "0.0.0.0"
	default:
		return bindAddress
	}
}

func isLoopbackBind(bindAddress string) bool {
	if ip := net.ParseIP(bindAddress); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// waitForDynamicForwardControlChannel blocks until the client closes the
// dynamic-forward control channel or the conversation ends.
func waitForDynamicForwardControlChannel(conv *ssh3.Conversation, channel ssh3.Channel) {
	ctx := conv.Context()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		genericMessage, err := channel.NextMessage()
		if genericMessage == nil || err != nil {
			if err != nil && !errors.Is(err, io.EOF) {
				log.Debug().Msgf("dynamic forwarding control channel %d closed: %s", channel.ChannelID(), err)
			}
			return
		}
		// the client is not supposed to send anything else on that channel
		if dataMessage, ok := genericMessage.(*ssh3Messages.DataOrExtendedDataMessage); ok && len(dataMessage.Data) > 0 {
			log.Warn().Msgf("ignoring %d unexpected data bytes on the dynamic forwarding control channel %d",
				len(dataMessage.Data), channel.ChannelID())
		}
	}
}

// readDynamicForwardRequest waits for the client's request on the control
// channel. A closed channel (no data) means the peer went away.
func readDynamicForwardRequest(channel ssh3.Channel) (*ssh3Messages.RequestDynamicForward, error) {
	genericMessage, err := channel.NextMessage()
	if err != nil {
		return nil, err
	}
	return parseDynamicForwardChannelData(genericMessage, ssh3Messages.ParseRequestDynamicForward)
}

// writeDynamicForwardReply sends the control-channel acknowledgement.
func writeDynamicForwardReply(channel ssh3.Channel, reply *ssh3Messages.DynamicForwardReply) error {
	buf := make([]byte, reply.Length())
	if _, err := reply.Write(buf); err != nil {
		return err
	}
	_, err := channel.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	return err
}

// writeDynamicForwardTargetReply sends the per-connection acknowledgement.
func writeDynamicForwardTargetReply(stream dynamicForwardStream, reply *ssh3Messages.DynamicForwardTargetReply) error {
	buf := make([]byte, reply.Length())
	if _, err := reply.Write(buf); err != nil {
		return err
	}
	_, err := stream.WriteData(buf, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	return err
}

// dynamicForwardStream is the slice of ssh3.Channel the dynamic forwarding
// bridging needs. ssh3.Channel satisfies it; declaring it separately keeps the
// data plane testable without a QUIC session.
type dynamicForwardStream interface {
	ChannelID() util.ChannelID
	NextMessage() (ssh3Messages.Message, error)
	WriteData(dataBuf []byte, dataType ssh3Messages.SSHDataType) (int, error)
	CancelRead()
	Close()
	MaxPacketSize() uint64
}

// parseDynamicForwardChannelData extracts the first data message of a channel
// and decodes the dynamic forwarding payload it carries.
func parseDynamicForwardChannelData[T any](genericMessage ssh3Messages.Message, parse func(util.Reader) (*T, error)) (*T, error) {
	dataMessage, ok := genericMessage.(*ssh3Messages.DataOrExtendedDataMessage)
	if !ok || dataMessage.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
		return nil, fmt.Errorf("unexpected message of type %T", genericMessage)
	}
	return parse(&util.BytesReadCloser{Reader: bytes.NewReader([]byte(dataMessage.Data))})
}

// readDynamicForwardTarget waits for the target address on a
// "dynamic-forward-tcp" channel.
func readDynamicForwardTarget(stream dynamicForwardStream) (*ssh3Messages.DynamicForwardTarget, error) {
	genericMessage, err := stream.NextMessage()
	if err != nil {
		return nil, err
	}
	return parseDynamicForwardChannelData(genericMessage, ssh3Messages.ParseDynamicForwardTarget)
}

// dialDynamicForwardTarget resolves and dials the target requested on a
// "dynamic-forward-tcp" channel. Unlike the reverse forwarding (-R) targets,
// the address may be a hostname: a SOCKS client only knows a name.
func dialDynamicForwardTarget(target *ssh3Messages.DynamicForwardTarget) (*net.TCPConn, error) {
	address, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(target.Address, strconv.Itoa(int(target.Port))))
	if err != nil {
		return nil, fmt.Errorf("could not resolve %q: %w", target.Address, err)
	}
	conn, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// serveDynamicForwardDataChannel serves one client "dynamic-forward-tcp"
// channel: it reads the target, dials it and bridges the channel with the TCP
// connection. A nil state means no dynamic forwarding session is active on the
// conversation, which is refused with a readable reason.
func serveDynamicForwardDataChannel(ctx context.Context, state *dynamicForwardState, stream dynamicForwardStream) {
	target, err := readDynamicForwardTarget(stream)
	if err != nil {
		log.Error().Msgf("invalid dynamic forwarding target on channel %d: %s", stream.ChannelID(), err)
		stream.Close()
		return
	}
	if state == nil {
		log.Warn().Msgf("refusing dynamic forwarding target %s:%d on channel %d: no dynamic forwarding session",
			target.Address, target.Port, stream.ChannelID())
		writeDynamicForwardTargetReply(stream, &ssh3Messages.DynamicForwardTargetReply{
			ErrorUTF8: "no dynamic forwarding session on this connection",
		})
		stream.Close()
		return
	}
	conn, err := dialDynamicForwardTarget(target)
	if err != nil {
		log.Error().Msgf("could not dial the dynamic forwarding target %s:%d on channel %d: %s",
			target.Address, target.Port, stream.ChannelID(), err)
		writeDynamicForwardTargetReply(stream, &ssh3Messages.DynamicForwardTargetReply{ErrorUTF8: err.Error()})
		stream.Close()
		return
	}
	release, err := state.trackConn(conn)
	if err != nil {
		log.Warn().Msgf("not bridging dynamic forwarding target %s:%d on channel %d: %s",
			target.Address, target.Port, stream.ChannelID(), err)
		writeDynamicForwardTargetReply(stream, &ssh3Messages.DynamicForwardTargetReply{ErrorUTF8: err.Error()})
		conn.Close()
		stream.Close()
		return
	}
	defer release()
	defer conn.Close()

	if err := writeDynamicForwardTargetReply(stream, &ssh3Messages.DynamicForwardTargetReply{}); err != nil {
		log.Error().Msgf("could not acknowledge the dynamic forwarding target %s:%d on channel %d: %s",
			target.Address, target.Port, stream.ChannelID(), err)
		stream.Close()
		return
	}
	log.Debug().Msgf("bridging dynamic forwarding channel %d to %s", stream.ChannelID(), conn.RemoteAddr())
	pumpDynamicForwardTCP(ctx, stream, conn)
}

// pumpDynamicForwardTCP copies data between a "dynamic-forward-tcp" channel
// and its TCP connection in both directions until either end is done. It
// returns once both directions are over, so the caller can release the
// connection and close the channel.
func pumpDynamicForwardTCP(ctx context.Context, stream dynamicForwardStream, conn *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// channel -> TCP
	go func() {
		defer wg.Done()
		defer conn.CloseWrite()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			genericMessage, err := stream.NextMessage()
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					log.Debug().Msgf("dynamic forwarding channel %d read ended: %s", stream.ChannelID(), err)
				}
				return
			}
			if genericMessage == nil {
				return
			}
			dataMessage, ok := genericMessage.(*ssh3Messages.DataOrExtendedDataMessage)
			if !ok || dataMessage.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
				log.Warn().Msgf("ignoring message of type %T on dynamic forwarding channel %d", genericMessage, stream.ChannelID())
				continue
			}
			if len(dataMessage.Data) == 0 {
				continue
			}
			if _, err := conn.Write([]byte(dataMessage.Data)); err != nil {
				log.Debug().Msgf("could not write on the dynamic forwarding socket for channel %d: %s", stream.ChannelID(), err)
				stream.CancelRead()
				return
			}
		}
	}()

	// TCP -> channel
	go func() {
		defer wg.Done()
		defer stream.Close()
		defer conn.CloseRead()
		buf := make([]byte, stream.MaxPacketSize())
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := conn.Read(buf)
			if err != nil && !errors.Is(err, io.EOF) {
				if !errors.Is(err, net.ErrClosed) {
					log.Debug().Msgf("could not read on the dynamic forwarding socket for channel %d: %s", stream.ChannelID(), err)
				}
				return
			}
			if n == 0 {
				return
			}
			if _, err := stream.WriteData(buf[:n], ssh3Messages.SSH_EXTENDED_DATA_NONE); err != nil {
				return
			}
			if errors.Is(err, io.EOF) {
				return
			}
		}
	}()

	wg.Wait()
}
