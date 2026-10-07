package cmd

// Dynamic port forwarding (-D): a local SOCKS5 proxy whose connections are
// dialed by the remote peer. This is the client half; the server half lives in
// dynamic_forward_server.go.
//
// One "dynamic-forward" control channel per listener announces the local bind
// and lives as long as the session, and every connection the SOCKS listener
// accepts gets its own "dynamic-forward-tcp" channel carrying the requested
// target. Addresses are forwarded verbatim: a SOCKS client may only know a
// name, and resolving it here would both change the meaning of the request
// (which network resolves it) and leak the name to the local resolver.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

// SOCKS5 protocol constants (RFC 1928). Only the "no authentication required"
// method is implemented: the proxy binds a local listener and forwards
// credentials over the SSH3 connection itself, so it never has to see them.
const (
	socks5Version = 0x05

	socks5MethodNoAuth = 0x00
	socks5MethodGssApi = 0x01

	socks5CommandConnect = 0x01

	socks5AddressIPv4   = 0x01
	socks5AddressDomain = 0x03
	socks5AddressIPv6   = 0x04

	socks5ReplySuccess             = 0x00
	socks5ReplyGeneralFailure      = 0x01
	socks5ReplyNotAllowed          = 0x02
	socks5ReplyNetworkUnreachable  = 0x03
	socks5ReplyHostUnreachable     = 0x04
	socks5ReplyConnectionRefused   = 0x05
	socks5ReplyTTLExpired          = 0x06
	socks5ReplyCommandNotSupported = 0x07
	socks5ReplyAddressNotSupported = 0x08
)

const (
	// socks5MaxRequestLength is the largest SOCKS5 request: 4 header bytes,
	// a 255-byte domain name and its 1 length byte, and the 2 port bytes.
	socks5MaxRequestLength = 4 + 1 + 255 + 2
	// socks5HandshakeTimeout bounds the client prologue. A client that opens
	// a connection and then says nothing must not hold a channel open.
	socks5HandshakeTimeout = 30 * time.Second
)

// socks5Error carries the SOCKS5 reply code that best describes a failure, so
// the client gets a meaningful answer (host unreachable, command unsupported)
// instead of a blanket "general SOCKS server failure".
type socks5Error struct {
	code uint8
	err  error
}

func (e *socks5Error) Error() string { return e.err.Error() }
func (e *socks5Error) Unwrap() error { return e.err }

func socks5Fail(code uint8, format string, args ...interface{}) error {
	return &socks5Error{code: code, err: fmt.Errorf(format, args...)}
}

// socks5ReplyCode maps an error to the reply code to send to the SOCKS client.
func socks5ReplyCode(err error) uint8 {
	var protocolErr *socks5Error
	if errors.As(err, &protocolErr) {
		return protocolErr.code
	}
	return socks5ReplyGeneralFailure
}

// socks5Request is a decoded SOCKS5 CONNECT request. Address holds an IP
// literal for the IPv4/IPv6 address types and the name as sent for the domain
// type; it is never resolved on this side.
type socks5Request struct {
	Version  uint8
	Command  uint8
	Address  string
	Port     uint16
	Consumed int
}

// parseSocks5Request decodes one SOCKS5 request and reports how many bytes it
// used, so a client that already pipelined payload bytes keeps them: the
// tunnel starts right after the request.
func parseSocks5Request(buf []byte) (socks5Request, int, error) {
	request := socks5Request{}
	if len(buf) < 4 {
		return request, 0, socks5Fail(socks5ReplyGeneralFailure, "truncated SOCKS5 request: %d bytes", len(buf))
	}
	if buf[0] != socks5Version {
		return request, 0, socks5Fail(socks5ReplyGeneralFailure, "unsupported SOCKS version 0x%02x", buf[0])
	}
	request.Version = buf[0]
	request.Command = buf[1]
	if buf[2] != 0 {
		return request, 0, socks5Fail(socks5ReplyGeneralFailure, "invalid SOCKS5 reserved byte 0x%02x", buf[2])
	}

	consumed := 4
	var address string
	switch buf[3] {
	case socks5AddressIPv4:
		if len(buf) < consumed+4 {
			return request, 0, socks5Fail(socks5ReplyAddressNotSupported, "truncated SOCKS5 IPv4 address")
		}
		address = net.IP(buf[4:8]).String()
		consumed += 4
	case socks5AddressIPv6:
		if len(buf) < consumed+16 {
			return request, 0, socks5Fail(socks5ReplyAddressNotSupported, "truncated SOCKS5 IPv6 address")
		}
		address = net.IP(buf[4:20]).String()
		consumed += 16
	case socks5AddressDomain:
		if len(buf) < consumed+1 {
			return request, 0, socks5Fail(socks5ReplyAddressNotSupported, "truncated SOCKS5 domain name length")
		}
		nameLength := int(buf[4])
		if nameLength == 0 {
			return request, 0, socks5Fail(socks5ReplyAddressNotSupported, "empty SOCKS5 domain name")
		}
		if len(buf) < consumed+1+nameLength {
			return request, 0, socks5Fail(socks5ReplyAddressNotSupported, "truncated SOCKS5 domain name")
		}
		// the name is forwarded as sent: the server resolves it
		address = string(buf[5 : 5+nameLength])
		consumed += 1 + nameLength
	default:
		return request, 0, socks5Fail(socks5ReplyAddressNotSupported,
			"unsupported SOCKS5 address type 0x%02x", buf[3])
	}

	if len(buf) < consumed+2 {
		return request, 0, socks5Fail(socks5ReplyGeneralFailure, "truncated SOCKS5 port")
	}
	request.Address = address
	request.Port = uint16(buf[consumed])<<8 | uint16(buf[consumed+1])
	request.Consumed = consumed + 2
	if request.Command != socks5CommandConnect {
		return request, 0, socks5Fail(socks5ReplyCommandNotSupported,
			"unsupported SOCKS5 command 0x%02x", request.Command)
	}
	if request.Port == 0 {
		return request, 0, socks5Fail(socks5ReplyHostUnreachable, "invalid SOCKS5 target port 0")
	}
	return request, request.Consumed, nil
}

// readSocks5Request reads exactly one SOCKS5 request from conn into buf, in
// stages, so that the bytes a client sent past the request stay unread and can
// be forwarded as tunnel payload.
func readSocks5Request(conn net.Conn, buf []byte) (int, error) {
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return 0, err
	}
	addressLength := 0
	// payloadStart is where the address (and then the port) continues after
	// the 4-byte header: right after it, except for the domain form whose
	// length byte is consumed first and must not be read twice
	payloadStart := 4
	// total request size: 4 header bytes, then the address (the domain form
	// carries one extra length byte before the name), then the 2 port bytes
	total := 0
	switch buf[3] {
	case socks5AddressIPv4:
		total = 4 + 4 + 2
	case socks5AddressIPv6:
		total = 4 + 16 + 2
	case socks5AddressDomain:
		if _, err := io.ReadFull(conn, buf[4:5]); err != nil {
			return 0, err
		}
		addressLength = int(buf[4])
		payloadStart = 5
		total = 5 + addressLength + 2
	default:
		// the rest of the request (port) is still consumed so the reply can be
		// written and the connection closed cleanly
		return 4, socks5Fail(socks5ReplyAddressNotSupported,
			"unsupported SOCKS5 address type 0x%02x", buf[3])
	}

	if total > len(buf) {
		return 0, socks5Fail(socks5ReplyAddressNotSupported, "oversized SOCKS5 request")
	}
	if _, err := io.ReadFull(conn, buf[payloadStart:total]); err != nil {
		return 0, err
	}
	return total, nil
}

// socks5MethodSelectionReply builds the server's answer to the method
// negotiation.
func socks5MethodSelectionReply(method uint8) []byte {
	return []byte{socks5Version, method}
}

// socks5WriteMethodSelectionReply offers the single method this proxy speaks.
func socks5WriteMethodSelectionReply(w io.Writer, method uint8) error {
	_, err := w.Write(socks5MethodSelectionReply(method))
	return err
}

// socks5ReadMethodSelectionReply reads the chosen method and refuses anything
// but the accepted one: a client that asked for credentials must be told so
// rather than silently downgraded.
func socks5ReadMethodSelectionReply(r io.Reader, accept uint8) error {
	var reply [2]byte
	if _, err := io.ReadFull(r, reply[:]); err != nil {
		return err
	}
	if reply[0] != socks5Version {
		return socks5Fail(socks5ReplyGeneralFailure, "unsupported SOCKS version 0x%02x in method reply", reply[0])
	}
	if reply[1] == 0xff {
		return socks5Fail(socks5ReplyNotAllowed, "no acceptable SOCKS5 authentication method offered")
	}
	if reply[1] != accept {
		return socks5Fail(socks5ReplyNotAllowed,
			"the SOCKS5 proxy selected authentication method 0x%02x, only \"no authentication\" is supported", reply[1])
	}
	return nil
}

// socks5ReadMethodSelection reads the client's method list and checks that "no
// authentication required" is part of it.
func socks5ReadMethodSelection(r io.Reader) error {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return socks5Fail(socks5ReplyGeneralFailure, "unsupported SOCKS version 0x%02x", header[0])
	}
	methodCount := int(header[1])
	if methodCount == 0 {
		return socks5Fail(socks5ReplyGeneralFailure, "empty SOCKS5 method list")
	}
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(r, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == socks5MethodNoAuth {
			return nil
		}
	}
	return socks5Fail(socks5ReplyNotAllowed,
		"the SOCKS5 proxy only supports \"no authentication required\"")
}

// socks5WriteMethodSelection offers the single method this proxy speaks. The
// message is VER | NMETHODS | METHODS, so the method count is part of it.
func socks5WriteMethodSelection(w io.Writer) error {
	_, err := w.Write([]byte{socks5Version, 1, socks5MethodNoAuth})
	return err
}

// socks5SuccessReply builds a success reply. The bound address is always the
// unspecified one: the proxy has no listener of its own to advertise.
func socks5SuccessReply(bound net.Addr) []byte {
	reply := make([]byte, 10)
	reply[0] = socks5Version
	reply[1] = socks5ReplySuccess
	reply[3] = socks5AddressIPv4
	return reply
}

// socks5FailureReply builds a failure reply. The message is logged, never sent:
// a reply with a bound address is variable-length and a client that picked
// ATYP=1 would read past it, desynchronizing the stream.
func socks5FailureReply(code uint8, message string) []byte {
	log.Debug().Msgf("SOCKS5 request failed (reply 0x%02x): %s", code, message)
	reply := make([]byte, 10)
	reply[0] = socks5Version
	reply[1] = code
	reply[3] = socks5AddressIPv4
	return reply
}

// dynamicForwardTargetFromSocks5Request converts a decoded SOCKS5 request into
// the payload the server dials.
func dynamicForwardTargetFromSocks5Request(request socks5Request) (*ssh3Messages.DynamicForwardTarget, error) {
	if request.Address == "" {
		return nil, socks5Fail(socks5ReplyHostUnreachable, "empty SOCKS5 target address")
	}
	if request.Port == 0 {
		return nil, socks5Fail(socks5ReplyHostUnreachable, "invalid SOCKS5 target port 0")
	}
	return &ssh3Messages.DynamicForwardTarget{Address: request.Address, Port: request.Port}, nil
}

// dynamicForwarder serves a local SOCKS5 proxy for one -D specification.
type dynamicForwarder struct {
	conversation   *ssh3.Conversation
	controlChannel ssh3.Channel
	listener       net.Listener
	spec           dynamicForwardSpec

	ctx         context.Context
	cancel      context.CancelFunc
	connections sync.WaitGroup
	closeOnce   sync.Once
}

// startDynamicForward announces the forward to the server, opens the local
// SOCKS listener and starts serving it. The control channel is kept open for
// the whole session: closing it is how the server learns the forward is gone.
func startDynamicForward(ctx context.Context, conversation *ssh3.Conversation, spec dynamicForwardSpec) (*dynamicForwarder, error) {
	controlChannel, err := conversation.OpenChannel(ssh3Messages.ChannelTypeDynamicForward, 30000, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open the dynamic forwarding control channel: %s", err)
	}
	forwarder := &dynamicForwarder{conversation: conversation, controlChannel: controlChannel, spec: spec}

	request := &ssh3Messages.RequestDynamicForward{BindAddress: spec.BindAddress, BindPort: spec.BindPort}
	if err := writeDynamicForwardPayload(controlChannel, request); err != nil {
		controlChannel.Close()
		return nil, fmt.Errorf("could not send the dynamic forwarding request: %s", err)
	}
	reply, err := readDynamicForwardReply(controlChannel)
	if err != nil {
		controlChannel.Close()
		return nil, fmt.Errorf("could not read the dynamic forwarding reply: %s", err)
	}
	if !reply.Success() {
		controlChannel.Close()
		return nil, fmt.Errorf("the server refused the dynamic port forwarding: %s", reply.ErrorUTF8)
	}

	bindPort := strconv.Itoa(int(spec.BindPort))
	listener, err := net.Listen("tcp", net.JoinHostPort(spec.ListenAddress(), bindPort))
	if err != nil {
		controlChannel.Close()
		return nil, fmt.Errorf("could not listen on %s for dynamic port forwarding: %s", spec.SpecString(), err)
	}

	forwarder.listener = listener
	forwarder.ctx, forwarder.cancel = context.WithCancel(ctx)
	go forwarder.acceptLoop()
	log.Info().Msgf("dynamic port forwarding: SOCKS5 proxy listening on %s", listener.Addr())
	return forwarder, nil
}

// ListenAddr returns the address the local SOCKS proxy actually listens on,
// which is the resolved one when the specification asked for port 0.
func (f *dynamicForwarder) ListenAddr() net.Addr {
	if f.listener == nil {
		return nil
	}
	return f.listener.Addr()
}

// Close stops the proxy: the listener is closed, the running connections are
// released and the control channel goes away, which retires the forward on the
// server too. It is safe to call more than once.
func (f *dynamicForwarder) Close() {
	f.closeOnce.Do(func() {
		if f.cancel != nil {
			f.cancel()
		}
		if f.listener != nil {
			f.listener.Close()
		}
		if f.controlChannel != nil {
			f.controlChannel.Close()
		}
	})
}

// Wait blocks until every served connection has finished.
func (f *dynamicForwarder) Wait() { f.connections.Wait() }

func (f *dynamicForwarder) acceptLoop() {
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			select {
			case <-f.ctx.Done():
				return
			default:
			}
			log.Error().Msgf("could not accept a SOCKS5 connection: %s", err)
			return
		}
		f.connections.Add(1)
		go func() {
			defer util.PanicGuard("cmd/dynamic_forward.go:408")()
			defer f.connections.Done()
			f.serveSOCKSConnection(conn)
		}()
	}
}

// serveSOCKSConnection runs the SOCKS5 state machine for one accepted
// connection and, on success, bridges it to the target through the server.
func (f *dynamicForwarder) serveSOCKSConnection(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout)); err != nil {
		log.Warn().Msgf("could not set the SOCKS5 handshake deadline: %s", err)
		return
	}

	if err := socks5ReadMethodSelection(conn); err != nil {
		log.Debug().Msgf("closing SOCKS5 connection from %s: %s", conn.RemoteAddr(), err)
		return
	}
	if err := socks5WriteMethodSelectionReply(conn, socks5MethodNoAuth); err != nil {
		log.Debug().Msgf("could not send the SOCKS5 method selection to %s: %s", conn.RemoteAddr(), err)
		return
	}

	buffer := make([]byte, socks5MaxRequestLength)
	length, err := readSocks5Request(conn, buffer)
	if err != nil {
		f.replyAndClose(conn, err)
		return
	}
	request, consumed, err := parseSocks5Request(buffer[:length])
	if err != nil {
		f.replyAndClose(conn, err)
		return
	}
	target, err := dynamicForwardTargetFromSocks5Request(request)
	if err != nil {
		f.replyAndClose(conn, err)
		return
	}

	stream, err := f.openDynamicForwardStream(target)
	if err != nil {
		f.replyAndClose(conn, err)
		return
	}
	defer stream.Close()

	// the handshake is over: the connection is now an opaque tunnel
	if err := conn.SetDeadline(time.Time{}); err != nil {
		log.Warn().Msgf("could not clear the SOCKS5 handshake deadline: %s", err)
	}
	if _, err := conn.Write(socks5SuccessReply(conn.RemoteAddr())); err != nil {
		log.Debug().Msgf("could not confirm the SOCKS5 request to %s: %s", conn.RemoteAddr(), err)
		return
	}

	// whatever the client already sent past its request belongs to the tunnel
	pending := buffer[consumed:length]
	var reader io.Reader = conn
	if len(pending) > 0 {
		reader = io.MultiReader(bytes.NewReader(pending), conn)
	}
	pumpDynamicForward(reader, conn, stream)
}

// openDynamicForwardStream opens the data channel for one SOCKS connection and
// returns it only once the server confirmed it reached the target.
func (f *dynamicForwarder) openDynamicForwardStream(target *ssh3Messages.DynamicForwardTarget) (io.ReadWriteCloser, error) {
	targetDescription := net.JoinHostPort(target.Address, strconv.Itoa(int(target.Port)))
	// the data channel is a byte tunnel: no datagrams flow through it, and a
	// non-zero queue size here would allocate a huge channel per connection
	channel, err := f.conversation.OpenChannel(ssh3Messages.ChannelTypeDynamicForwardTCP, 30000, 0)
	if err != nil {
		return nil, socks5Fail(socks5ReplyHostUnreachable,
			"could not open the dynamic forwarding channel for %s: %s", targetDescription, err)
	}
	if err := writeDynamicForwardPayload(channel, target); err != nil {
		channel.Close()
		return nil, socks5Fail(socks5ReplyHostUnreachable,
			"could not send the dynamic forwarding target %s: %s", targetDescription, err)
	}
	reply, err := readDynamicForwardTargetReply(channel)
	if err != nil {
		channel.Close()
		return nil, socks5Fail(socks5ReplyHostUnreachable,
			"could not read the dynamic forwarding reply for %s: %s", targetDescription, err)
	}
	if !reply.Success() {
		channel.Close()
		return nil, socks5Fail(socks5ReplyCodeForServerError(reply.ErrorUTF8), "%s", reply.ErrorUTF8)
	}
	log.Debug().Msgf("dynamic forwarding channel established for %s", targetDescription)
	return ssh3.NewChannelReadWriteCloser(channel), nil
}

func (f *dynamicForwarder) replyAndClose(conn net.Conn, err error) {
	log.Debug().Msgf("closing SOCKS5 connection from %s: %s", conn.RemoteAddr(), err)
	if _, writeErr := conn.Write(socks5FailureReply(socks5ReplyCode(err), err.Error())); writeErr != nil {
		log.Debug().Msgf("could not send the SOCKS5 failure reply to %s: %s", conn.RemoteAddr(), writeErr)
	}
}

// socks5ReplyCodeForServerError maps the server's textual dial failure onto a
// SOCKS5 reply code, so "connection refused" does not reach the client as
// "host unreachable".
func socks5ReplyCodeForServerError(message string) uint8 {
	lowered := strings.ToLower(message)
	switch {
	case strings.Contains(lowered, "refused"):
		return socks5ReplyConnectionRefused
	case strings.Contains(lowered, "no such host"), strings.Contains(lowered, "unknown host"),
		strings.Contains(lowered, "unreachable"):
		return socks5ReplyHostUnreachable
	case strings.Contains(lowered, "timeout"), strings.Contains(lowered, "expired"):
		return socks5ReplyTTLExpired
	case strings.Contains(lowered, "network"):
		return socks5ReplyNetworkUnreachable
	default:
		return socks5ReplyGeneralFailure
	}
}

// pumpDynamicForward bridges the local connection and the remote channel in
// both directions, half-closing each side as soon as its source is done so the
// peer observes a clean end of stream instead of waiting for the other side.
func pumpDynamicForward(remote io.Reader, local io.Writer, stream io.ReadWriteCloser) {
	results := make(chan error, 2)
	go func() {
		defer util.PanicGuard("cmd/dynamic_forward.go:538")()
		_, err := io.Copy(stream, remote)
		closeWrite(stream)
		results <- err
	}()
	go func() {
		defer util.PanicGuard("cmd/dynamic_forward.go:543")()
		_, err := io.Copy(local, stream)
		closeWrite(local)
		results <- err
	}()
	<-results
}

func closeWrite(writer interface{}) {
	if halfCloser, ok := writer.(interface{ CloseWrite() error }); ok {
		halfCloser.CloseWrite()
	}
}

// dynamicForwardPayload is the shared shape of the dynamic forwarding payloads:
// each encodes itself into a buffer of exactly Length() bytes.
type dynamicForwardPayload interface {
	Length() int
	Write(buf []byte) (int, error)
}

func writeDynamicForwardPayload(channel ssh3.Channel, payload dynamicForwardPayload) error {
	buffer := make([]byte, payload.Length())
	if _, err := payload.Write(buffer); err != nil {
		return err
	}
	_, err := channel.WriteData(buffer, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	return err
}

// readDynamicForwardData reads the next data message of a channel and parses
// it. The payloads travel as channel data and not as new message-type ids:
// message.ParseMessage panics on an unknown id, so a new id would crash the
// peer instead of letting it reject the forward gracefully.
func readDynamicForwardData(channel ssh3.Channel, parse func(util.Reader) (dynamicForwardPayload, error)) (dynamicForwardPayload, error) {
	message, err := channel.NextMessage()
	if err != nil {
		return nil, err
	}
	dataMessage, ok := message.(*ssh3Messages.DataOrExtendedDataMessage)
	if !ok || dataMessage.DataType != ssh3Messages.SSH_EXTENDED_DATA_NONE {
		return nil, fmt.Errorf("unexpected message of type %T on the dynamic forwarding channel", message)
	}
	// the payload travels as a string inside the message; its bytes are
	// arbitrary (varint header, addresses), which a Go string preserves as is
	reader := util.BytesReadCloser{Reader: bytes.NewReader([]byte(dataMessage.Data))}
	return parse(&reader)
}

func readDynamicForwardReply(channel ssh3.Channel) (*ssh3Messages.DynamicForwardReply, error) {
	payload, err := readDynamicForwardData(channel, func(reader util.Reader) (dynamicForwardPayload, error) {
		return ssh3Messages.ParseDynamicForwardReply(reader)
	})
	if err != nil {
		return nil, err
	}
	reply, ok := payload.(*ssh3Messages.DynamicForwardReply)
	if !ok {
		return nil, fmt.Errorf("unexpected dynamic forwarding reply of type %T", payload)
	}
	return reply, nil
}

func readDynamicForwardTargetReply(channel ssh3.Channel) (*ssh3Messages.DynamicForwardTargetReply, error) {
	payload, err := readDynamicForwardData(channel, func(reader util.Reader) (dynamicForwardPayload, error) {
		return ssh3Messages.ParseDynamicForwardTargetReply(reader)
	})
	if err != nil {
		return nil, err
	}
	reply, ok := payload.(*ssh3Messages.DynamicForwardTargetReply)
	if !ok {
		return nil, fmt.Errorf("unexpected dynamic forwarding target reply of type %T", payload)
	}
	return reply, nil
}
