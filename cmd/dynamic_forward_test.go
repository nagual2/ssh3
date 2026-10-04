package cmd

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// The SOCKS5 request must be decoded for the three address types a client can
// send, and a domain name must reach the server untouched: the proxy target is
// resolved by the server, never locally.
func TestParseSocks5Request(t *testing.T) {
	ipv6Host := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x01,
	}

	tests := []struct {
		name        string
		request     []byte
		wantHost    string
		wantPort    uint16
		wantConsume int
		wantErr     bool
	}{
		{
			name:        "ipv4",
			request:     append([]byte{0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50}, []byte{0xde, 0xad, 0xbe, 0xef}...),
			wantHost:    "93.184.216.34",
			wantPort:    80,
			wantConsume: 10,
		},
		{
			name:        "domain",
			request:     []byte{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb},
			wantHost:    "example.com",
			wantPort:    443,
			wantConsume: 18,
		},
		{
			name:        "ipv6",
			request:     append([]byte{0x05, 0x01, 0x00, 0x04}, append(append([]byte{}, ipv6Host...), 0x1f, 0x90)...),
			wantHost:    "2001:db8::1",
			wantPort:    8080,
			wantConsume: 22,
		},
		{
			name: "trailing payload is left for the tunnel",
			// a pipelined client may already have sent payload bytes
			request:     append([]byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90, 'h', 'i'}, 0xde, 0xad),
			wantHost:    "127.0.0.1",
			wantPort:    8080,
			wantConsume: 10,
		},
		{name: "empty buffer", request: nil, wantErr: true},
		{name: "truncated header", request: []byte{0x05, 0x01}, wantErr: true},
		{
			name:    "bad version",
			request: []byte{0x04, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50},
			wantErr: true,
		},
		{
			name:    "bind command is not supported",
			request: []byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50},
			wantErr: true,
		},
		{
			name:    "unknown address type",
			request: []byte{0x05, 0x01, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00},
			wantErr: true,
		},
		{
			name:    "truncated ipv4 address",
			request: []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0},
			wantErr: true,
		},
		{
			name:    "truncated domain length",
			request: []byte{0x05, 0x01, 0x00, 0x03},
			wantErr: true,
		},
		{
			name:    "empty domain",
			request: []byte{0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50},
			wantErr: true,
		},
		{
			name:    "truncated domain name",
			request: []byte{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a'},
			wantErr: true,
		},
		{
			name:    "truncated ipv6 address",
			request: []byte{0x05, 0x01, 0x00, 0x04, 0x20, 0x01},
			wantErr: true,
		},
		{
			name:    "missing port",
			request: []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, consumed, err := parseSocks5Request(test.request)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseSocks5Request(% x) = %+v, want an error", test.request, request)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSocks5Request(% x) returned error: %s", test.request, err)
			}
			if request.Address != test.wantHost {
				t.Errorf("address = %q, want %q", request.Address, test.wantHost)
			}
			if request.Port != test.wantPort {
				t.Errorf("port = %d, want %d", request.Port, test.wantPort)
			}
			if consumed != test.wantConsume {
				t.Errorf("consumed = %d, want %d", consumed, test.wantConsume)
			}
			if request.Version != socks5Version || request.Command != socks5CommandConnect {
				t.Errorf("version/command = %d/%d, want %d/%d",
					request.Version, request.Command, socks5Version, socks5CommandConnect)
			}
		})
	}
}

// No authentication is offered and no authentication is accepted: an SOCKS5
// proxy that only ever listens on the loopback interface.
func TestSocks5NegotiationNoAuth(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		if err := socks5ReadMethodSelection(server); err != nil {
			t.Errorf("the server could not read the method selection: %s", err)
			client.Close()
			return
		}
		if err := socks5WriteMethodSelectionReply(server, socks5MethodNoAuth); err != nil {
			t.Errorf("the server could not send the method selection reply: %s", err)
		}
	}()

	if err := socks5WriteMethodSelection(client); err != nil {
		t.Fatalf("the client could not send the method selection: %s", err)
	}
	if err := socks5ReadMethodSelectionReply(client, socks5MethodNoAuth); err != nil {
		t.Fatalf("the client could not read the method selection reply: %s", err)
	}
}

// A client asking for a credential method must be refused instead of being
// silently downgraded, so that credentials never travel over the proxy.
func TestSocks5MethodSelectionRefusesAuthentication(t *testing.T) {
	for _, method := range []byte{socks5MethodGssApi, 0x02, 0x80, 0xff} {
		var reply bytes.Buffer
		if err := socks5WriteMethodSelectionReply(&reply, method); err != nil {
			t.Fatalf("could not write the method selection reply: %s", err)
		}
		if got := reply.Bytes(); !bytes.Equal(got, []byte{0x05, method}) {
			t.Errorf("method selection reply = % x, want {05 %02x}", got, method)
		}
		if err := socks5ReadMethodSelectionReply(bytes.NewReader([]byte{0x05, method}), socks5MethodNoAuth); err == nil {
			t.Errorf("method %02x was accepted, want a refusal", method)
		}
		if err := socks5ReadMethodSelectionReply(bytes.NewReader([]byte{0x05, 0xff}), socks5MethodNoAuth); err == nil {
			t.Error("no acceptable method must be refused")
		}
	}
}

// The failure reply has to stay short: a client that picked ATYP=1 only reads
// four address bytes there, and a longer reply desynchronizes the stream.
func TestSocks5FailureReply(t *testing.T) {
	message := "target refused"
	reply := socks5FailureReply(socks5ReplyHostUnreachable, message)
	if len(reply) != 10 {
		t.Fatalf("failure reply length = %d, want 10: % x", len(reply), reply)
	}
	if reply[0] != socks5Version || reply[1] != socks5ReplyHostUnreachable {
		t.Errorf("failure reply header = % x, want {%02x %02x}", reply[:2], socks5Version, socks5ReplyHostUnreachable)
	}
	// the bound address/port must be the unspecified ones
	for i, b := range reply[4:8] {
		if b != 0 {
			t.Errorf("failure reply address byte %d = %d, want 0", i, b)
		}
	}
	if binary.BigEndian.Uint16(reply[8:10]) != 0 {
		t.Errorf("failure reply port = %d, want 0", binary.BigEndian.Uint16(reply[8:10]))
	}
	// no message is ever exposed on the wire: it would be truncated anyway
	if success := socks5SuccessReply(nil); len(success) != 10 {
		t.Errorf("success reply length = %d, want 10", len(success))
	}
}

// The proxy resolves nothing locally: the target must reach the server with
// the address the client sent, ports included.
func TestDynamicForwardTargetFromSocks5Request(t *testing.T) {
	target, err := dynamicForwardTargetFromSocks5Request(socks5Request{
		Version: socks5Version,
		Command: socks5CommandConnect,
		Address: "files.example.com",
		Port:    2222,
	})
	if err != nil {
		t.Fatalf("dynamicForwardTargetFromSocks5Request returned error: %s", err)
	}
	if target.Address != "files.example.com" || target.Port != 2222 {
		t.Errorf("target = %s:%d, want files.example.com:2222", target.Address, target.Port)
	}
	if _, err := dynamicForwardTargetFromSocks5Request(socks5Request{Version: socks5Version, Address: "x", Port: 0}); err == nil {
		t.Error("a target without a port must be refused")
	}
	if _, err := dynamicForwardTargetFromSocks5Request(socks5Request{Version: socks5Version, Port: 1}); err == nil {
		t.Error("a target without an address must be refused")
	}
}

// The listener must not outlive its context, and closing must stay safe even
// when the forwarder never got as far as listening (a startup error path).
func TestDynamicForwarderCloseIsIdempotent(t *testing.T) {
	forwarder := &dynamicForwarder{}
	forwarder.Close()
	forwarder.Close()
}
