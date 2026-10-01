package cm

// Slave→master message payloads. Encoding is big-endian, length-prefixed
// strings; decoders are strict (truncation and trailing bytes are errors)
// so a desynchronized stream fails loudly instead of mis-decoding.

import (
	"crypto/rand"
	"encoding/binary"
)

// PtySpec requests a remote pty; nil in OpenSession means no pty.
type PtySpec struct {
	Term        string
	Columns     uint32
	Rows        uint32
	PixelWidth  uint32
	PixelHeight uint32
}

// OpenSession asks the master to open a session channel. Command is the
// remote command line; empty/nil means a remote shell.
type OpenSession struct {
	Command      []string
	Env          []string
	Pty          *PtySpec
	ForwardAgent bool
}

// OpenForward asks the master to open a forwarding channel.
type OpenForward struct {
	ListenAddr string // local side; "" lets the master pick one
	TargetAddr string // remote side the master connects/forwards to
}

// Token identifies one bridged session between the control connection and
// the stream attachments.
type Token [16]byte

// NewToken generates a fresh session token.
func NewToken() (Token, error) {
	var t Token
	if _, err := rand.Read(t[:]); err != nil {
		return t, err
	}
	return t, nil
}

// StreamKind selects which data stream an attachment carries.
type StreamKind uint8

const (
	StreamIO     StreamKind = 0 // full duplex: slave stdin up, session stdout down
	StreamStderr StreamKind = 1 // master → slave only
)

// Attach binds a dedicated stream connection to a bridged session. The
// stderr stream must attach before the io stream: the master starts the
// session pump on the io attachment and needs the stderr sink by then.
type Attach struct {
	Token  Token
	Stream StreamKind
}

// Encode marshals the message.
func (m *Attach) Encode() []byte {
	b := make([]byte, 0, 17)
	b = append(b, m.Token[:]...)
	return append(b, byte(m.Stream))
}

// Decode unmarshals the message; malformed input is an error.
func (m *Attach) Decode(payload []byte) error {
	if len(payload) != 17 {
		return errShort
	}
	copy(m.Token[:], payload)
	switch StreamKind(payload[16]) {
	case StreamIO:
		m.Stream = StreamIO
	case StreamStderr:
		m.Stream = StreamStderr
	default:
		return errTrailing
	}
	return nil
}

// EncodeExitStatus marshals a session exit status (8 bytes, big endian).
func EncodeExitStatus(code uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, code)
}

// DecodeExitStatus unmarshals a session exit status.
func DecodeExitStatus(payload []byte) (uint64, error) {
	if len(payload) != 8 {
		return 0, errShort
	}
	return binary.BigEndian.Uint64(payload), nil
}

func appendStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func readStr(b []byte) (string, []byte, error) {
	if len(b) < 4 {
		return "", nil, errShort
	}
	n := binary.BigEndian.Uint32(b)
	b = b[4:]
	if uint64(len(b)) < uint64(n) {
		return "", nil, errShort
	}
	return string(b[:n]), b[n:], nil
}

func readCount(b []byte, minBytesPerItem int) (int, []byte, error) {
	if len(b) < 4 {
		return 0, nil, errShort
	}
	n := int(binary.BigEndian.Uint32(b))
	b = b[4:]
	// each item costs at least minBytesPerItem payload bytes, so a count
	// above the remaining length is already malformed
	if n > len(b)/minBytesPerItem {
		return 0, nil, errShort
	}
	return n, b, nil
}

// Encode marshals the message.
func (m *OpenSession) Encode() ([]byte, error) {
	b := make([]byte, 0, 64)
	b = binary.BigEndian.AppendUint32(b, uint32(len(m.Command)))
	for _, s := range m.Command {
		b = appendStr(b, s)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(len(m.Env)))
	for _, s := range m.Env {
		b = appendStr(b, s)
	}
	if m.Pty != nil {
		b = append(b, 1)
		b = appendStr(b, m.Pty.Term)
		b = binary.BigEndian.AppendUint32(b, m.Pty.Columns)
		b = binary.BigEndian.AppendUint32(b, m.Pty.Rows)
		b = binary.BigEndian.AppendUint32(b, m.Pty.PixelWidth)
		b = binary.BigEndian.AppendUint32(b, m.Pty.PixelHeight)
	} else {
		b = append(b, 0)
	}
	agent := byte(0)
	if m.ForwardAgent {
		agent = 1
	}
	return append(b, agent), nil
}

// Decode unmarshals the message; malformed or trailing input is an error.
func (m *OpenSession) Decode(payload []byte) error {
	b := payload
	ncmd, b, err := readCount(b, 4)
	if err != nil {
		return err
	}
	if ncmd > 0 {
		m.Command = make([]string, 0, ncmd)
		for range ncmd {
			var s string
			if s, b, err = readStr(b); err != nil {
				return err
			}
			m.Command = append(m.Command, s)
		}
	}
	nenv, b, err := readCount(b, 4)
	if err != nil {
		return err
	}
	if nenv > 0 {
		m.Env = make([]string, 0, nenv)
		for range nenv {
			var s string
			if s, b, err = readStr(b); err != nil {
				return err
			}
			m.Env = append(m.Env, s)
		}
	}
	if len(b) < 1 {
		return errShort
	}
	hasPty := b[0] == 1
	b = b[1:]
	if !hasPty {
		m.Pty = nil
	} else {
		m.Pty = &PtySpec{}
		if m.Pty.Term, b, err = readStr(b); err != nil {
			return err
		}
		if len(b) < 16 {
			return errShort
		}
		m.Pty.Columns = binary.BigEndian.Uint32(b)
		m.Pty.Rows = binary.BigEndian.Uint32(b[4:])
		m.Pty.PixelWidth = binary.BigEndian.Uint32(b[8:])
		m.Pty.PixelHeight = binary.BigEndian.Uint32(b[12:])
		b = b[16:]
	}
	if len(b) < 1 {
		return errShort
	}
	m.ForwardAgent = b[0] == 1
	b = b[1:]
	if len(b) != 0 {
		return errTrailing
	}
	return nil
}

// Encode marshals the message.
func (m *OpenForward) Encode() []byte {
	b := appendStr(nil, m.ListenAddr)
	return appendStr(b, m.TargetAddr)
}

// Decode unmarshals the message; malformed or trailing input is an error.
func (m *OpenForward) Decode(payload []byte) error {
	listen, b, err := readStr(payload)
	if err != nil {
		return err
	}
	target, b, err := readStr(b)
	if err != nil {
		return err
	}
	if len(b) != 0 {
		return errTrailing
	}
	m.ListenAddr = listen
	m.TargetAddr = target
	return nil
}
