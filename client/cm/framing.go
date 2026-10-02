// Package cm implements the ControlMaster (stage 3.5) control-channel
// protocol: a minimal versioned framing plus the slave→master message set.
// Deliberately not OpenSSH-mux-wire-compatible (CTO_TASK §6b): both ends are
// ours (Go CLI now, Rust client later), so the format optimizes for a small
// auditable codec over UDS.
package cm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the mux protocol version carried by every frame header; a HELLO
// with a mismatching version is refused by the peer.
const Version = 1

// MsgType enumerates control frames. Slave→master: Hello, OpenSession,
// OpenForwardTCP, OpenForwardUDP, Exit, WindowChange, Signal. Master→slave:
// OK, Error, ExitStatus.
type MsgType uint8

const (
	MsgHello          MsgType = 1
	MsgOpenSession    MsgType = 2
	MsgOpenForwardTCP MsgType = 3
	MsgOpenForwardUDP MsgType = 4
	MsgExit           MsgType = 5
	MsgOK             MsgType = 6
	MsgError          MsgType = 7
	MsgAttach         MsgType = 8
	MsgExitStatus     MsgType = 9
	MsgWindowChange   MsgType = 10
	MsgSignal         MsgType = 11
)

// magic tags every frame so a garbage dialer (HTTP probe, stray client)
// fails fast instead of being misparsed as a control message.
var magic = [4]byte{'S', '3', 'C', 'M'}

// maxFrame bounds one control payload. Session/forward descriptors are
// tiny; bulk data travels outside this codec over the bridged streams.
const maxFrame = 1 << 20

// headerLen: magic(4) version(1) type(1) payload length(4, big endian).
const headerLen = 10

var (
	ErrBadMagic  = errors.New("cm: not a control-master stream (bad magic)")
	ErrVersion   = errors.New("cm: protocol version mismatch")
	ErrFrameSize = errors.New("cm: frame payload too large")
	ErrTruncated = errors.New("cm: truncated frame")
	errShort     = errors.New("cm: truncated message payload")
	errTrailing  = errors.New("cm: trailing bytes after message")
)

// WriteFrame writes one frame with the current protocol version.
func WriteFrame(w io.Writer, t MsgType, payload []byte) error {
	if len(payload) > maxFrame {
		return ErrFrameSize
	}
	hdr := make([]byte, headerLen)
	copy(hdr, magic[:])
	hdr[4] = Version
	hdr[5] = byte(t)
	binary.BigEndian.PutUint32(hdr[6:], uint32(len(payload)))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one frame. A clean peer close surfaces as io.EOF; a
// started-but-incomplete header or payload is ErrTruncated — a partial
// write is a protocol violation, not an orderly end.
func ReadFrame(r io.Reader) (MsgType, []byte, error) {
	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, nil, ErrTruncated
		}
		return 0, nil, err
	}
	if hdr[0] != magic[0] || hdr[1] != magic[1] || hdr[2] != magic[2] || hdr[3] != magic[3] {
		return 0, nil, ErrBadMagic
	}
	if hdr[4] != Version {
		return 0, nil, fmt.Errorf("%w: got %d, want %d", ErrVersion, hdr[4], Version)
	}
	n := binary.BigEndian.Uint32(hdr[6:])
	if n > maxFrame {
		return 0, nil, ErrFrameSize
	}
	payload := make([]byte, n)
	if n > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, nil, ErrTruncated
			}
			return 0, nil, err
		}
	}
	return MsgType(hdr[5]), payload, nil
}
