package cm

// Client-side protocol helpers shared by the slave and by tests: the
// version handshake and the request/reply exchange on a control or stream
// connection.

import (
	"fmt"
	"net"
)

// Hello performs the version handshake: it sends HELLO and expects OK.
func Hello(conn net.Conn) error {
	if err := WriteFrame(conn, MsgHello, nil); err != nil {
		return err
	}
	typ, _, err := ReadFrame(conn)
	if err != nil {
		return err
	}
	if typ != MsgOK {
		return fmt.Errorf("cm: unexpected handshake reply %v", typ)
	}
	return nil
}

// Call sends one request frame and reads the reply. OK returns the reply
// payload; Error returns it as an error; anything else is a protocol
// violation.
func Call(conn net.Conn, t MsgType, payload []byte) ([]byte, error) {
	if err := WriteFrame(conn, t, payload); err != nil {
		return nil, err
	}
	typ, resp, err := ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	switch typ {
	case MsgOK:
		return resp, nil
	case MsgError:
		return nil, fmt.Errorf("cm: master refused: %s", resp)
	default:
		return nil, fmt.Errorf("cm: unexpected reply %v", typ)
	}
}

// AttachPayload marshals an ATTACH request for a session stream.
func AttachPayload(token Token, stream StreamKind) []byte {
	return (&Attach{Token: token, Stream: stream}).Encode()
}
