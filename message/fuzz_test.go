package message

import (
	"bytes"
	"testing"

	"github.com/francoismichel/ssh3/util"
)

// FuzzParseMessage guards the parse surface every peer byte goes through:
// any input may come back as an error (including UnknownMessageType), but
// the parse must never panic — the old panic("not implemented") on unknown
// type ids was a 2-byte remote process kill.
func FuzzParseMessage(f *testing.F) {
	for _, typeId := range []uint64{
		SSH_MSG_CHANNEL_REQUEST,
		SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
		SSH_MSG_CHANNEL_OPEN_FAILURE,
		SSH_MSG_CHANNEL_DATA,
		SSH_MSG_CHANNEL_EXTENDED_DATA,
		0x01, 0x2a, 0xff,
	} {
		f.Add(util.AppendVarInt(nil, typeId))
	}
	f.Add([]byte{})
	f.Add([]byte{0x94, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseMessage(util.NewReader(bytes.NewReader(data)))
	})
}
