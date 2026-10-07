package message

import (
	"bytes"
	"errors"
	"testing"

	"github.com/francoismichel/ssh3/util"
)

// An unknown message-type id used to hit panic("not implemented") in
// ParseMessage; reachable with 2 bytes from any peer holding an accepted
// channel, it killed the whole process. It must come back as a typed error
// so the channel can be torn down instead.
func TestParseMessageUnknownTypeIdReturnsError(t *testing.T) {
	for _, typeId := range []uint64{0x01, 0x42, 0xff} {
		buf := util.AppendVarInt(nil, typeId)
		_, err := ParseMessage(util.NewReader(bytes.NewReader(buf)))
		var unknown UnknownMessageType
		if err == nil {
			t.Errorf("type id %#x: expected UnknownMessageType, got no error", typeId)
		} else if !errors.As(err, &unknown) {
			t.Errorf("type id %#x: expected UnknownMessageType, got %v", typeId, err)
		} else if unknown.TypeID != typeId {
			t.Errorf("type id %#x: error carries id %d", typeId, unknown.TypeID)
		}
	}
}

// known type ids must keep parsing
func TestParseMessageKnownTypeIdsStillParse(t *testing.T) {
	data := "payload"
	payload := util.AppendVarInt(nil, uint64(SSH_MSG_CHANNEL_DATA))
	encoded := make([]byte, util.SSHStringLen(data))
	if _, err := util.WriteSSHString(encoded, data); err != nil {
		t.Fatalf("WriteSSHString: %v", err)
	}
	payload = append(payload, encoded...)
	_, err := ParseMessage(util.NewReader(bytes.NewReader(payload)))
	if err != nil {
		t.Fatalf("SSH_MSG_CHANNEL_DATA: unexpected error %v", err)
	}
}
