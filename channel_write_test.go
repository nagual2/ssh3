package ssh3

// Byte-identity tests for the zero-copy channel WriteData: the concatenated
// header+payload writes must produce exactly the same byte stream as the
// previous per-message marshalling.

import (
	"bytes"
	"testing"

	"github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

type recordingWriter struct {
	buf bytes.Buffer
}

func (w *recordingWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *recordingWriter) Close() error                { return nil }

// referenceWrite builds the byte stream the pre-optimization code produced:
// each MaxPacketSize-bounded chunk marshalled through DataOrExtendedDataMessage.
func referenceWrite(dataType message.SSHDataType, data []byte, maxPacketSize uint64) []byte {
	var out bytes.Buffer
	rest := data
	for len(rest) > 0 {
		dataMsg := &message.DataOrExtendedDataMessage{DataType: dataType, Data: ""}
		emptyMsgLen := dataMsg.Length()
		msgLen := util.MinUint64(maxPacketSize-uint64(emptyMsgLen), uint64(len(rest)))
		full := &message.DataOrExtendedDataMessage{
			DataType: dataType,
			Data:     string(rest[:msgLen]),
		}
		msgBuf := make([]byte, full.Length())
		if _, err := full.Write(msgBuf); err != nil {
			panic(err)
		}
		out.Write(msgBuf)
		rest = rest[msgLen:]
	}
	return out.Bytes()
}

func TestWriteDataByteIdentity(t *testing.T) {
	data := make([]byte, 70000)
	for i := range data {
		data[i] = byte(i % 251)
	}
	for _, dataType := range []message.SSHDataType{
		message.SSH_EXTENDED_DATA_NONE,
		message.SSH_EXTENDED_DATA_STDERR,
	} {
		w := &recordingWriter{}
		ch := &channelImpl{
			ChannelInfo: ChannelInfo{MaxPacketSize: 30000},
			send:        w,
		}
		if _, err := ch.WriteData(data, dataType); err != nil {
			t.Fatalf("WriteData: %v", err)
		}
		ref := referenceWrite(dataType, data, 30000)
		if !bytes.Equal(w.buf.Bytes(), ref) {
			t.Fatalf("byte stream mismatch (dataType=%d): got %d bytes, want %d\n got head: %x\nwant head: %x",
				dataType, w.buf.Len(), len(ref), w.buf.Bytes()[:16], ref[:16])
		}
	}
}

// a write shorter than MaxPacketSize must round-trip as a single message
func TestWriteDataSmallPayloadSingleMessage(t *testing.T) {
	w := &recordingWriter{}
	ch := &channelImpl{
		ChannelInfo: ChannelInfo{MaxPacketSize: 30000},
		send:        w,
	}
	if _, err := ch.WriteData([]byte("ping"), message.SSH_EXTENDED_DATA_NONE); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	ref := referenceWrite(message.SSH_EXTENDED_DATA_NONE, []byte("ping"), 30000)
	if !bytes.Equal(w.buf.Bytes(), ref) {
		t.Fatalf("mismatch: got %q, want %q", w.buf.Bytes(), ref)
	}
}
