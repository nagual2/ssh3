package message

import (
	"bytes"
	"testing"

	"github.com/francoismichel/ssh3/util"
)

// Edge values of the exit-status request: 2^62-1 is the largest status that
// fits the 62-bit QUIC varint and can go on the wire (CTO task stage 1,
// bug 2: a signal-killed process must never be encoded as uint64(-1)).
func TestExitStatusRequestEdgeValues(t *testing.T) {
	for _, status := range []uint64{0, 255, 1<<62 - 1} {
		req := &ExitStatusRequest{ExitStatus: status}
		buf := make([]byte, req.Length())
		if _, err := req.Write(buf); err != nil {
			t.Fatalf("Write(%d): %s", status, err)
		}
		got, err := util.ReadVarInt(bytes.NewReader(buf))
		if err != nil || got != status {
			t.Fatalf("wire roundtrip of %d returned (%d, %v)", status, got, err)
		}
	}
}
