package util

import (
	"bytes"
	"testing"
)

// FuzzParseSSHString guards the no-unbounded-allocation invariant: any byte
// stream may come back as an error, but the parse must never panic (the
// makeslice/OOM kill behind the peer-controlled length) nor allocate past
// the cap.
func FuzzParseSSHString(f *testing.F) {
	for _, seed := range [][]byte{
		{},
		{0x00},
		{0x05, 'h', 'e', 'l', 'l', 'o'},
		{0x80, 0x01},
		AppendVarInt(nil, MaxSSHStringLen)[:1],
		AppendVarInt(nil, MaxSSHStringLen+1),
		AppendVarInt(nil, 1<<62-1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseSSHString(NewReader(bytes.NewReader(data)))
	})
}

// FuzzReadVarInt: roundtrip already covered by tests; here any byte stream
// must come back as a value or an error, never a panic.
func FuzzReadVarInt(f *testing.F) {
	for _, seed := range [][]byte{
		{}, {0x7f}, {0x80}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ReadVarInt(NewReader(bytes.NewReader(data)))
	})
}
