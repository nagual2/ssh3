package ssh3

import "testing"

// clampPeerMaxPacketSize is the S2-01 bound: the peer's advertised value
// sizes the endpoint's per-channel read buffers, so it must never exceed the
// locally advertised one.
func TestClampPeerMaxPacketSize(t *testing.T) {
	const local = 30000
	cases := []struct {
		peer uint64
		want uint64
	}{
		{0, 0},
		{1, 1},
		{30000, 30000},   // equal to the local value stays as-is
		{30001, 30000},   // slightly above is lowered
		{1 << 24, 30000}, // the 16 MiB ParseSSHString cap is lowered too
		{1 << 62, 30000},
	}
	for _, c := range cases {
		if got := clampPeerMaxPacketSize(c.peer, local); got != c.want {
			t.Errorf("clampPeerMaxPacketSize(%d, %d) = %d, want %d", c.peer, local, got, c.want)
		}
	}
}
