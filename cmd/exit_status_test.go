package cmd

import "testing"

// A process killed by a signal reports a negative exit code (-1), which after
// a uint64 conversion overflows the 62-bit QUIC varint and panicked the whole
// server on exit-status encoding (CTO task stage 1, bug 2). The wire-safe
// mapping caps such abnormal deaths at 255, OpenSSH-style.
func TestSafeExitStatus(t *testing.T) {
	cases := []struct {
		exitCode int
		want     uint64
	}{
		{0, 0},
		{1, 1},
		{42, 42},
		{255, 255},
		{-1, 255},
		{-15, 255},
	}
	for _, c := range cases {
		if got := safeExitStatus(c.exitCode); got != c.want {
			t.Errorf("safeExitStatus(%d) = %d, want %d", c.exitCode, got, c.want)
		}
	}
}
