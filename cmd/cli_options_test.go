package cmd

import "testing"

// cliOptionFlags backs the repeatable -o Key=Value flag: only well-formed
// pairs are accepted, malformed values must fail at flag parsing time (like
// OpenSSH rejects bad -o arguments before connecting).
func TestCliOptionFlags(t *testing.T) {
	var flags cliOptionFlags
	if flags.String() != "" {
		t.Errorf("empty cliOptionFlags String() = %q, want empty", flags.String())
	}
	if err := flags.Set("StrictHostKeyChecking=accept-new"); err != nil {
		t.Errorf("Set(valid pair) returned error: %s", err)
	}
	if err := flags.Set("IdentityFile=~/.ssh/id_ed25519"); err != nil {
		t.Errorf("Set(valid pair) returned error: %s", err)
	}
	if err := flags.Set("NoValueHere"); err == nil {
		t.Error("Set(value without =) = nil error, want an error")
	}
	want := "StrictHostKeyChecking=accept-new,IdentityFile=~/.ssh/id_ed25519"
	if flags.String() != want {
		t.Errorf("cliOptionFlags String() = %q, want %q", flags.String(), want)
	}
	if len(flags) != 2 {
		t.Errorf("len(cliOptionFlags) = %d, want 2", len(flags))
	}
}
