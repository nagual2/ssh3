// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The RequestTTY policy values and their validation (OpenSSH ssh_config
// semantics): auto, no, yes, force.

import "testing"

func TestParseRequestTTY(t *testing.T) {
	for _, valid := range []string{"auto", "no", "yes", "force", "AUTO", "Force"} {
		if _, err := parseRequestTTY(valid); err != nil {
			t.Errorf("parseRequestTTY(%q): unexpected error %v", valid, err)
		}
	}

	for _, bad := range []string{"", "always", "tty", "1"} {
		if _, err := parseRequestTTY(bad); err == nil {
			t.Errorf("parseRequestTTY(%q): want an error", bad)
		}
	}

	// the canonical lower-case form must come back out (config lookups and
	// logs compare on it)
	if got, _ := parseRequestTTY("FORCE"); got != "force" {
		t.Errorf("parseRequestTTY(\"FORCE\") = %q, want \"force\"", got)
	}
}
