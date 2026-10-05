//go:build !windows

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// Unit tests for the server-side -R hardening: the GatewayPorts policy
// applied to client-requested bind addresses and the per-user limit on
// simultaneous reverse forward listeners.

import (
	"strings"
	"testing"
)

func TestParseGatewayPorts(t *testing.T) {
	for valid := range map[string]struct{}{"no": {}, "clientspecified": {}, "yes": {}} {
		if _, err := parseGatewayPorts(valid); err != nil {
			t.Errorf("parseGatewayPorts(%q): unexpected error %v", valid, err)
		}
	}

	if _, err := parseGatewayPorts(""); err == nil {
		t.Error("parseGatewayPorts(\"\"): want an error for the empty policy")
	}

	if _, err := parseGatewayPorts("sometimes"); err == nil {
		t.Error("parseGatewayPorts(\"sometimes\"): want an error for an unknown policy")
	}
}

func TestResolveReverseForwardBind(t *testing.T) {
	for _, tc := range []struct {
		policy    string
		requested string
		want      string
	}{
		// GatewayPorts=no (the default): everything non-loopback is forced
		// back to the loopback, like OpenSSH does silently
		{"no", "", "127.0.0.1"},
		{"no", "127.0.0.1", "127.0.0.1"},
		{"no", "::1", "::1"},
		{"no", "0.0.0.0", "127.0.0.1"},
		{"no", "192.0.2.1", "127.0.0.1"},
		{"no", "2001:db8::1", "127.0.0.1"},
		{"no", "example.invalid", "127.0.0.1"},

		// clientspecified: the client decides, an empty bind stays loopback
		{"clientspecified", "", "127.0.0.1"},
		{"clientspecified", "127.0.0.1", "127.0.0.1"},
		{"clientspecified", "0.0.0.0", "0.0.0.0"},
		{"clientspecified", "192.0.2.1", "192.0.2.1"},
		{"clientspecified", "2001:db8::1", "2001:db8::1"},

		// yes: the wildcard address, whatever the client asked for
		{"yes", "", ""},
		{"yes", "127.0.0.1", ""},
		{"yes", "0.0.0.0", ""},
		{"yes", "192.0.2.1", ""},
	} {
		got, err := resolveReverseForwardBind(tc.policy, tc.requested)
		if err != nil {
			t.Errorf("resolveReverseForwardBind(%q, %q): unexpected error %v", tc.policy, tc.requested, err)
			continue
		}

		if got != tc.want {
			t.Errorf("resolveReverseForwardBind(%q, %q) = %q, want %q", tc.policy, tc.requested, got, tc.want)
		}
	}
}

func TestReverseForwardBindLimit(t *testing.T) {
	restore := setReverseForwardMaxBindsPerUserForTest(2)
	defer restore()

	if !tryAcquireReverseForwardBind("alice") || !tryAcquireReverseForwardBind("alice") {
		t.Fatal("alice: the first two binds must be admitted")
	}

	if tryAcquireReverseForwardBind("alice") {
		t.Error("alice: the third bind must be refused at the limit of 2")
	}

	// another user has its own budget
	if !tryAcquireReverseForwardBind("bob") {
		t.Error("bob: a bind must be admitted while alice is saturated")
	}

	// a release frees a slot for the same user only
	releaseReverseForwardBind("alice")
	if tryAcquireReverseForwardBind("alice") != true {
		t.Error("alice: a bind must be admitted again after a release")
	}

	// releasing more than acquired must not corrupt the counter
	releaseReverseForwardBind("alice")
	releaseReverseForwardBind("alice")
	releaseReverseForwardBind("alice")
	if got := reverseForwardBindsPerUser["alice"]; got < 0 {
		t.Errorf("alice: the bind counter went negative (%d)", got)
	}

	if !tryAcquireReverseForwardBind("alice") || !tryAcquireReverseForwardBind("alice") {
		t.Error("alice: two binds must be admitted again after the releases")
	}
}

// the policy error must name the accepted values, the server startup uses it
// verbatim in its flag validation message
func TestParseGatewayPortsErrorMessage(t *testing.T) {
	_, err := parseGatewayPorts("bogus")
	if err == nil {
		t.Fatal("want an error for an unknown policy")
	}

	for _, want := range []string{"no", "clientspecified", "yes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q must mention %q", err, want)
		}
	}
}
