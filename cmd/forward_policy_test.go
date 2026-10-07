// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// PermitOpen semantics for the server-side forwarding policy: wildcard
// hosts, wildcard ports, ! negation, empty = unrestricted.

import "testing"

func TestParsePermitOpenEmptyIsUnrestricted(t *testing.T) {
	policy, err := parsePermitOpen("")
	if err != nil || policy != nil {
		t.Fatalf("empty spec must yield (nil, nil), got (%v, %v)", policy, err)
	}
	if !policy.allows("anything", 1) {
		t.Error("a nil policy must allow everything")
	}
}

func TestParsePermitOpenInvalidEntries(t *testing.T) {
	for _, spec := range []string{"host", "host:", ":80", "host:notaport", "!host"} {
		if _, err := parsePermitOpen(spec); err == nil {
			t.Errorf("%q must not parse", spec)
		}
	}
}

func TestForwardPolicyAllows(t *testing.T) {
	policy, err := parsePermitOpen("*.example.org:443, db.internal:5432, host:*")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host  string
		port  int
		allow bool
	}{
		{"a.example.org", 443, true},
		{"b.a.example.org", 443, true},
		{"example.org", 443, false}, // the bare domain is not under *.
		{"a.example.org", 8443, false},
		{"db.internal", 5432, true},
		{"db.internal", 22, false},
		{"host", 1, true},
		{"host", 65535, true},
		{"other", 80, false},
		{"A.EXAMPLE.ORG", 443, true}, // host matching is case-insensitive
	}
	for _, c := range cases {
		if got := policy.allows(c.host, c.port); got != c.allow {
			t.Errorf("allows(%q, %d) = %v, want %v", c.host, c.port, got, c.allow)
		}
	}
}

func TestForwardPolicyNegation(t *testing.T) {
	policy, err := parsePermitOpen("!internal.host:*,*.example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	if policy.allows("internal.host", 443) {
		t.Error("a negated match must deny even when another entry allows")
	}
	if !policy.allows("a.example.org", 443) {
		t.Error("a non-negated allow entry must match")
	}
	if policy.allows("a.example.org", 80) {
		t.Error("no entry matches this port: with allow entries present, unmatched is denied")
	}
}

func TestForwardPolicyOnlyNegatedAllowsRest(t *testing.T) {
	policy, err := parsePermitOpen("!secret.host:*")
	if err != nil {
		t.Fatal(err)
	}
	if policy.allows("secret.host", 22) {
		t.Error("the negated host must stay denied")
	}
	if !policy.allows("anything.else", 22) {
		t.Error("with only negated entries, everything else stays allowed")
	}
}
