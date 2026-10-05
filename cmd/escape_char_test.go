// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The EscapeChar value parser: one ASCII printable character, a ^X control
// form or none.

import "testing"

func TestParseEscapeChar(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  byte
	}{
		{"~", '~'},
		{"^]", 29},
		{"^[", 27},
		{"^?", 127},
		{"^A", 1},
		{"none", 0},
		{"", 0},
	} {
		got, err := parseEscapeChar(tc.value)
		if err != nil {
			t.Errorf("parseEscapeChar(%q): unexpected error %v", tc.value, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseEscapeChar(%q) = %d, want %d", tc.value, got, tc.want)
		}
	}

	for _, bad := range []string{"ab", "00e9", "^1", "^x"} {
		if _, err := parseEscapeChar(bad); err == nil {
			t.Errorf("parseEscapeChar(%q): want an error", bad)
		}
	}
}
