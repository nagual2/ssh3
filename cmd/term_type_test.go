package cmd

import (
	"strings"
	"testing"

	"github.com/francoismichel/ssh3/client"
)

// The -o Term value is rejected before a connection is set up: empty names,
// whitespace and oversize values never reach the wire.
func TestParseTermType(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "plain", value: "xterm", want: "xterm"},
		{name: "256color", value: "xterm-256color", want: "xterm-256color"},
		{name: "trimmed", value: "  screen-256color  ", want: "screen-256color"},
		{name: "empty", value: "", wantErr: true},
		{name: "blank", value: "   ", wantErr: true},
		{name: "whitespace inside", value: "xterm color", wantErr: true},
		{name: "tab inside", value: "xterm\tx", wantErr: true},
		{name: "too long", value: strings.Repeat("a", 65), wantErr: true},
		{name: "max length", value: strings.Repeat("a", 64), want: strings.Repeat("a", 64)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTermType(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseTermType(%q) = %q, want error", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTermType(%q) returned error: %s", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("parseTermType(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// The Term resolution follows the OpenSSH precedence: the -o option wins over
// the ~/.ssh/config keyword, then comes the local TERM environment variable,
// and the built-in default is the last resort.
func TestResolveTermTypePrecedence(t *testing.T) {
	t.Setenv("TERM", "env-term")
	if got := resolveTermType("option-term", "config-term"); got != "option-term" {
		t.Errorf("option: got %q, want option-term", got)
	}
	if got := resolveTermType("", "config-term"); got != "config-term" {
		t.Errorf("config: got %q, want config-term", got)
	}
	if got := resolveTermType("", ""); got != "env-term" {
		t.Errorf("environment: got %q, want env-term", got)
	}
	t.Setenv("TERM", "")
	if got := resolveTermType("", ""); got != client.DefaultTermType {
		t.Errorf("default: got %q, want %s", got, client.DefaultTermType)
	}
}
