package ssh3

// Unit tests for the StrictHostKeyChecking policy: value parsing (OpenSSH
// semantics), the precedence between configuration sources, and the way the
// optional SSHFP verification plugs into the policy.

import "testing"

func TestParseStrictHostKeyChecking(t *testing.T) {
	cases := []struct {
		value string
		want  StrictHostKeyChecking
		ok    bool
	}{
		{"yes", StrictHostKeyCheckingYes, true},
		{"YES", StrictHostKeyCheckingYes, true},
		{"true", StrictHostKeyCheckingYes, true},
		{"on", StrictHostKeyCheckingYes, true},
		{"no", StrictHostKeyCheckingNo, true},
		{"False", StrictHostKeyCheckingNo, true},
		{"off", StrictHostKeyCheckingNo, true},
		{"accept-new", StrictHostKeyCheckingAcceptNew, true},
		{"Accept-New", StrictHostKeyCheckingAcceptNew, true},
		{"ask", StrictHostKeyCheckingAsk, true},
		{"", StrictHostKeyCheckingAsk, true},
		{"  yes  ", StrictHostKeyCheckingYes, true},
		{"maybe", "", false},
		{"strict", "", false},
	}
	for _, c := range cases {
		got, err := ParseStrictHostKeyChecking(c.value)
		if c.ok {
			if err != nil {
				t.Errorf("ParseStrictHostKeyChecking(%q) returned error %s, want %q", c.value, err, c.want)
			} else if got != c.want {
				t.Errorf("ParseStrictHostKeyChecking(%q) = %q, want %q", c.value, got, c.want)
			}
		} else if err == nil {
			t.Errorf("ParseStrictHostKeyChecking(%q) = %q, want an error", c.value, got)
		}
	}
}

func TestResolveStrictHostKeyChecking(t *testing.T) {
	cases := []struct {
		name           string
		cliFlagSet     bool
		cliFlagValue   string
		optionValue    string
		configValue    string
		want           StrictHostKeyChecking
		wantErr        bool
		wantErrForFlag bool
	}{
		{"default is ask", false, "", "", "", StrictHostKeyCheckingAsk, false, false},
		{"flag wins over all", true, "yes", "accept-new", "no", StrictHostKeyCheckingYes, false, false},
		{"option wins over config", false, "", "accept-new", "no", StrictHostKeyCheckingAcceptNew, false, false},
		{"config used alone", false, "", "", "no", StrictHostKeyCheckingNo, false, false},
		{"empty config ignored", false, "", "", "", StrictHostKeyCheckingAsk, false, false},
		{"invalid flag value", true, "maybe", "accept-new", "no", "", true, true},
		{"invalid option value", false, "", "maybe", "", "", true, false},
		{"invalid config value", false, "", "", "maybe", "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveStrictHostKeyChecking(c.cliFlagSet, c.cliFlagValue, c.optionValue, c.configValue)
			if c.wantErr {
				if err == nil {
					t.Fatalf("ResolveStrictHostKeyChecking(%v, %q, %q, %q) = %q, want an error",
						c.cliFlagSet, c.cliFlagValue, c.optionValue, c.configValue, got)
				}
				if _, ok := err.(InvalidStrictHostKeyCheckingValue); !ok {
					t.Fatalf("error type = %T, want InvalidStrictHostKeyCheckingValue", err)
				}
				invalid := err.(InvalidStrictHostKeyCheckingValue)
				if c.wantErrForFlag && invalid.Value != c.cliFlagValue {
					t.Errorf("error reports %q, want the invalid flag value %q", invalid.Value, c.cliFlagValue)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveStrictHostKeyChecking(%v, %q, %q, %q) returned error %s",
					c.cliFlagSet, c.cliFlagValue, c.optionValue, c.configValue, err)
			}
			if got != c.want {
				t.Errorf("ResolveStrictHostKeyChecking(%v, %q, %q, %q) = %q, want %q",
					c.cliFlagSet, c.cliFlagValue, c.optionValue, c.configValue, got, c.want)
			}
		})
	}
}

func TestParseVerifyHostKeyDNS(t *testing.T) {
	cases := []struct {
		value string
		want  VerifyHostKeyDNS
		ok    bool
	}{
		{"no", VerifyHostKeyDNSNo, true},
		{"NO", VerifyHostKeyDNSNo, true},
		{" false ", VerifyHostKeyDNSNo, true},
		{"ask", VerifyHostKeyDNSAsk, true},
		{"Ask", VerifyHostKeyDNSAsk, true},
		{"yes", VerifyHostKeyDNSYes, true},
		{"true", VerifyHostKeyDNSYes, true},
		{"on", VerifyHostKeyDNSYes, true},
		{"", VerifyHostKeyDNSNo, true},
		{"maybe", "", false},
		{"1", "", false},
	}
	for _, c := range cases {
		got, err := ParseVerifyHostKeyDNS(c.value)
		if c.ok {
			if err != nil {
				t.Errorf("ParseVerifyHostKeyDNS(%q) returned error %s, want %q", c.value, err, c.want)
			} else if got != c.want {
				t.Errorf("ParseVerifyHostKeyDNS(%q) = %q, want %q", c.value, got, c.want)
			}
		} else if err == nil {
			t.Errorf("ParseVerifyHostKeyDNS(%q) = %q, want an error", c.value, got)
		}
	}
}

func TestResolveVerifyHostKeyDNS(t *testing.T) {
	cases := []struct {
		name       string
		cliSet     bool
		cliValue   string
		option     string
		config     string
		want       VerifyHostKeyDNS
		wantErrFor string
	}{
		{"default is off", false, "", "", "", VerifyHostKeyDNSNo, ""},
		{"flag wins", true, "yes", "no", "no", VerifyHostKeyDNSYes, ""},
		{"option wins over config", false, "", "ask", "no", VerifyHostKeyDNSAsk, ""},
		{"config alone", false, "", "", "yes", VerifyHostKeyDNSYes, ""},
		{"invalid flag", true, "maybe", "", "", "", "maybe"},
		{"invalid option", false, "", "maybe", "", "", "maybe"},
		{"invalid config", false, "", "", "maybe", "", "maybe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ResolveVerifyHostKeyDNS(c.cliSet, c.cliValue, c.option, c.config)
			if c.wantErrFor != "" {
				if err == nil {
					t.Fatalf("ResolveVerifyHostKeyDNS = %q, want an error", got)
				}
				invalid, ok := err.(InvalidVerifyHostKeyDNSValue)
				if !ok {
					t.Fatalf("error type = %T, want InvalidVerifyHostKeyDNSValue", err)
				}
				if invalid.Value != c.wantErrFor {
					t.Errorf("error reports %q, want %q", invalid.Value, c.wantErrFor)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveVerifyHostKeyDNS returned error %s", err)
			}
			if got != c.want {
				t.Errorf("ResolveVerifyHostKeyDNS = %q, want %q", got, c.want)
			}
		})
	}
}

// SSHFP is an optional, off-by-default verification: a DNS lookup must never
// delay a command by default, and it must only ever be a *refusal* signal, in
// addition to the known_hosts check.
func TestSSHFPEnforcement(t *testing.T) {
	cases := []struct {
		name   string
		verify VerifyHostKeyDNS
		status SSHFPStatus
		want   bool
	}{
		{"disabled never enforces", VerifyHostKeyDNSNo, SSHFPStatusMismatch, false},
		{"disabled does not enforce a match either", VerifyHostKeyDNSNo, SSHFPStatusVerified, false},
		{"yes rejects on mismatch", VerifyHostKeyDNSYes, SSHFPStatusMismatch, true},
		{"ask rejects on mismatch", VerifyHostKeyDNSAsk, SSHFPStatusMismatch, true},
		{"yes accepts on match", VerifyHostKeyDNSYes, SSHFPStatusVerified, false},
		{"yes stays soft without records", VerifyHostKeyDNSYes, SSHFPStatusNoRecords, false},
		{"yes stays soft on lookup failure", VerifyHostKeyDNSYes, SSHFPStatusLookupFailed, false},
		{"yes stays soft when not checked", VerifyHostKeyDNSYes, SSHFPStatusNotChecked, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SSHFPRejectsHost(c.verify, c.status); got != c.want {
				t.Errorf("SSHFPRejectsHost(%q, %s) = %v, want %v", c.verify, c.status, got, c.want)
			}
		})
	}
}

// A host that is only rejected by SSHFP must be reported as such, so that the
// caller can tell an SSHFP failure from a known_hosts failure.
func TestSSHFPRejectionError(t *testing.T) {
	err := SSHFPRejectionError("sshfp.example.org:443/ssh3-term")
	if err == nil {
		t.Fatal("SSHFPRejectionError returned nil")
	}
	if _, ok := err.(SSHFPMismatchError); !ok {
		t.Fatalf("error type = %T, want SSHFPMismatchError", err)
	}
	if got := err.Error(); got == "" {
		t.Error("error message is empty")
	}
}
