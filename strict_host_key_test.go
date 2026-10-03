package ssh3

// Unit tests for the StrictHostKeyChecking policy: value parsing (OpenSSH
// semantics) and the precedence between configuration sources.

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
