package ssh3

import (
	"fmt"
	"strings"
)

// StrictHostKeyChecking mirrors the OpenSSH StrictHostKeyChecking option
// values on top of the ssh3 TOFU known_hosts mechanism (~/.ssh3/known_hosts).
type StrictHostKeyChecking string

const (
	// StrictHostKeyCheckingAsk is the default: for an unknown host presenting
	// a self-signed certificate, interactively prompt through the TOFU flow
	// (add to known_hosts or abort); in a non-terminal session, refuse.
	StrictHostKeyCheckingAsk StrictHostKeyChecking = "ask"
	// StrictHostKeyCheckingYes refuses any server whose certificate is not
	// verifiable and exactly pinned in known_hosts.
	StrictHostKeyCheckingYes StrictHostKeyChecking = "yes"
	// StrictHostKeyCheckingAcceptNew automatically pins an unknown host's
	// certificate on first use and continues, but refuses a host whose
	// certificate no longer matches the pinned one.
	StrictHostKeyCheckingAcceptNew StrictHostKeyChecking = "accept-new"
	// StrictHostKeyCheckingNo is the explicitly allowed insecure behaviour:
	// unknown hosts connect (and get pinned when possible), and a changed
	// certificate only produces a warning.
	StrictHostKeyCheckingNo StrictHostKeyChecking = "no"
)

// InvalidStrictHostKeyCheckingValue is returned for a value that is not part
// of the OpenSSH StrictHostKeyChecking value set.
type InvalidStrictHostKeyCheckingValue struct {
	Value string
}

func (e InvalidStrictHostKeyCheckingValue) Error() string {
	return fmt.Sprintf("invalid StrictHostKeyChecking value: %q (expected yes, accept-new, no or ask)", e.Value)
}

// ParseStrictHostKeyChecking parses a StrictHostKeyChecking value, following
// OpenSSH: the comparison is case-insensitive and the boolean aliases
// true/on and false/off are accepted for yes and no.
func ParseStrictHostKeyChecking(value string) (StrictHostKeyChecking, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "ask":
		return StrictHostKeyCheckingAsk, nil
	case "yes", "true", "on":
		return StrictHostKeyCheckingYes, nil
	case "no", "false", "off":
		return StrictHostKeyCheckingNo, nil
	case "accept-new":
		return StrictHostKeyCheckingAcceptNew, nil
	}
	return "", InvalidStrictHostKeyCheckingValue{Value: value}
}

// ResolveStrictHostKeyChecking applies the value precedence between the
// configuration sources: an explicit CLI flag wins over the -o option, which
// wins over the ~/.ssh/config keyword. Empty strings mean "source not set".
// The returned error reports the first invalid value found, whatever source
// it comes from.
func ResolveStrictHostKeyChecking(cliFlagSet bool, cliFlagValue string, optionValue string, configValue string) (StrictHostKeyChecking, error) {
	if cliFlagSet {
		return ParseStrictHostKeyChecking(cliFlagValue)
	}
	if optionValue != "" {
		return ParseStrictHostKeyChecking(optionValue)
	}
	if configValue != "" {
		return ParseStrictHostKeyChecking(configValue)
	}
	return StrictHostKeyCheckingAsk, nil
}
