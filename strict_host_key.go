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

// VerifyHostKeyDNS mirrors the OpenSSH VerifyHostKeyDNS option: it asks for the
// host key to be checked against the SSHFP records (RFC 4255) published in DNS.
//
// It is deliberately disabled by default: verifying it costs a DNS round-trip,
// and ssh3 is used as a command transport where every millisecond of latency
// counts. When enabled, it stays a strictly additional signal on top of the
// known_hosts check, never a replacement for it.
type VerifyHostKeyDNS string

const (
	// VerifyHostKeyDNSNo is the default: no SSHFP lookup is ever performed, so
	// no DNS traffic and no added latency.
	VerifyHostKeyDNSNo VerifyHostKeyDNS = "no"
	// VerifyHostKeyDNSAsk checks the SSHFP records when they are published.
	VerifyHostKeyDNSAsk VerifyHostKeyDNS = "ask"
	// VerifyHostKeyDNSYes checks the SSHFP records and requires one of them to
	// match the presented host key.
	VerifyHostKeyDNSYes VerifyHostKeyDNS = "yes"
)

// InvalidVerifyHostKeyDNSValue is returned for a value outside the OpenSSH
// VerifyHostKeyDNS value set.
type InvalidVerifyHostKeyDNSValue struct {
	Value string
}

func (e InvalidVerifyHostKeyDNSValue) Error() string {
	return fmt.Sprintf("invalid VerifyHostKeyDNS value: %q (expected yes, ask or no)", e.Value)
}

// ParseVerifyHostKeyDNS parses a VerifyHostKeyDNS value, following OpenSSH:
// the comparison is case-insensitive, the boolean aliases true/on and
// false/off are accepted, and an empty value means "not set" (hence off).
func ParseVerifyHostKeyDNS(value string) (VerifyHostKeyDNS, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "no", "false", "off":
		return VerifyHostKeyDNSNo, nil
	case "ask":
		return VerifyHostKeyDNSAsk, nil
	case "yes", "true", "on":
		return VerifyHostKeyDNSYes, nil
	}
	return "", InvalidVerifyHostKeyDNSValue{Value: value}
}

// ResolveVerifyHostKeyDNS applies the same source precedence as
// ResolveStrictHostKeyChecking: an explicit CLI flag wins over the -o option,
// which wins over the ~/.ssh/config keyword.
func ResolveVerifyHostKeyDNS(cliFlagSet bool, cliFlagValue string, optionValue string, configValue string) (VerifyHostKeyDNS, error) {
	if cliFlagSet {
		return ParseVerifyHostKeyDNS(cliFlagValue)
	}
	if optionValue != "" {
		return ParseVerifyHostKeyDNS(optionValue)
	}
	if configValue != "" {
		return ParseVerifyHostKeyDNS(configValue)
	}
	return VerifyHostKeyDNSNo, nil
}

// SSHFPRejectsHost decides whether an SSHFP verdict may veto a connection.
//
// The only refusing verdict is a mismatch on records that were actually
// published and fetched. No record published, no lookup performed, and every
// transport failure are soft: they say nothing about the host key, and refusing
// on them would break connections for hosts that simply do not publish SSHFP,
// or for a machine whose resolver is down. Note that even a mismatch only adds
// to the known_hosts decision: with StrictHostKeyChecking=no the caller keeps
// the explicitly insecure "warn and connect" behaviour.
func SSHFPRejectsHost(verify VerifyHostKeyDNS, status SSHFPStatus) bool {
	if verify == VerifyHostKeyDNSNo {
		return false
	}
	return status == SSHFPStatusMismatch
}

// SSHFPMismatchError reports a host refused because its presented key does not
// match any of the SSHFP records published for it.
type SSHFPMismatchError struct {
	HostKey string
}

func (e SSHFPMismatchError) Error() string {
	return fmt.Sprintf("the host key presented by %s does not match any of the SSHFP records published for it "+
		"(RFC 4255): this can be a machine-in-the-middle attack, or a stale SSHFP record. "+
		"If the change is legitimate, update the SSHFP records of the host, or connect again with "+
		"-o StrictHostKeyChecking=no to bypass the check.", e.HostKey)
}

// SSHFPRejectionError builds the error to report when an SSHFP mismatch is the
// reason a host is refused.
func SSHFPRejectionError(hostKey string) error {
	return SSHFPMismatchError{HostKey: hostKey}
}
