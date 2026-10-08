// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The forward-target policy, the PermitOpen analog (F-05): server-side
// TCP/UDP/dynamic forwarding used to dial any client-chosen target with the
// process's own privileges, turning an authenticated account into an SSRF
// and port-scanning pivot. -permit-open / SSH3_PERMIT_OPEN bounds it with
// sshd_config PermitOpen semantics:
//
//	permit-open="host:port"     exact host (or IP) and port
//	permit-open="*.example.org:443"  wildcard host, exact port
//	permit-open="host:*"        any port
//	permit-open="!host:port"    negated entry: always denied
//
// An empty spec (the default) keeps the historical unrestricted behavior;
// this matches OpenSSH, where PermitOpen unset means no restriction.

import (
	"fmt"
	"strconv"
	"strings"
)

type forwardTarget struct {
	host    string
	port    string // "*" or a decimal port
	negated bool
}

// forwardPolicy is nil when unrestricted; the zero value denies everything
// that does not match an allow entry.
type forwardPolicy struct {
	entries []forwardTarget
}

var permitOpen *forwardPolicy

// permitListen is the reverse-forward counterpart (S2-04): it bounds the
// binds the client-requested -R listeners take on the server, with the
// same sshd_config PermitListen semantics. nil (empty spec, the default)
// keeps the historical unrestricted behavior.
var permitListen *forwardPolicy

// parsePermitOpen parses a comma/space-separated PermitOpen spec.
func parsePermitOpen(spec string) (*forwardPolicy, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	policy := &forwardPolicy{}
	for _, field := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		entry := forwardTarget{}
		rest := field
		if strings.HasPrefix(rest, "!") {
			entry.negated = true
			rest = rest[1:]
		}
		host, port, ok := strings.Cut(rest, ":")
		if !ok || host == "" || port == "" {
			return nil, fmt.Errorf("invalid -permit-open entry %q: want host:port", field)
		}
		if port != "*" {
			if _, err := strconv.ParseUint(port, 10, 16); err != nil {
				return nil, fmt.Errorf("invalid -permit-open entry %q: %w", field, err)
			}
		}
		entry.host = strings.ToLower(host)
		entry.port = port
		policy.entries = append(policy.entries, entry)
	}
	return policy, nil
}

// allows reports whether a dial to host:port may proceed.
func (p *forwardPolicy) allows(host string, port int) bool {
	if p == nil {
		return true
	}
	host = strings.ToLower(host)
	portStr := strconv.Itoa(port)
	allowed := false
	matched := false
	for _, entry := range p.entries {
		if !matchForwardHost(host, entry.host) || (entry.port != "*" && entry.port != portStr) {
			continue
		}
		matched = true
		if entry.negated {
			return false
		}
		allowed = true
	}
	if !matched {
		// with only negated entries, everything not negated is allowed
		allowed = !hasAllowEntry(p.entries)
	}
	return allowed
}

func hasAllowEntry(entries []forwardTarget) bool {
	for _, entry := range entries {
		if !entry.negated {
			return true
		}
	}
	return false
}

func matchForwardHost(host, pattern string) bool {
	if pattern == "*" || pattern == host {
		return true
	}
	// leading wildcard: "*.example.org" matches "a.b.example.org" but not
	// "example.org" itself (sshd_config PATTERNS semantics)
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return false
}

// checkForwardTarget is the single gate for every server-side dial.
func checkForwardTarget(kind, host string, port int) error {
	if !permitOpen.allows(host, port) {
		return fmt.Errorf("%s forwarding to %s:%d denied by -permit-open policy", kind, host, port)
	}
	return nil
}

// checkListenTarget is the single gate for every server-side bind a reverse
// forward (-R) requests. Unlike dials, a bind occupies a server port: the
// gate runs on the post-GatewayPorts address, the one actually bound.
func checkListenTarget(kind, host string, port int) error {
	if !permitListen.allows(host, port) {
		return fmt.Errorf("%s listen on %s:%d denied by -permit-listen policy", kind, host, port)
	}
	return nil
}
