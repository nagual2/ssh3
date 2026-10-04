package cmd

// SSHFP host key verification (VerifyHostKeyDNS). The DNS machinery and the
// verdict rules live in the ssh3 package (sshfp.go); this file builds the
// resolver the CLI needs and turns a verdict into a connection decision.
//
// The resolver must always carry an explicit server list: on Windows
// SystemDNSServers() finds no /etc/resolv.conf and returns nil, and a resolver
// without servers would fall back to it, turn every lookup into a silent
// soft-fail and make VerifyHostKeyDNS=yes a no-op on that platform.

import (
	"context"
	"crypto/x509"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
)

// defaultSSHFPResolver returns the resolver used for the SSHFP lookup, or nil
// when no DNS server could be determined at all (in which case the check
// degrades to a documented soft pass rather than blocking the connection).
func defaultSSHFPResolver() ssh3.SSHFPResolver {
	servers := ssh3.SystemDNSServers()
	if len(servers) == 0 {
		servers = platformDNSServers()
	}
	if len(servers) == 0 {
		log.Debug().Msgf("no DNS server found, the SSHFP lookup will be skipped")
		return nil
	}
	return ssh3.UDPSSHFPResolver{Servers: servers, Timeout: ssh3.DefaultSSHFPTimeout}
}

// checkHostKeySSHFP runs the SSHFP verification for a presented host key. It
// returns the verdict for logging and an error when the connection must be
// refused.
//
// Only a mismatch is ever fatal: a host without records, an unreachable
// resolver or a timeout means the DNS signal is simply absent, and reading that
// as an attack would make every host without SSHFP records unusable.
func checkHostKeySSHFP(
	ctx context.Context,
	hostKey string,
	certificate *x509.Certificate,
	setting verifyHostKeyDNSSetting,
	strictHostKeyChecking ssh3.StrictHostKeyChecking,
) (ssh3.SSHFPResult, error) {
	if setting.Mode == ssh3.VerifyHostKeyDNSNo || certificate == nil {
		return ssh3.SSHFPResult{Status: ssh3.SSHFPStatusNotChecked}, nil
	}

	// "yes:rsa" restricts the verification to the listed host key algorithms:
	// anything else is simply not covered by the request.
	var algorithm *uint8
	if value, ok := ssh3.HostKeyAlgorithm(certificate); ok {
		algorithm = &value
	}
	if !setting.AllowsAlgorithm(algorithm) {
		log.Debug().Msgf("host key algorithm is not covered by the requested VerifyHostKeyDNS algorithm list, skipping the lookup")
		return ssh3.SSHFPResult{Status: ssh3.SSHFPStatusNotChecked}, nil
	}

	result := ssh3.CheckSSHFP(ctx, hostKey, certificate, defaultSSHFPResolver())
	logSSHFPResult(hostKey, result)

	if !ssh3.SSHFPRejectsHost(setting.Mode, result.Status) {
		return result, nil
	}

	// A mismatch with StrictHostKeyChecking=no is the explicitly allowed
	// insecure behaviour: warn loudly and continue, like the known_hosts check
	// does for a changed certificate.
	if strictHostKeyChecking == ssh3.StrictHostKeyCheckingNo {
		log.Warn().Msgf("SSHFP records for %s do not match the presented host key, continuing because StrictHostKeyChecking=no", hostKey)
		return result, nil
	}
	if setting.Mode == ssh3.VerifyHostKeyDNSAsk {
		// There is no interactive prompt here: a mismatch under "ask" is
		// refused, and the message names the override so the user is not stuck.
		log.Warn().Msgf("VerifyHostKeyDNS=ask cannot prompt here, the SSHFP mismatch is treated as a failure")
	}
	return result, ssh3.SSHFPRejectionError(hostKey)
}

// logSSHFPResult reports the verdict at the level that matches its meaning.
func logSSHFPResult(hostKey string, result ssh3.SSHFPResult) {
	switch result.Status {
	case ssh3.SSHFPStatusVerified:
		record := "record"
		if result.Matched != nil {
			record = result.Matched.String()
		}
		log.Info().Msgf("SSHFP verification of %s succeeded (%s)", hostKey, record)
	case ssh3.SSHFPStatusMismatch:
		log.Warn().Msgf("the SSHFP records published for %s do not match the presented host key", result.QueryName)
	case ssh3.SSHFPStatusLookupFailed:
		log.Debug().Msgf("could not look up the SSHFP records of %s: %s", result.QueryName, result.Err)
	case ssh3.SSHFPStatusNoRecords:
		log.Debug().Msgf("no SSHFP record is published for %s", result.QueryName)
	case ssh3.SSHFPStatusNotChecked:
	}
}

// describeVerifyHostKeyDNS renders the effective verification mode for the log
// line printed when the connection starts.
func describeVerifyHostKeyDNS(setting verifyHostKeyDNSSetting) string {
	description := string(setting.Mode)
	if len(setting.Algorithms) == 0 {
		return description
	}
	names := make([]string, 0, len(setting.Algorithms))
	for _, algorithm := range setting.Algorithms {
		names = append(names, sshfpAlgorithmName(algorithm))
	}
	return description + ":" + strings.Join(names, ",")
}

func sshfpAlgorithmName(algorithm uint8) string {
	for name, value := range sshfpAlgorithmsByName {
		if value == algorithm {
			return name
		}
	}
	for name, value := range sshfpDigestsByName {
		if value == algorithm {
			return name
		}
	}
	return "unknown"
}
