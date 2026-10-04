package cmd

import (
	"net"
	"testing"

	"github.com/francoismichel/ssh3"
)

// The SSHFP resolver must never be built without an explicit server list: on
// Windows SystemDNSServers() finds no /etc/resolv.conf, and a resolver with no
// servers would fall back to it, turn the lookup into a silent soft-fail and
// make VerifyHostKeyDNS=yes a no-op.
func TestDefaultSSHFPResolverAlwaysCarriesServers(t *testing.T) {
	resolver := defaultSSHFPResolver()
	systemServers := ssh3.SystemDNSServers()
	platformServers := platformDNSServers()

	if len(systemServers) == 0 && len(platformServers) == 0 {
		if resolver != nil {
			t.Fatalf("defaultSSHFPResolver() = %+v, want nil when no DNS server exists", resolver)
		}
		return
	}
	if resolver == nil {
		t.Fatalf("defaultSSHFPResolver() = nil although %d system and %d platform DNS servers exist",
			len(systemServers), len(platformServers))
	}

	udpResolver, ok := resolver.(ssh3.UDPSSHFPResolver)
	if !ok {
		t.Fatalf("defaultSSHFPResolver() returned %T, want an ssh3.UDPSSHFPResolver", resolver)
	}
	if len(udpResolver.Servers) == 0 {
		t.Error("the SSHFP resolver has no DNS server, the lookup would always soft-fail")
	}
	if udpResolver.Timeout != ssh3.DefaultSSHFPTimeout {
		t.Errorf("resolver timeout = %s, want %s", udpResolver.Timeout, ssh3.DefaultSSHFPTimeout)
	}
}

// Whatever platformDNSServers reports has to be usable by the UDP resolver,
// which is what rules out a malformed or port-carrying address.
func TestPlatformDNSServersArePlainAddresses(t *testing.T) {
	for _, server := range platformDNSServers() {
		if net.ParseIP(server) == nil {
			t.Errorf("platformDNSServers() returned %q, which is not an IP address", server)
		}
	}
}
