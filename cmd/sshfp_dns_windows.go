// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmd

// DNS server discovery on Windows. There is no /etc/resolv.conf, so
// SystemDNSServers() finds nothing and the SSHFP resolver would have to be
// given its servers explicitly. The list comes from the adapters of the
// machine, which is exactly what the Windows resolver itself uses.

import (
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
)

// initialDNSServersBufferSize is the size GetAdaptersAddresses is called with
// first: it is enough for a machine with a handful of adapters, and the API
// reports the required size when it is not.
const initialDNSServersBufferSize = 15 * 1024

// platformDNSServers returns the DNS server addresses configured on the local
// adapters, without any port. Duplicates are removed and the order is kept, so
// the list can be passed to a UDP resolver as is.
func platformDNSServers() []string {
	addresses, err := queryAdapterAddresses()
	if err != nil {
		log.Debug().Msgf("could not enumerate the network adapters: %s", err)
		return nil
	}

	seen := make(map[string]bool)
	servers := make([]string, 0, 4)
	for adapter := addresses; adapter != nil; adapter = adapter.Next {
		for server := adapter.FirstDnsServerAddress; server != nil; server = server.Next {
			ip := server.Address.IP()
			if ip == nil {
				continue
			}
			address := ip.String()
			if seen[address] {
				continue
			}
			seen[address] = true
			servers = append(servers, address)
		}
	}
	if len(servers) == 0 {
		log.Debug().Msgf("no DNS server is configured on the local adapters")
	}
	return servers
}

// queryAdapterAddresses calls GetAdaptersAddresses, growing the buffer until the
// call succeeds.
func queryAdapterAddresses() (*windows.IpAdapterAddresses, error) {
	size := uint32(initialDNSServersBufferSize)
	buffer := make([]byte, size)
	for attempt := 0; attempt < 4; attempt++ {
		addresses := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		// the DNS servers are exactly what this call is made for: neither
		// GAA_FLAG_SKIP_DNS_SERVER nor a unicast-only request may be set here
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_UNICAST|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST,
			0, addresses, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			buffer = make([]byte, size)
			continue
		}
		if err != nil {
			return nil, err
		}
		return addresses, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}
