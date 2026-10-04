// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

// DNS server discovery outside Windows: /etc/resolv.conf is the single source
// of truth and SystemDNSServers() already reads it, so there is nothing to
// discover here.

func platformDNSServers() []string { return nil }
