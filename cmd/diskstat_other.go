// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package cmd

// rootDiskUsage is not implemented outside linux: stats show "unknown".
func rootDiskUsage() (used, total uint64, ok bool) {
	return 0, 0, false
}
