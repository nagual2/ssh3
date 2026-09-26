// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cmd

import "syscall"

// rootDiskUsage returns used/total bytes of the root filesystem.
func rootDiskUsage() (used, total uint64, ok bool) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err != nil {
		return 0, 0, false
	}
	total = fs.Blocks * uint64(fs.Bsize)
	used = total - fs.Bavail*uint64(fs.Bsize)
	return used, total, total > 0
}
