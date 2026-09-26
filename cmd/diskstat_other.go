//go:build !linux

package cmd

// rootDiskUsage is not implemented outside linux: stats show "unknown".
func rootDiskUsage() (used, total uint64, ok bool) {
	return 0, 0, false
}
