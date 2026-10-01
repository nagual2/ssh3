//go:build windows

package cmd

import "syscall"

// daemonSysProcAttr: Windows has no setsid; the control master is a
// separate track (CTO_TASK stage 3.5, portability).
func daemonSysProcAttr() *syscall.SysProcAttr {
	return nil
}
