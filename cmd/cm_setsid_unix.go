//go:build !windows

package cmd

import "syscall"

// daemonSysProcAttr detaches the master from the invoking terminal's
// process group so it survives the parent shell.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
