// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package client

import (
	"net"
	"os"
)

// relaySlaveTTYEvents is a no-op on Windows: the control master itself is
// unsupported there, so no slave session ever runs (cmd/ssh3.go warns and
// falls back to a direct session).
func relaySlaveTTYEvents(control net.Conn, tty *os.File) (stop func()) {
	return func() {}
}
