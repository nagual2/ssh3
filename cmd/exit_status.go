// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// safeExitStatus converts an os/exec exit code into a wire-safe SSH3 exit
// status. A process that died by signal reports a negative exit code (-1),
// which after a uint64 conversion overflows the 62-bit QUIC varint and
// panicked the server in VarIntLen while encoding the exit-status request.
// OpenSSH sends an exit-signal request in this case; until that is
// implemented, 255 marks the abnormal termination.
//
// Pure mapping with no platform dependencies, so it lives outside the
// !windows server file and its unit test runs on every platform.
func safeExitStatus(exitCode int) uint64 {
	if exitCode < 0 {
		return 255
	}
	return uint64(exitCode)
}
