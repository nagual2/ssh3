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

// signalExitCodes maps the wire signal names (no SIG prefix, like the SSH2
// exit-signal request carries) onto the conventional 128+signum client exit
// codes.
var signalExitCodes = map[string]int{
	"HUP":    129,
	"INT":    130,
	"QUIT":   131,
	"ILL":    132,
	"ABRT":   134,
	"FPE":    136,
	"KILL":   137,
	"SEGV":   139,
	"PIPE":   141,
	"ALRM":   142,
	"TERM":   143,
	"USR1":   138,
	"USR2":   140,
	"STOP":   149,
	"TSTP":   150,
	"CONT":   151,
	"CHLD":   152,
	"TTIN":   153,
	"TTOU":   154,
	"XCPU":   155,
	"XFSZ":   156,
	"VTALRM": 157,
	"PROF":   158,
	"WINCH":  159,
	"IO":     160,
	"POLL":   161,
	"PWR":    162,
	"SYS":    163,
}

// exitCodeForExitSignal converts an exit-signal request into the client
// process exit code: 128+signum for the known signals, the OpenSSH 255
// fallback otherwise.
func exitCodeForExitSignal(signalName string) int {
	if code, ok := signalExitCodes[signalName]; ok {
		return code
	}
	return 255
}
