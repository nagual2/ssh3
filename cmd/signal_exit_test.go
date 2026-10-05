//go:build !windows

// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// The exit-signal reporting: a remote process that died by signal must map
// onto the RFC 4254 section 6.10 exit-signal request (server side) and the
// 128+signum client convention (client side).

import (
	"os/exec"
	"testing"
)

func TestExitCodeForExitSignal(t *testing.T) {
	for _, tc := range []struct {
		signal string
		want   int
	}{
		{"SEGV", 139},
		{"TERM", 143},
		{"KILL", 137},
		{"INT", 130},
		{"HUP", 129},
	} {
		if got := exitCodeForExitSignal(tc.signal); got != tc.want {
			t.Errorf("exitCodeForExitSignal(%q) = %d, want %d", tc.signal, got, tc.want)
		}
	}

	// an unknown signal name cannot map: the OpenSSH fallback is 255
	if got := exitCodeForExitSignal("NOSUCH"); got != 255 {
		t.Errorf("exitCodeForExitSignal(\"NOSUCH\") = %d, want 255", got)
	}
}

func TestSignalExitDetectsSignalDeath(t *testing.T) {
	// a real child killed by an uncatchable signal (SIGKILL never dumps core)
	cmd := exec.Command("sh", "-c", "kill -KILL $$")
	err := cmd.Run()
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("want an ExitError, got %v", err)
	}

	name, coreDumped, signaled := signalExit(exitError)
	if !signaled {
		t.Fatal("the child died by signal, signalExit must report it")
	}

	if name != "KILL" {
		t.Errorf("signal name = %q, want KILL", name)
	}

	if coreDumped {
		t.Error("SIGKILL cannot dump core, coreDumped = true")
	}
}

func TestSignalExitIgnoresPlainExit(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 3")
	err := cmd.Run()
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("want an ExitError, got %v", err)
	}

	if _, _, signaled := signalExit(exitError); signaled {
		t.Error("a normal exit must not be reported as a signal death")
	}
}
