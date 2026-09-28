// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import "testing"

func TestIsRemoteTransferSpec(t *testing.T) {
	tests := []struct {
		operand string
		remote  bool
	}{
		{"max@127.0.0.1:18443/ssh3-test:fx-upload.bin", true},
		{"max@host:remote/file.bin", true},
		{"max@host:~/file.bin", true},
		{"max@host:443:file.bin", true},
		{"/tmp/ssh3-fx/payload.bin", false},
		{"payload.bin", false},
	}
	for _, test := range tests {
		if got := isRemoteTransferSpec(test.operand); got != test.remote {
			t.Errorf("isRemoteTransferSpec(%q) = %v, want %v", test.operand, got, test.remote)
		}
	}
}

func TestParseRemoteTransferSpec(t *testing.T) {
	target, port, urlPath, err := parseRemoteTransferSpec("max@127.0.0.1:18443/ssh3-test:fx-upload.bin", 443, "/ssh3-term")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if target.username != "max" || target.hostname != "127.0.0.1" {
		t.Errorf("user/host mismatch: %+v", target)
	}
	if target.remotePath != "fx-upload.bin" {
		t.Errorf("remote path: got %q", target.remotePath)
	}
	if port != 18443 || urlPath != "/ssh3-test" {
		t.Errorf("port/urlPath: got %d %q", port, urlPath)
	}
	if target.port != 18443 || target.urlPath != "/ssh3-test" {
		t.Errorf("target port/urlPath: got %d %q", target.port, target.urlPath)
	}

	target, port, urlPath, err = parseRemoteTransferSpec("max@host:remote/file.bin", 443, "/ssh3-term")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if target.hostname != "host" || target.remotePath != "remote/file.bin" {
		t.Errorf("simple spec mismatch: %+v", target)
	}
	if port != 443 || urlPath != "/ssh3-term" {
		t.Errorf("defaults not applied: %d %q", port, urlPath)
	}
}
