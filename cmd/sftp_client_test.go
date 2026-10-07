// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

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

	target, port, urlPath, err = parseRemoteTransferSpec("max@host/ssh3-term:remote.bin", 443, "/ssh3-term")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if target.hostname != "host" || target.urlPath != "/ssh3-term" || target.remotePath != "remote.bin" {
		t.Errorf("hybrid spec mismatch: %+v", target)
	}
}

func buildLocalTree(t *testing.T, root string, dirs, filesPerDir int) {
	t.Helper()
	for d := 0; d < dirs; d++ {
		dir := filepath.Join(root, "dir"+string(rune('a'+d)))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for f := 0; f < filesPerDir; f++ {
			name := filepath.Join(dir, "f"+string(rune('a'+f))+".dat")
			content := make([]byte, 64+d*16+f)
			for i := range content {
				content[i] = byte(i + d + f)
			}
			if err := os.WriteFile(name, content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func compareTrees(t *testing.T, wantRoot, gotRoot string) {
	t.Helper()
	err := filepath.WalkDir(wantRoot, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(wantRoot, current)
		if err != nil {
			return err
		}
		got := filepath.Join(gotRoot, rel)
		if entry.IsDir() {
			if info, err := os.Stat(got); err != nil || !info.IsDir() {
				t.Fatalf("missing dir %s in the transferred tree", got)
			}
			return nil
		}
		wantData, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		gotData, err := os.ReadFile(got)
		if err != nil {
			t.Fatalf("file %s did not arrive: %v", got, err)
		}
		if string(wantData) != string(gotData) {
			t.Fatalf("content mismatch in %s", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
}

// the pipes must be closed read-side-first for the client's receive loop to
// unwind (see internal_sftp_test.go)
func startTestSFTP(t *testing.T) (client *sftp.Client, serverRoot string, cleanup func()) {
	t.Helper()
	serverRoot = t.TempDir()
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- serveInternalSFTP(stdinR, stdoutW, serverRoot, 0, 0)
	}()
	sftpClient, err := sftp.NewClientPipe(stdoutR, stdinW)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}
	cleaned := false
	cleanup = func() {
		if cleaned {
			return
		}
		cleaned = true
		stdoutR.Close()
		stdinW.Close()
		sftpClient.Close()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serve did not finish")
		}
	}
	return sftpClient, serverRoot, cleanup
}

func TestRecursiveUploadDownloadRoundtrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	buildLocalTree(t, src, 4, 25)

	client, serverRoot, cleanup := startTestSFTP(t)
	defer cleanup()

	if code := uploadDir(client, src, "jt", false, false); code != 0 {
		t.Fatalf("uploadDir returned %d", code)
	}

	// every file must have landed in the jail namespace under jt/
	remoteRoot := filepath.Join(serverRoot, "jt")
	remoteFiles := 0
	err := filepath.WalkDir(remoteRoot, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			remoteFiles++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if remoteFiles != 100 {
		t.Fatalf("remote tree has %d files, want 100", remoteFiles)
	}

	dst := filepath.Join(t.TempDir(), "dst")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if code := downloadDir(client, "jt", dst, false, false); code != 0 {
		t.Fatalf("downloadDir returned %d", code)
	}
	// downloadDir maps the remote root onto the local root directly
	compareTrees(t, src, dst)

	// re-upload over the existing tree: the transfer path must tolerate
	// already present directories and files (O_TRUNC overwrite)
	if code := uploadDir(client, src, "jt", false, false); code != 0 {
		t.Fatalf("re-upload returned %d", code)
	}
}
