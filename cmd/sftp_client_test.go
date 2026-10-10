// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"bytes"
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

// R7 helpers: the resume tests need same-size/different-content rewrites, so
// the skip decision cannot lean on the size alone.
func rewriteSameSize(t *testing.T, path string, seed byte) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	content := make([]byte, info.Size())
	for i := range content {
		content[i] = seed + byte(i)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ageLocalTree backdates every file's mtime so the transfer moment (which
// stamps freshly written remote files) can never collide with the source
// mtime within the same second.
func ageLocalTree(t *testing.T, root string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(age)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		return os.Chtimes(path, old, old)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readRemoteTreeFile(t *testing.T, client *sftp.Client, remotePath string) string {
	t.Helper()
	data, err := readRemoteFile(client, remotePath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// After an uploadDir the remote must carry the source's mtime: the --continue
// skip decision compares size+mtime, so an unstamped remote would be
// re-transferred forever (or, pre-R7, skipped on size alone).
func TestRecursiveUploadSetsRemoteMtime(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	buildLocalTree(t, src, 2, 3)
	ageLocalTree(t, src, -2*time.Hour)

	client, _, cleanup := startTestSFTP(t)
	defer cleanup()

	if code := uploadDir(client, src, "jt", false, false); code != 0 {
		t.Fatalf("uploadDir returned %d", code)
	}
	err := filepath.WalkDir(src, func(current string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, current)
		if err != nil {
			return err
		}
		localInfo, err := os.Stat(current)
		if err != nil {
			return err
		}
		remoteInfo, err := client.Stat(filepath.ToSlash(filepath.Join("jt", rel)))
		if err != nil {
			return err
		}
		if remoteInfo.ModTime().Unix() != localInfo.ModTime().Unix() {
			t.Errorf("remote mtime for %s: got %d, want %d (source mtime not stamped)", rel, remoteInfo.ModTime().Unix(), localInfo.ModTime().Unix())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Mirror image for downloads: the local copy must inherit the remote mtime.
func TestRecursiveDownloadSetsLocalMtime(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	buildLocalTree(t, src, 2, 3)
	ageLocalTree(t, src, -2*time.Hour)

	client, _, cleanup := startTestSFTP(t)
	defer cleanup()

	if code := uploadDir(client, src, "jt", false, false); code != 0 {
		t.Fatalf("uploadDir returned %d", code)
	}
	// a fresh remote file's write moment must not stand in for the stamped
	// mtime: without the pause a missing inheritance would hide inside the
	// same second
	time.Sleep(1100 * time.Millisecond)
	dst := filepath.Join(t.TempDir(), "dst")
	if code := downloadDir(client, "jt", dst, false, false); code != 0 {
		t.Fatalf("downloadDir returned %d", code)
	}
	err := filepath.WalkDir(src, func(current string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, current)
		if err != nil {
			return err
		}
		localInfo, err := os.Stat(filepath.Join(dst, rel))
		if err != nil {
			return err
		}
		remoteInfo, err := client.Stat(filepath.ToSlash(filepath.Join("jt", rel)))
		if err != nil {
			return err
		}
		if localInfo.ModTime().Unix() != remoteInfo.ModTime().Unix() {
			t.Errorf("local mtime for %s: got %d, want %d (remote mtime not inherited)", rel, localInfo.ModTime().Unix(), remoteInfo.ModTime().Unix())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// An unchanged tree must keep skipping under --continue (regression guard
// for the size+mtime decision).
func TestRecursiveUploadResumeSkipsUnchanged(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	buildLocalTree(t, src, 2, 3)

	client, _, cleanup := startTestSFTP(t)
	defer cleanup()

	if code := uploadDir(client, src, "jt", false, false); code != 0 {
		t.Fatalf("uploadDir returned %d", code)
	}
	snapshot := readRemoteTreeFile(t, client, "jt/dira/fa.dat")
	if code := uploadDir(client, src, "jt", true, false); code != 0 {
		t.Fatalf("resume uploadDir returned %d", code)
	}
	if got := readRemoteTreeFile(t, client, "jt/dira/fa.dat"); got != snapshot {
		t.Error("unchanged tree was not left intact by --continue")
	}
}

// The R7 core: a source file rewritten in place (same size, new mtime) must
// be re-transferred under --continue instead of being skipped by size alone.
func TestRecursiveUploadResumeRetransfersChangedFile(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	buildLocalTree(t, src, 2, 3)
	ageLocalTree(t, src, -2*time.Hour)

	client, _, cleanup := startTestSFTP(t)
	defer cleanup()

	if code := uploadDir(client, src, "jt", false, false); code != 0 {
		t.Fatalf("uploadDir returned %d", code)
	}
	target := filepath.Join(src, "dira", "fa.dat")
	rewriteSameSize(t, target, 0xC7)

	// the rewrite bumped the local mtime: --continue must notice the
	// mismatch and re-transfer
	if code := uploadDir(client, src, "jt", true, false); code != 0 {
		t.Fatalf("resume uploadDir returned %d", code)
	}
	localData, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := readRemoteTreeFile(t, client, "jt/dira/fa.dat"); got != string(localData) {
		t.Error("changed file was skipped by --continue: remote kept the stale content")
	}
}

// Downloads mirror the upload rule: a remote file rewritten in place (same
// size, new mtime) must re-transfer into an unchanged-size local copy.
func TestRecursiveDownloadResumeRetransfersChangedRemote(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	buildLocalTree(t, src, 2, 3)
	ageLocalTree(t, src, -2*time.Hour)

	client, _, cleanup := startTestSFTP(t)
	defer cleanup()

	if code := uploadDir(client, src, "jt", false, false); code != 0 {
		t.Fatalf("uploadDir returned %d", code)
	}
	dst := filepath.Join(t.TempDir(), "dst")
	if code := downloadDir(client, "jt", dst, false, false); code != 0 {
		t.Fatalf("downloadDir returned %d", code)
	}

	remotePath := "jt/dira/fa.dat"
	// the in-place rewrite must keep the size: only the mtime may betray it
	rewritten := bytes.Repeat([]byte{'R'}, 64)
	remoteFile, err := client.OpenFile(remotePath, os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remoteFile.Write(rewritten); err != nil {
		t.Fatal(err)
	}
	if err := remoteFile.Close(); err != nil {
		t.Fatal(err)
	}
	remoteInfo, err := client.Stat(remotePath)
	if err != nil {
		t.Fatal(err)
	}
	if remoteInfo.Size() != 64 {
		t.Fatalf("test setup: remote rewrite kept size %d, want 64", remoteInfo.Size())
	}

	if code := downloadDir(client, "jt", dst, true, false); code != 0 {
		t.Fatalf("resume downloadDir returned %d", code)
	}
	localData, err := os.ReadFile(filepath.Join(dst, "dira", "fa.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(localData, rewritten) {
		t.Error("changed remote file was skipped by --continue: local kept the stale content")
	}
}

// The single-file paths share the resume decision with the tree paths; R7
// must hold there too — an in-place rewrite (same size, new mtime) is
// re-transferred, not skipped.
func TestSingleFileUploadResumeRetransfersChangedFile(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "one.dat")
	if err := os.WriteFile(local, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	ageLocalTree(t, dir, -2*time.Hour)

	client, _, cleanup := startTestSFTP(t)
	defer cleanup()

	if code := uploadFile(client, local, "one.dat", false, false); code != 0 {
		t.Fatalf("uploadFile returned %d", code)
	}
	remoteInfo, err := client.Stat("one.dat")
	if err != nil {
		t.Fatal(err)
	}
	localInfo, err := os.Stat(local)
	if err != nil {
		t.Fatal(err)
	}
	if remoteInfo.ModTime().Unix() != localInfo.ModTime().Unix() {
		t.Error("single-file upload did not stamp the remote mtime")
	}

	rewriteSameSize(t, local, 0x5A)
	if code := uploadFile(client, local, "one.dat", true, false); code != 0 {
		t.Fatalf("resume uploadFile returned %d", code)
	}
	want, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	if got := readRemoteTreeFile(t, client, "one.dat"); got != string(want) {
		t.Error("changed file was skipped by --continue: remote kept the stale content")
	}
}

func TestSingleFileDownloadResumeRetransfersChangedRemote(t *testing.T) {
	local := filepath.Join(t.TempDir(), "one.dat")
	if err := os.WriteFile(local, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	client, _, cleanup := startTestSFTP(t)
	defer cleanup()

	seedRemote := func(payload string) {
		t.Helper()
		remoteFile, err := client.OpenFile("one.dat", os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := remoteFile.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		if err := remoteFile.Close(); err != nil {
			t.Fatal(err)
		}
	}

	seedRemote("0123456789")
	if code := downloadFile(client, "one.dat", local, false, false); code != 0 {
		t.Fatalf("downloadFile returned %d", code)
	}
	if info, err := os.Stat(local); err != nil {
		t.Fatal(err)
	} else if remoteInfo, err := client.Stat("one.dat"); err != nil {
		t.Fatal(err)
	} else if info.ModTime().Unix() != remoteInfo.ModTime().Unix() {
		t.Error("single-file download did not inherit the remote mtime")
	}

	// the rewrite lands at least a second after the seed, so the inherited
	// local mtime cannot accidentally match the new remote one
	time.Sleep(1100 * time.Millisecond)
	seedRemote("9876543210")
	if code := downloadFile(client, "one.dat", local, true, false); code != 0 {
		t.Fatalf("resume downloadFile returned %d", code)
	}
	localData, err := os.ReadFile(local)
	if err != nil {
		t.Fatal(err)
	}
	if string(localData) != "9876543210" {
		t.Error("changed remote file was skipped by --continue: local kept the stale content")
	}
}
