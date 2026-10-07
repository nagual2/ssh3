// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

// The internal sftp child: chroot/drop behavior, the chroot "/" namespace,
// and end-to-end serving over pipes. The full chroot confinement test
// re-execs the test binary as a child (a chroot is process-wide) and only
// runs under root; the unprivileged paths are covered directly.

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func TestResolveJailedChrootRootNamespace(t *testing.T) {
	// in the chroot child the served root is "/": every absolute spelling
	// lands inside the jail, there is nothing outside to escape to
	h := &sftpHandlers{root: string(filepath.Separator)}
	cases := map[string]string{
		"docs/f.txt":      `/docs/f.txt`,
		"/docs/f.txt":     `/docs/f.txt`,
		"":                `/`,
		"/":               `/`,
		"../../etc":       `/etc`,
		"/etc/passwd":     `/etc/passwd`,
		"/a/./b/../c.txt": `/a/c.txt`,
	}
	for in, want := range cases {
		got, err := h.resolveJailed(in)
		if err != nil {
			t.Fatalf("resolveJailed(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("resolveJailed(%q) = %q, want %q", in, got, want)
		}
	}
}

// a chroot request without root privileges must fail closed, not fall back
// to serving unjailed
func TestInternalSFTPChrootRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the fail-closed branch is unreachable")
	}
	if code := runInternalSFTPServer(t.TempDir(), "", 1000, 1000); code != 1 {
		t.Fatalf("chroot without root must exit 1, got %d", code)
	}
}

// serveInternalSFTP over pipes, driven by a real sftp client: the -sftp-root
// (unprivileged) mode maps client-relative paths under the root
func TestInternalSFTPServesOverPipes(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("ssh3"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}

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
		serveErr <- serveInternalSFTP(stdinR, stdoutW, root, 0, 0)
	}()

	client, err := sftp.NewClientPipe(stdoutR, stdinW)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}

	if _, err := client.Stat("hello.txt"); err != nil {
		t.Errorf("Stat(hello.txt): %v", err)
	}
	infos, err := client.ReadDir(".")
	if err != nil {
		t.Errorf("ReadDir(.): %v", err)
	} else if len(infos) != 2 {
		t.Errorf("ReadDir(.): got %d entries, want 2", len(infos))
	}
	remote, err := client.Create("dir/new.txt")
	if err != nil {
		t.Errorf("Create(dir/new.txt): %v", err)
	} else {
		if _, err := remote.Write([]byte("data")); err != nil {
			t.Errorf("write: %v", err)
		}
		remote.Close()
	}
	if _, err := client.Stat("dir/new.txt"); err != nil {
		t.Errorf("Stat(dir/new.txt): %v", err)
	}

	// teardown order matters: the client's receive loop only unwinds when
	// its read side hits EOF/error, and the server's Serve ends on stdin EOF
	stdoutR.Close()
	stdinW.Close()
	client.Close()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not finish after client close")
	}
}

// the chroot child is a separate process (a chroot is process-wide), so the
// root-mode confinement test re-execs the test binary
func TestMain(m *testing.M) {
	if dir := os.Getenv("TEST_SFTP_CHROOT_CHILD"); dir != "" {
		uid := parseEnvUint("TEST_SFTP_UID")
		gid := parseEnvUint("TEST_SFTP_GID")
		os.Exit(runInternalSFTPServer(dir, "", uid, gid))
	}
	os.Exit(m.Run())
}

func parseEnvUint(name string) uint64 {
	v := os.Getenv(name)
	var out uint64
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
		out = out*10 + uint64(c-'0')
	}
	return out
}

// inside a real chroot, a symlink pointing outside must be unresolvable —
// the kernel refuses the walk, no lexical check involved
func TestInternalSFTPChrootConfinesSymlinks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chroot requires root: run under sudo to exercise the kernel jail")
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("root-stuff"), 0o644); err != nil {
		t.Fatal(err)
	}
	jail := t.TempDir()
	if err := os.WriteFile(filepath.Join(jail, "inside.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(jail, "escape")); err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run", "TestMain$")
	cmd.Env = append(os.Environ(),
		"TEST_SFTP_CHROOT_CHILD="+jail,
		"TEST_SFTP_UID=0",
		"TEST_SFTP_GID=0",
	)
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin, cmd.Stdout = stdinR, stdoutW
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stdinR.Close()
	stdoutW.Close()

	client, err := sftp.NewClientPipe(stdoutR, stdinW)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}
	defer func() {
		// the client's receive loop needs its read side closed to unwind
		stdoutR.Close()
		stdinW.Close()
		client.Close()
		cmd.Wait()
	}()

	if _, err := client.Stat("inside.txt"); err != nil {
		t.Errorf("Stat(inside.txt): %v (a plain file inside the jail must work)", err)
	}
	if _, err := client.Stat("escape/secret"); err == nil {
		t.Error("Stat(escape/secret): the kernel jail must refuse a symlink walking outside")
	}
	if content, err := readRemoteFile(client, "inside.txt"); err != nil || content != "mine" {
		t.Errorf("read inside.txt = %q, %v", content, err)
	}
}

func readRemoteFile(client *sftp.Client, path string) (string, error) {
	f, err := client.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	return string(data), err
}
