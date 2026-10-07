// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

// The internal sftp server child, the sshd internal-sftp model transposed to
// a re-exec (Go has no fork): the network-facing server never touches user
// paths — it spawns this binary, the child chroots into the user's home and
// drops to the user's uid/gid before the first path is opened, then serves
// sftp over stdin/stdout. After the chroot, path confinement is the
// kernel's: absolute symlinks and ".." cannot reach outside the jail, so no
// lexical check is load-bearing anymore.
//
// The child never escalates: the chroot/drop only runs when already root,
// and a child started by hand without privileges serves with its own
// identity or exits.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/pkg/sftp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// runInternalSFTPServer is the -sftp-server-internal entrypoint. chrootDir
// non-empty selects the chroot jail (root becomes "/"); otherwise rootDir is
// the served root (the -sftp-root unprivileged mode). The return value is
// the child's exit code.
func runInternalSFTPServer(chrootDir, rootDir string, uid, gid uint64) int {
	// the child logs to the server's stderr; keep it quiet by default
	if os.Getenv("SSH3_SFTP_DEBUG") == "" {
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	}

	root := rootDir
	if chrootDir != "" {
		if os.Geteuid() != 0 {
			// fail closed: the caller asked for the chroot jail (a root
			// server does); serving root-owned paths unjailed is exactly the
			// bug class this design removes
			log.Error().Msg("-sftp-chroot requires running as root")
			return 1
		}
		if err := applyChrootAndDrop(chrootDir, uid, gid); err != nil {
			log.Error().Msgf("sftp subsystem: chroot/drop: %s", err)
			return 1
		}
		root = string(filepath.Separator)
	} else if rootDir == "" {
		log.Error().Msg("internal sftp server needs -sftp-chroot or -sftp-root")
		return 1
	}

	if err := serveInternalSFTP(os.Stdin, os.Stdout, root, uid, gid); err != nil {
		log.Error().Msgf("sftp subsystem: serve: %s", err)
		return 1
	}
	return 0
}

// serveInternalSFTP serves sftp over the given streams, rooted at root.
func serveInternalSFTP(stdin io.Reader, stdout io.Writer, root string, uid, gid uint64) error {
	handlers, err := newSFTPHandlers(root, uid, gid)
	if err != nil {
		return err
	}
	rwc := struct {
		io.Reader
		io.WriteCloser
	}{stdin, nopWriteCloser{stdout}}
	server := sftp.NewRequestServer(rwc, sftp.Handlers{
		FileGet:  handlers,
		FilePut:  handlers,
		FileCmd:  handlers,
		FileList: handlers,
	})
	defer func() {
		if err := server.Close(); err != nil {
			log.Debug().Msgf("sftp subsystem: server close: %s", err)
		}
	}()
	if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// applyChrootAndDrop chroots into dir and drops to uid/gid, in that order:
// the chroot needs the privileges, the drop must remove them before any
// path is served. Supplementary groups are cleared (least privilege; sshd
// would initgroups instead — a known divergence, matching how the exec
// sessions drop privileges).
func applyChrootAndDrop(dir string, uid, gid uint64) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	// the sshd rule, adapted: the jail root must not be group/world-writable
	// (another user must not be able to plant content in it). A user-owned
	// root is fine here: after the drop nothing privileged remains inside.
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group/world-writable, refusing to chroot into it", dir)
	}
	if err := syscall.Chdir(dir); err != nil {
		return err
	}
	if err := syscall.Chroot(dir); err != nil {
		return err
	}
	if err := syscall.Chdir(string(filepath.Separator)); err != nil {
		return err
	}
	if os.Getuid() == 0 && (uid != 0 || gid != 0) {
		if err := syscall.Setgroups([]int{}); err != nil {
			return err
		}
		if err := syscall.Setgid(int(gid)); err != nil {
			return err
		}
		if err := syscall.Setuid(int(uid)); err != nil {
			return err
		}
	}
	return nil
}

// nopWriteCloser adapts a Writer to a WriteCloser with a no-op Close (the
// child's stdout is the parent's pipe; closing it here is not ours to do).
type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }
