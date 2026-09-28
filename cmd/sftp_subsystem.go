// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/util/unix_util"
	"github.com/pkg/sftp"
	"github.com/rs/zerolog/log"
)

// File-transfer subsystem: serves pkg/sftp over an ssh3 channel, jailed to
// the session user's home directory. The server process may run as root, so
// every path is resolved inside the jail and every created inode is chowned
// back to the user.

// SFTP v3 open flags (private in pkg/sftp; SSH_FXF_* from the wire spec).
const (
	sftpFlagRead    = 0x00000001
	sftpFlagWrite   = 0x00000002
	sftpFlagAppend  = 0x00000004
	sftpFlagCreate  = 0x00000008
	sftpFlagTrunc   = 0x00000010
	sftpFlagExpires = 0x00000020 // SSH_FXF_EXCL; unused here
)

type sftpHandlers struct {
	user *unix_util.User
	root string
}

func newSFTPHandlers(user *unix_util.User) (*sftpHandlers, error) {
	if user.Dir == "" {
		return nil, fmt.Errorf("user %s has no home directory", user.Username)
	}
	absRoot, err := filepath.Abs(user.Dir)
	if err != nil {
		return nil, err
	}
	return &sftpHandlers{user: user, root: absRoot}, nil
}

// serveSFTPSubsystem runs for the whole lifetime of an "sftp" channel; it
// must be spawned as its own goroutine and must not touch runningSessions,
// since closing the channel ends only this transfer, not the conversation.
func serveSFTPSubsystem(user *unix_util.User, channel ssh3.Channel) {
	handlers, err := newSFTPHandlers(user)
	if err != nil {
		log.Error().Msgf("sftp subsystem: %s", err)
		channel.Close()
		return
	}
	rwc := ssh3.NewChannelReadWriteCloser(channel)
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
		channel.Close()
	}()
	if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
		log.Info().Msgf("sftp subsystem ended on channel %d: %s", channel.ChannelID(), err)
	}
}

// resolveJailed maps a client-visible path into the jail, rejecting escapes.
func (h *sftpHandlers) resolveJailed(clientPath string) (string, error) {
	trimmed := strings.TrimSpace(clientPath)
	if trimmed == "" {
		trimmed = "/"
	}
	clean := path.Clean("/" + trimmed)
	full := filepath.Join(h.root, filepath.FromSlash(clean))
	if full != h.root && !strings.HasPrefix(full, h.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the home directory", clientPath)
	}
	return full, nil
}

func (h *sftpHandlers) chownToUser(name string) {
	if err := os.Chown(name, int(h.user.Uid), int(h.user.Gid)); err != nil {
		log.Debug().Msgf("sftp subsystem: chown %s: %s", name, err)
	}
}

// chownToUserRoot fixes ownership of freshly created directories under the
// jail (MkdirAll may create more than one level).
func (h *sftpHandlers) chownToUserRoot(name string) {
	for current := name; current != h.root && strings.HasPrefix(current, h.root+string(filepath.Separator)); current = filepath.Dir(current) {
		h.chownToUser(current)
	}
}

func (h *sftpHandlers) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	name, err := h.resolveJailed(request.Filepath)
	if err != nil {
		return nil, err
	}
	return os.Open(name)
}

func (h *sftpHandlers) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	name, err := h.resolveJailed(request.Filepath)
	if err != nil {
		return nil, err
	}
	flags := os.O_WRONLY
	if request.Flags&sftpFlagCreate != 0 {
		flags |= os.O_CREATE
	}
	if request.Flags&sftpFlagTrunc != 0 {
		flags |= os.O_TRUNC
	}
	file, err := os.OpenFile(name, flags, 0o644)
	if err != nil {
		return nil, err
	}
	if flags&os.O_CREATE != 0 {
		h.chownToUser(name)
	}
	return file, nil
}

func (h *sftpHandlers) Filecmd(request *sftp.Request) error {
	switch request.Method {
	case "Mkdir":
		return h.mkdir(request)
	case "Rename":
		return h.rename(request)
	case "Remove":
		return h.remove(request)
	case "Rmdir":
		return h.rmdir(request)
	case "Link":
		return h.link(request, false)
	case "Symlink":
		return h.link(request, true)
	default:
		// Setstat and friends arrive as raw attribute blobs; the Go client
		// does not rely on them, so they stay unsupported until needed
		return sftp.ErrSSHFxOpUnsupported
	}
}

func (h *sftpHandlers) mkdir(request *sftp.Request) error {
	name, err := h.resolveJailed(request.Filepath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(name, 0o755); err != nil {
		return err
	}
	h.chownToUserRoot(name)
	return nil
}

func (h *sftpHandlers) rename(request *sftp.Request) error {
	oldName, err := h.resolveJailed(request.Filepath)
	if err != nil {
		return err
	}
	newName, err := h.resolveJailed(request.Target)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(newName); err == nil {
		return os.ErrExist
	}
	return os.Rename(oldName, newName)
}

func (h *sftpHandlers) remove(request *sftp.Request) error {
	name, err := h.resolveJailed(request.Filepath)
	if err != nil {
		return err
	}
	return os.Remove(name)
}

func (h *sftpHandlers) rmdir(request *sftp.Request) error {
	name, err := h.resolveJailed(request.Filepath)
	if err != nil {
		return err
	}
	return os.Remove(name)
}

func (h *sftpHandlers) link(request *sftp.Request, symbolic bool) error {
	target, err := h.resolveJailed(request.Filepath)
	if err != nil {
		return err
	}
	linkPath, err := h.resolveJailed(request.Target)
	if err != nil {
		return err
	}
	if symbolic {
		return os.Symlink(target, linkPath)
	}
	return os.Link(target, linkPath)
}

func (h *sftpHandlers) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	switch request.Method {
	case "List":
		name, err := h.resolveJailed(request.Filepath)
		if err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(name)
		if err != nil {
			return nil, err
		}
		infos := make([]fs.FileInfo, 0, len(entries)+1)
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			infos = append(infos, fileInfoNamed{FileInfo: info, name: entry.Name()})
		}
		return &listerAt{infos: infos}, nil
	case "Stat":
		name, err := h.resolveJailed(request.Filepath)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(name)
		if err != nil {
			return nil, err
		}
		return &listerAt{infos: []fs.FileInfo{info}}, nil
	case "Readlink":
		name, err := h.resolveJailed(request.Filepath)
		if err != nil {
			return nil, err
		}
		target, err := os.Readlink(name)
		if err != nil {
			return nil, err
		}
		return &listerAt{infos: []fs.FileInfo{fileInfoNamed{FileInfo: trivialInfo{mode: fs.ModeSymlink}, name: target}}}, nil
	default:
		return nil, sftp.ErrSSHFxOpUnsupported
	}
}

// listerAt serves directory entries one window at a time, as pkg/sftp expects.
type listerAt struct {
	infos []fs.FileInfo
}

func (l *listerAt) ListAt(buf []fs.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l.infos)) {
		return 0, io.EOF
	}
	n := copy(buf, l.infos[offset:])
	if offset+int64(n) < int64(len(l.infos)) {
		return n, nil
	}
	return n, io.EOF
}

// fileInfoNamed renames a FileInfo so List reports the entry name, not the
// one from os.Stat of the parent.
type fileInfoNamed struct {
	fs.FileInfo
	name string
}

func (f fileInfoNamed) Name() string { return f.name }

// trivialInfo backs Readlink responses, which only need a mode and a name.
type trivialInfo struct {
	mode fs.FileMode
}

func (t trivialInfo) Name() string       { return "" }
func (t trivialInfo) Size() int64        { return 0 }
func (t trivialInfo) Mode() fs.FileMode  { return t.mode }
func (t trivialInfo) ModTime() time.Time { return time.Time{} }
func (t trivialInfo) IsDir() bool        { return false }
func (t trivialInfo) Sys() any           { return nil }
