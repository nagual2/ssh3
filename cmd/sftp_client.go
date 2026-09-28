// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/francoismichel/ssh3"
	client "github.com/francoismichel/ssh3/client"
	"github.com/pkg/sftp"
	"github.com/rs/zerolog/log"
)

// Client side of the file-transfer mode: `ssh3 -f SRC DST` with exactly one
// scp-style operand `user@host:remote_path`; the other operand is local.

type transferTarget struct {
	username   string
	hostname   string
	remotePath string
	port       int
	urlPath    string
}

func isRemoteTransferSpec(operand string) bool {
	// a remote operand always carries a user part ("user@host:remote_path"):
	// the transfer client needs an explicit username, and requiring "@"
	// keeps local paths (including Windows "C:\..." ones) unambiguous
	at := strings.Index(operand, "@")
	if at <= 0 {
		return false
	}
	return strings.Contains(operand[at:], ":")
}

func digitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, symbol := range value {
		if symbol < '0' || symbol > '9' {
			return false
		}
	}
	return true
}

// parseRemoteTransferSpec accepts "user@host:remote_path" and the explicit
// "user@host:port/url_path:remote_path" form; returns the target with the
// effective port and URL path.
func parseRemoteTransferSpec(spec string, defaultPort int, defaultURLPath string) (transferTarget, int, string, error) {
	target := transferTarget{port: defaultPort, urlPath: defaultURLPath}
	hostnamePart := spec
	if at := strings.Index(hostnamePart, "@"); at >= 0 {
		target.username = hostnamePart[:at]
		hostnamePart = hostnamePart[at+1:]
	}
	parts := strings.Split(hostnamePart, ":")
	if len(parts) < 2 || parts[0] == "" {
		return target, defaultPort, defaultURLPath, fmt.Errorf("%q is not a remote operand (expected user@host:remote_path)", spec)
	}
	target.hostname = parts[0]
	if len(parts) == 2 {
		target.remotePath = parts[1]
	} else if len(parts) == 3 {
		portPart, urlRest, found := strings.Cut(parts[1], "/")
		if !digitsOnly(portPart) {
			return target, defaultPort, defaultURLPath, fmt.Errorf("%q has an invalid port %q", spec, portPart)
		}
		target.port = atoi(portPart, defaultPort)
		target.urlPath = defaultURLPath
		if found {
			target.urlPath = "/" + urlRest
		}
		target.remotePath = parts[2]
	} else {
		return target, defaultPort, defaultURLPath, fmt.Errorf("%q has too many ':' separators", spec)
	}
	if target.remotePath == "" {
		return target, defaultPort, defaultURLPath, fmt.Errorf("%q is missing the remote path", spec)
	}
	return target, target.port, target.urlPath, nil
}

func atoi(value string, fallback int) int {
	number := 0
	for _, symbol := range value {
		number = number*10 + int(symbol-'0')
	}
	if number == 0 {
		return fallback
	}
	return number
}

// buildTransferURL assembles the connection URL for a transfer target, with
// the port and URL path resolved from the operand (or -P/-U defaults).
func buildTransferURL(target transferTarget) *url.URL {
	return &url.URL{
		Scheme: "https",
		User:   url.User(target.username),
		Host:   fmt.Sprintf("%s:%d", target.hostname, target.port),
		Path:   target.urlPath,
	}
}

// runFileTransfer performs one upload or download over a dedicated "sftp"
// channel of an already authenticated client.
func runFileTransfer(client *client.Client, target transferTarget, localPath string, upload bool, recursive bool) int {
	channel, err := client.OpenChannel(sftpChannelType, 30000, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open sftp channel: %+v\n", err)
		return -1
	}
	rwc := ssh3.NewChannelReadWriteCloser(channel)
	sftpClient, err := sftp.NewClientPipe(rwc, rwc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not start sftp client: %+v\n", err)
		channel.Close()
		return -1
	}
	defer func() {
		if err := sftpClient.Close(); err != nil {
			log.Debug().Msgf("sftp client close: %s", err)
		}
	}()

	remotePath := target.remotePath
	if upload {
		if recursive {
			return uploadDir(sftpClient, localPath, remotePath)
		}
		return uploadFile(sftpClient, localPath, remotePath)
	}
	if recursive {
		return downloadDir(sftpClient, remotePath, localPath)
	}
	return downloadFile(sftpClient, remotePath, localPath)
}

// sftpMkdirAll creates remote directories level by level (pkg/sftp Mkdir is
// single-level) and tolerates existing ones.
func sftpMkdirAll(sftpClient *sftp.Client, remoteDir string) error {
	current := ""
	for _, segment := range strings.Split(path.Clean(remoteDir), "/") {
		if segment == "" {
			current = "/"
			continue
		}
		current = path.Join(current, segment)
		if err := sftpClient.Mkdir(current); err != nil {
			if info, statErr := sftpClient.Stat(current); statErr == nil && info.IsDir() {
				continue
			}
			return err
		}
	}
	return nil
}

func uploadDir(sftpClient *sftp.Client, localRoot, remoteRoot string) int {
	info, err := os.Stat(localRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat %s: %s\n", localRoot, err)
		return -1
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is not a directory: drop -r for a single-file transfer\n", localRoot)
		return -1
	}
	if err := sftpMkdirAll(sftpClient, remoteRoot); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create remote directory %s: %s\n", remoteRoot, err)
		return -1
	}
	progress := newTransferProgress("upload", localRoot, -1)
	var failures int
	err = filepath.WalkDir(localRoot, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(localRoot, current)
		if err != nil {
			return err
		}
		remotePath := path.Join(remoteRoot, filepath.ToSlash(relative))
		if entry.IsDir() {
			if current == localRoot {
				return nil
			}
			if err := sftpMkdirAll(sftpClient, remotePath); err != nil {
				return err
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		progress.rename(path.Base(current))
		if code := uploadFile(sftpClient, current, remotePath); code != 0 {
			failures++
		}
		return nil
	})
	progress.finish()
	if err != nil {
		fmt.Fprintf(os.Stderr, "upload walk failed: %s\n", err)
		return -1
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "upload finished with %d failed file(s)\n", failures)
		return -1
	}
	return 0
}

func downloadDir(sftpClient *sftp.Client, remoteRoot, localRoot string) int {
	remoteInfo, err := sftpClient.Stat(remoteRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat remote %s: %s\n", remoteRoot, err)
		return -1
	}
	if !remoteInfo.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is not a remote directory: drop -r for a single-file transfer\n", remoteRoot)
		return -1
	}
	if err := os.MkdirAll(localRoot, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create %s: %s\n", localRoot, err)
		return -1
	}
	progress := newTransferProgress("download", remoteRoot, -1)
	var failures int
	walker := sftpClient.Walk(remoteRoot)
	for walker.Step() {
		if walker.Err() != nil {
			fmt.Fprintf(os.Stderr, "walk error at %s: %s\n", walker.Path(), walker.Err())
			failures++
			continue
		}
		relative, err := filepath.Rel(remoteRoot, walker.Path())
		if err != nil {
			continue
		}
		localPath := filepath.Join(localRoot, filepath.FromSlash(relative))
		if walker.Stat().IsDir() {
			if err := os.MkdirAll(localPath, 0o755); err != nil {
				fmt.Fprintf(os.Stderr, "cannot create %s: %s\n", localPath, err)
				failures++
			}
			continue
		}
		if !walker.Stat().Mode().IsRegular() {
			continue
		}
		progress.rename(filepath.Base(localPath))
		if code := downloadFileTo(sftpClient, walker.Path(), localPath); code != 0 {
			failures++
		}
	}
	progress.finish()
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "download finished with %d failed file(s)\n", failures)
		return -1
	}
	return 0
}

// downloadFileTo downloads a remote file into an exact local path (no
// directory-guessing), used by recursive downloads.
func downloadFileTo(sftpClient *sftp.Client, remotePath, localPath string) int {
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open remote file %s: %s\n", remotePath, err)
		return -1
	}
	defer remoteFile.Close()

	info, err := remoteFile.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat remote file %s: %s\n", remotePath, err)
		return -1
	}

	localFile, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create %s: %s\n", localPath, err)
		return -1
	}
	defer localFile.Close()

	progress := newTransferProgress("download", path.Base(remotePath), info.Size())
	if _, err := io.Copy(localFile, progress.wrapReader(remoteFile)); err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %s\n", err)
		return -1
	}
	progress.finish()
	return 0
}

func uploadFile(sftpClient *sftp.Client, localPath, remotePath string) int {
	info, err := os.Stat(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat %s: %s\n", localPath, err)
		return -1
	}
	if info.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is a directory: use -r for recursive transfer\n", localPath)
		return -1
	}
	// a remote path pointing at an existing directory receives the file
	// under its local base name, scp-style
	if info, err := sftpClient.Stat(remotePath); err == nil && info.IsDir() {
		remotePath = path.Join(remotePath, path.Base(localPath))
	}
	localFile, err := os.Open(localPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot open %s: %s\n", localPath, err)
		return -1
	}
	defer localFile.Close()

	remoteFile, err := sftpClient.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create remote file %s: %s\n", remotePath, err)
		return -1
	}
	defer remoteFile.Close()

	progress := newTransferProgress("upload", localPath, info.Size())
	if _, err := io.Copy(remoteFile, progress.wrapReader(localFile)); err != nil {
		fmt.Fprintf(os.Stderr, "upload failed: %s\n", err)
		return -1
	}
	progress.finish()

	remoteInfo, err := sftpClient.Stat(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot verify remote file %s: %s\n", remotePath, err)
		return -1
	}
	if remoteInfo.Size() != info.Size() {
		fmt.Fprintf(os.Stderr, "size mismatch after upload: local %d bytes, remote %d bytes\n", info.Size(), remoteInfo.Size())
		return -1
	}
	return 0
}

func downloadFile(sftpClient *sftp.Client, remotePath, localPath string) int {
	remoteInfo, err := sftpClient.Stat(remotePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot stat remote %s: %s\n", remotePath, err)
		return -1
	}
	if remoteInfo.IsDir() {
		fmt.Fprintf(os.Stderr, "%s is a remote directory: use -r for recursive transfer\n", remotePath)
		return -1
	}
	if info, err := os.Stat(localPath); err == nil && info.IsDir() {
		localPath = filepath.Join(localPath, path.Base(remotePath))
	}
	return downloadFileTo(sftpClient, remotePath, localPath)
}

// transferProgress reports byte counts on stderr every 500ms and a final
// summary line; it is wired into the copy path by wrapping reader/writer.
type transferProgress struct {
	label    string
	name     string
	total    int64
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	addBytes func(int64)
}

func newTransferProgress(label, name string, total int64) *transferProgress {
	p := &transferProgress{
		label: label,
		name:  name,
		total: total,
		done:  make(chan struct{}),
	}
	var transferred atomic.Int64
	p.addBytes = func(n int64) { transferred.Add(n) }
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.done:
				fmt.Fprintf(os.Stderr, "[ssh3 -f] %s %s: %s done\n", label, p.currentName(), humanBytes(transferred.Load()))
				return
			case <-ticker.C:
				done := transferred.Load()
				if p.total > 0 {
					fmt.Fprintf(os.Stderr, "\r[ssh3 -f] %s %s: %s / %s (%d%%)",
						label, p.currentName(), humanBytes(done), humanBytes(p.total), done*100/p.total)
				} else {
					fmt.Fprintf(os.Stderr, "\r[ssh3 -f] %s %s: %s", label, p.currentName(), humanBytes(done))
				}
			}
		}
	}()
	return p
}

// rename switches the displayed file name (recursive transfers walk many
// files under one progress ticker).
func (p *transferProgress) rename(name string) {
	p.mu.Lock()
	p.name = name
	p.mu.Unlock()
}

func (p *transferProgress) currentName() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.name
}

func (p *transferProgress) finish() {
	p.once.Do(func() { close(p.done) })
}

type progressReader struct {
	reader io.Reader
	p      *transferProgress
}

func (p *transferProgress) wrapReader(reader io.Reader) io.Reader {
	if p.addBytes == nil {
		return reader
	}
	return &progressReader{reader: reader, p: p}
}

func (r *progressReader) Read(buf []byte) (int, error) {
	n, err := r.reader.Read(buf)
	if n > 0 {
		r.p.addBytes(int64(n))
	}
	return n, err
}

type progressWriter struct {
	writer io.Writer
	p      *transferProgress
}

func (p *transferProgress) wrapWriter(writer io.Writer) io.Writer {
	if p.addBytes == nil {
		return writer
	}
	return &progressWriter{writer: writer, p: p}
}

func (w *progressWriter) Write(buf []byte) (int, error) {
	n, err := w.writer.Write(buf)
	if n > 0 {
		w.p.addBytes(int64(n))
	}
	return n, err
}

func humanBytes(count int64) string {
	const unit = 1024
	if count < unit {
		return fmt.Sprintf("%d B", count)
	}
	value := float64(count)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	index := -1
	for value >= unit && index < len(units)-1 {
		value /= unit
		index++
	}
	return fmt.Sprintf("%.1f %s", value, units[index])
}
