// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package unix_util

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

type User struct {
	Username string
	Uid      uint64
	Gid      uint64
	Dir      string
	Shell    string
}

func GetUser(username string) (*User, error) {
	return getUser(username)
}

// CreateCommand wires the command's stdio. When stdout/stderr writers are
// not supplied, the parent gets its own os.Pipe read ends; os/exec must NOT
// own them (StdoutPipe's readers are closed by Wait and would race the
// output pumps, truncating command output), so the write ends are returned
// to the caller via closeParentStdio: it must be invoked right after Start,
// otherwise the child never sees EOF on its stdout/stderr.
func (u *User) CreateCommand(addEnv string, stdout, stderr io.Writer, stdin io.Reader, loginShell bool, command string, args ...string) (*exec.Cmd, io.Reader, io.Reader, io.Writer, func(), error) {
	cmd := exec.Command(command, args...)
	cmd.Env = append(cmd.Env, addEnv)
	cmd.Dir = u.Dir

	if loginShell {
		// from man bash: A  login shell is one whose first character of argument zero is a -, or
		// 				  one started with the --login option.
		// We chose to start it with a preprended "-"
		cmd.Args[0] = fmt.Sprintf("-%s", filepath.Base(cmd.Args[0]))
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{}
	currentUID := uint64(os.Getuid())
	currentGID := uint64(os.Getgid())
	if u.Uid != currentUID || u.Gid != currentGID {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(u.Uid), Gid: uint32(u.Gid)}
	}

	var err error
	var stdoutR, stderrR io.Reader
	var stdinW io.Writer
	var closeParentStdio func()

	if stdout == nil {
		pipeR, pipeW, pipeErr := os.Pipe()
		if pipeErr != nil {
			return nil, nil, nil, nil, nil, pipeErr
		}
		cmd.Stdout = pipeW
		stdoutR = pipeR
		closeParentStdio = appendCloser(closeParentStdio, pipeW)
	} else {
		cmd.Stdout = stdout
	}
	if stderr == nil {
		pipeR, pipeW, pipeErr := os.Pipe()
		if pipeErr != nil {
			return nil, nil, nil, nil, nil, pipeErr
		}
		cmd.Stderr = pipeW
		stderrR = pipeR
		closeParentStdio = appendCloser(closeParentStdio, pipeW)
	} else {
		cmd.Stderr = stderr
	}
	if stdin == nil {
		stdinW, err = cmd.StdinPipe()
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
	} else {
		cmd.Stdin = stdin
	}

	return cmd, stdoutR, stderrR, stdinW, closeParentStdio, err
}

func appendCloser(chain func(), closer io.Closer) func() {
	if chain == nil {
		return func() { _ = closer.Close() }
	}
	return func() {
		chain()
		_ = closer.Close()
	}
}

func (u *User) CreateCommandPipeOutput(addEnv string, loginShell bool, command string, args ...string) (*exec.Cmd, io.Reader, io.Reader, io.Writer, func(), error) {
	cmd := exec.Command(command, args...)

	cmd.Env = append(cmd.Env, addEnv)
	cmd.Dir = u.Dir

	cmd.SysProcAttr = &syscall.SysProcAttr{}
	currentUID := uint64(os.Getuid())
	currentGID := uint64(os.Getgid())
	if u.Uid != currentUID || u.Gid != currentGID {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(u.Uid), Gid: uint32(u.Gid)}
	}

	return u.CreateCommand(addEnv, nil, nil, nil, loginShell, command, args...)
}

/*
 *  Returns a boolean stating whether the user is correctly authenticated on this
 *  server. May return a UserNotFound error when the user does not exist.
 */
func UserPasswordAuthentication(username, password string) (bool, error) {
	return userPasswordAuthentication(username, password)
}

func PasswordAuthAvailable() bool {
	return passwordAuthAvailable()
}
