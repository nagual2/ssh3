package cmd

// Subsystem requests (-s). ssh3 serves sftp on a dedicated "sftp" channel
// rather than through a subsystem request, so that name is special-cased onto
// the interactive sftp client that already exists in this package; every other
// name is sent as a subsystem request on a session channel, as ssh(1) does.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"github.com/rs/zerolog/log"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client"
	ssh3Messages "github.com/francoismichel/ssh3/message"
)

// sftpSubsystemName is the -s value that selects the interactive sftp client.
const sftpSubsystemName = "sftp"

// runSubsystemSession opens a session channel, optionally requests a pty and
// asks the server for the named subsystem instead of a shell or a command.
// Agent and reverse forwarding are not offered here: they are wired by
// client.OpenSession, which issues a shell/exec request instead of a subsystem
// request, so -s is rejected together with them at the command line.
func runSubsystemSession(ctx context.Context, c *client.Client, tty *os.File, name string, forcePTY bool, termType string) error {
	channel, err := c.OpenChannel("session", 30000, 0)
	if err != nil {
		return fmt.Errorf("could not open channel: %w", err)
	}

	ptyRequested := false
	if forcePTY {
		ptySpec, err := newForcedPtySpec(tty, termType)
		if err != nil {
			return err
		}
		err = channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
			WantReply: true,
			ChannelRequest: &ssh3Messages.PtyRequest{
				Term:        ptySpec.Term,
				CharWidth:   ptySpec.Columns,
				CharHeight:  ptySpec.Rows,
				PixelWidth:  ptySpec.PixelWidth,
				PixelHeight: ptySpec.PixelHeight,
			},
		})
		if err != nil {
			return fmt.Errorf("could send pty request: %w", err)
		}
		ptyRequested = true
	}

	err = channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
		WantReply:      true,
		ChannelRequest: &ssh3Messages.SubsystemRequest{SubsystemName: name},
	})
	if err != nil {
		return fmt.Errorf("could not send subsystem request for %q: %w", name, err)
	}

	err = c.PumpSession(channel, os.Stdin, os.Stdout, os.Stderr, ptyRequested, nil)
	switch err.(type) {
	case nil, client.ExitStatus, client.ExitSignal:
		return err
	default:
		return fmt.Errorf("could not get message: %w", err)
	}
}

// runSFTPSubsystem starts the interactive sftp client: a prompt-driven shell
// over the "sftp" channel, with the command set of sftp(1) reduced to what is
// useful interactively.
func runSFTPSubsystem(conversation *ssh3.Conversation) int {
	channel, err := conversation.OpenChannel(sftpChannelType, 30000, 0)
	if err != nil {
		log.Error().Msgf("could not open the sftp channel: %s", err)
		return -1
	}
	defer channel.Close()

	stream := ssh3.NewChannelReadWriteCloser(channel)
	sftpClient, err := sftp.NewClientPipe(stream, stream)
	if err != nil {
		log.Error().Msgf("could not start the sftp client: %s", err)
		return -1
	}
	defer sftpClient.Close()

	remotePath, err := sftpClient.Getwd()
	if err != nil {
		log.Error().Msgf("could not read the remote working directory: %s", err)
		return -1
	}

	fmt.Fprintf(os.Stdout, "Connected to %s.\n", remotePath)
	printSFTPHelp()

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stdout, "sftp> ")
		line, err := reader.ReadString('\n')
		if line == "" && err != nil {
			fmt.Fprintln(os.Stdout)
			return 0
		}
		command, parseErr := parseSFTPCommand(line)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "%s\n", parseErr)
			if err != nil {
				return 0
			}
			continue
		}
		remotePath = runSFTPCommand(sftpClient, command, remotePath)
		if command.name == "quit" || command.name == "exit" {
			return 0
		}
		if err != nil {
			return 0
		}
	}
}

// sftpCommand is one parsed interactive sftp command.
type sftpCommand struct {
	name string
	args []string
}

// sftpCommandArity describes how many arguments each command accepts.
var sftpCommandArity = map[string]struct{ min, max int }{
	"help":  {0, 0},
	"pwd":   {0, 0},
	"ls":    {0, 1},
	"cd":    {0, 1},
	"get":   {1, 2},
	"put":   {2, 2},
	"mkdir": {1, 1},
	"rmdir": {1, 1},
	"rm":    {1, 1},
	"quit":  {0, 0},
	"exit":  {0, 0},
}

// parseSFTPCommand splits one input line into a command and its arguments.
// Double quotes group an argument containing spaces, which is enough for the
// paths an interactive session deals with.
func parseSFTPCommand(line string) (sftpCommand, error) {
	fields, err := splitSFTPFields(strings.TrimRight(line, "\r\n"))
	if err != nil {
		return sftpCommand{}, err
	}
	if len(fields) == 0 {
		return sftpCommand{}, errors.New("empty command")
	}

	name := strings.ToLower(fields[0])
	args := fields[1:]
	arity, known := sftpCommandArity[name]
	if !known {
		return sftpCommand{}, fmt.Errorf("unknown command %q (type \"help\" for the list)", name)
	}
	if len(args) < arity.min || len(args) > arity.max {
		return sftpCommand{}, fmt.Errorf("%q expects %s argument(s), got %d",
			name, describeSFTPArity(arity), len(args))
	}
	return sftpCommand{name: name, args: args}, nil
}

func describeSFTPArity(arity struct{ min, max int }) string {
	if arity.min == arity.max {
		return strconv.Itoa(arity.min)
	}
	return fmt.Sprintf("%d to %d", arity.min, arity.max)
}

// splitSFTPFields splits a command line on whitespace, honouring double
// quotes.
func splitSFTPFields(line string) ([]string, error) {
	var (
		fields   []string
		current  strings.Builder
		inQuotes bool
		started  bool
	)
	flush := func() {
		if started {
			fields = append(fields, current.String())
			current.Reset()
			started = false
		}
	}
	for i := 0; i < len(line); i++ {
		switch char := line[i]; {
		case char == '"':
			inQuotes = !inQuotes
			started = true
		case !inQuotes && (char == ' ' || char == '\t'):
			flush()
		default:
			current.WriteByte(char)
			started = true
		}
	}
	if inQuotes {
		return nil, errors.New("unbalanced quote in command")
	}
	flush()
	return fields, nil
}

// resolveRemoteSFTPPath resolves a path argument against the current remote
// directory. The second result tells the caller that the path names a
// directory rather than a file, which is what cd, ls and the rmdir target are
// about.
func resolveRemoteSFTPPath(current, requested string) (string, bool) {
	if requested == "" || requested == "." {
		return current, true
	}
	if strings.HasPrefix(requested, "/") {
		return path.Clean(requested), isRemoteDirectoryPath(requested)
	}
	return path.Clean(path.Join(current, requested)), isRemoteDirectoryPath(requested)
}

func isRemoteDirectoryPath(requested string) bool {
	return requested == "." || requested == ".." ||
		strings.HasSuffix(requested, "/") || path.Base(requested) == ".." || path.Base(requested) == "."
}

// runSFTPCommand executes one interactive sftp command and returns the new
// remote working directory.
func runSFTPCommand(sftpClient *sftp.Client, command sftpCommand, remotePath string) string {
	switch command.name {
	case "help":
		printSFTPHelp()
	case "quit", "exit":
		return remotePath
	case "pwd":
		fmt.Fprintln(os.Stdout, remotePath)
	case "cd":
		target, _ := resolveRemoteSFTPPath(remotePath, commandArg(command, 0))
		info, err := sftpClient.Stat(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not change directory to %s: %s\n", target, err)
			return remotePath
		}
		if !info.IsDir() {
			fmt.Fprintf(os.Stderr, "%s is not a directory\n", target)
			return remotePath
		}
		return target
	case "ls":
		target, _ := resolveRemoteSFTPPath(remotePath, commandArg(command, 0))
		entries, err := sftpClient.ReadDir(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not list %s: %s\n", target, err)
			return remotePath
		}
		printSFTPDirectory(entries)
	case "get":
		target, _ := resolveRemoteSFTPPath(remotePath, commandArg(command, 0))
		local := commandArg(command, 1)
		if local == "" {
			local = path.Base(target)
		}
		downloadFile(sftpClient, target, local, false, false)
	case "put":
		local := commandArg(command, 0)
		target, _ := resolveRemoteSFTPPath(remotePath, commandArg(command, 1))
		uploadFile(sftpClient, local, target, false, false)
	case "mkdir":
		target, _ := resolveRemoteSFTPPath(remotePath, commandArg(command, 0))
		if err := sftpClient.MkdirAll(target); err != nil {
			fmt.Fprintf(os.Stderr, "could not create %s: %s\n", target, err)
		}
	case "rmdir", "rm":
		target, _ := resolveRemoteSFTPPath(remotePath, commandArg(command, 0))
		var err error
		if command.name == "rmdir" {
			err = sftpClient.RemoveDirectory(target)
		} else {
			err = sftpClient.Remove(target)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not remove %s: %s\n", target, err)
		}
	}
	return remotePath
}

func commandArg(command sftpCommand, index int) string {
	if index < len(command.args) {
		return command.args[index]
	}
	return ""
}

func printSFTPDirectory(entries []os.FileInfo) {
	for _, entry := range entries {
		kind := "-"
		if entry.IsDir() {
			kind = "d"
		}
		fmt.Fprintf(os.Stdout, "%s %10d %s\n", kind, entry.Size(), entry.Name())
	}
}

func printSFTPHelp() {
	fmt.Fprint(os.Stdout, `Commands:
  pwd                  print the remote working directory
  ls [path]            list a remote directory
  cd [path]            change the remote working directory
  get <remote> [local] download a file
  put <local> <remote> upload a file
  mkdir <path>         create a remote directory
  rmdir <path>         remove a remote directory
  rm <path>            remove a remote file
  help                 show this help
  quit, exit           leave the sftp session
`)
}
