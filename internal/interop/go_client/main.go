package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	ssh3 "github.com/francoismichel/ssh3"
	client_pubkey_authentication "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication/client"
	"github.com/francoismichel/ssh3/client"
	client_config "github.com/francoismichel/ssh3/client/config"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
	"github.com/pkg/sftp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	os.Exit(run())
}

func run() int {
	var rawURL string
	var username string
	var privateKeyPath string
	var serverName string
	var insecure bool
	var sftpMode string
	var sftpLocal string
	var sftpRemote string
	var agentExec string

	flag.StringVar(&rawURL, "url", "", "server URL")
	flag.StringVar(&username, "user", "", "username")
	flag.StringVar(&privateKeyPath, "privkey", "", "private key path")
	flag.StringVar(&serverName, "server-name", "", "TLS server name override")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.StringVar(&sftpMode, "sftp-mode", "", "file transfer mode: put or get (exclusive with -agent-exec and positional args)")
	flag.StringVar(&sftpLocal, "sftp-local", "", "local file path for -sftp-mode")
	flag.StringVar(&sftpRemote, "sftp-remote", "", "remote file path for -sftp-mode")
	flag.StringVar(&agentExec, "agent-exec", "", "execute this command with ssh-agent forwarding enabled")
	flag.Parse()

	if rawURL == "" || username == "" || privateKeyPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flags: --url, --user, and --privkey")
		return 2
	}
	if sftpMode != "" && agentExec != "" {
		fmt.Fprintln(os.Stderr, "-sftp-mode and -agent-exec are mutually exclusive")
		return 2
	}
	if sftpMode != "" {
		if sftpMode != "put" && sftpMode != "get" {
			fmt.Fprintf(os.Stderr, "invalid -sftp-mode %q: must be put or get\n", sftpMode)
			return 2
		}
		if sftpLocal == "" || sftpRemote == "" {
			fmt.Fprintln(os.Stderr, "-sftp-mode requires -sftp-local and -sftp-remote")
			return 2
		}
		if flag.NArg() > 0 {
			fmt.Fprintln(os.Stderr, "positional arguments are not allowed with -sftp-mode")
			return 2
		}
	}
	if agentExec != "" && flag.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "positional arguments are not allowed with -agent-exec")
		return 2
	}

	util.ConfigureLogger("error")

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid URL: %s\n", err)
		return 1
	}

	port := 443
	if parsedURL.Port() != "" {
		fmt.Sscanf(parsedURL.Port(), "%d", &port)
	}
	host := parsedURL.Hostname()
	if host == "" {
		fmt.Fprintln(os.Stderr, "URL must include a host")
		return 1
	}

	option, err := (&client_pubkey_authentication.PrivkeyOptionParser{}).Parse([]string{privateKeyPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse private key option: %s\n", err)
		return 1
	}
	config, err := client_config.NewConfig(
		username,
		host,
		port,
		parsedURL.EscapedPath(),
		nil,
		map[client_config.OptionName]client_config.Option{
			client_pubkey_authentication.PRIVKEY_OPTION_NAME: option,
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not build client config: %s\n", err)
		return 1
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", config.URLHostnamePort())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not resolve remote address: %s\n", err)
		return 1
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create UDP socket: %s\n", err)
		return 1
	}
	defer udpConn.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         host,
	}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}

	qconn, err := quic.DialEarly(
		context.Background(),
		udpConn,
		remoteAddr,
		tlsConfig,
		&quic.Config{
			Allow0RTT:          true,
			EnableDatagrams:    true,
			KeepAlivePeriod:    time.Second,
			MaxIncomingStreams: 10,
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not establish QUIC connection: %s\n", err)
		return 1
	}
	defer qconn.CloseWithError(0, "done")

	transport := &http3.Transport{
		EnableDatagrams: true,
	}
	defer transport.Close()

	sshClient, err := client.Dial(context.Background(), config, qconn, transport, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not establish SSH3 conversation: %s\n", err)
		return 1
	}
	defer sshClient.Close()

	switch {
	case sftpMode != "":
		return runSFTPTransfer(sshClient, sftpMode, sftpLocal, sftpRemote)
	case agentExec != "":
		return runAgentExec(sshClient, agentExec)
	}

	stdout, stderr, exitStatus, err := runExecCapture(sshClient, flag.Args())
	if len(stdout) > 0 {
		_, _ = os.Stdout.Write(stdout)
	}
	if len(stderr) > 0 {
		_, _ = os.Stderr.Write(stderr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "go interop client failed: %s\n", err)
		return 1
	}
	return exitStatus
}

func runExecCapture(sshClient *client.Client, command []string) ([]byte, []byte, int, error) {
	channel, err := sshClient.OpenChannel("session", 30_000, 0)
	if err != nil {
		return nil, nil, 1, err
	}
	defer channel.Close()

	commandString := strings.Join(command, " ")
	if commandString == "" {
		commandString = "printf ''"
	}
	if err := channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
		WantReply: false,
		ChannelRequest: &ssh3Messages.ExecRequest{
			Command: commandString,
		},
	}); err != nil {
		return nil, nil, 1, err
	}

	return captureSessionOutput(channel)
}

// captureSessionOutput drains a session channel until the remote process
// reports its exit status or the transport fails.
func captureSessionOutput(channel ssh3.Channel) ([]byte, []byte, int, error) {
	var stdout []byte
	var stderr []byte
	for {
		genericMessage, err := channel.NextMessage()
		if err != nil {
			return stdout, stderr, 1, err
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.DataOrExtendedDataMessage:
			switch message.DataType {
			case ssh3Messages.SSH_EXTENDED_DATA_NONE:
				stdout = append(stdout, []byte(message.Data)...)
			case ssh3Messages.SSH_EXTENDED_DATA_STDERR:
				stderr = append(stderr, []byte(message.Data)...)
			}
		case *ssh3Messages.ChannelRequestMessage:
			switch request := message.ChannelRequest.(type) {
			case *ssh3Messages.ExitStatusRequest:
				return stdout, stderr, int(request.ExitStatus), nil
			case *ssh3Messages.ExitSignalRequest:
				return stdout, stderr, 1, fmt.Errorf(
					"remote process exited with signal %s: %s",
					request.SignalNameWithoutSig,
					request.ErrorMessageUTF8,
				)
			}
		}
	}
}

// --- sftp transfer mode ---

const sftpChannelType = "sftp"

// runSFTPTransfer performs one scp-style put/get over a dedicated "sftp"
// channel served by pkg/sftp on both ends (same wiring as cmd/sftp_client.go).
func runSFTPTransfer(sshClient *client.Client, mode, localPath, remotePath string) int {
	channel, err := sshClient.OpenChannel(sftpChannelType, 30_000, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open sftp channel: %s\n", err)
		return 1
	}
	defer channel.Close()

	rwc := ssh3.NewChannelReadWriteCloser(channel)
	sftpClient, err := sftp.NewClientPipe(rwc, rwc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not start sftp client: %s\n", err)
		return 1
	}
	defer func() {
		if err := sftpClient.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "sftp client close: %s\n", err)
		}
	}()

	var transferred int64
	switch mode {
	case "put":
		transferred, err = sftpPutFile(sftpClient, localPath, remotePath)
	case "get":
		transferred, err = sftpGetFile(sftpClient, localPath, remotePath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "sftp %s failed: %s\n", mode, err)
		return 1
	}
	fmt.Printf("SFTP-CLIENT-DONE mode=%s bytes=%d\n", mode, transferred)
	return 0
}

// sftpPutFile uploads localPath to remotePath with a minimal resume rule:
// when the server already holds a prefix of the local file (remote size not
// beyond the local size) the transfer continues at that offset via
// WriteAt-style absolute writes, otherwise the remote file restarts.
func sftpPutFile(sftpClient *sftp.Client, localPath, remotePath string) (int64, error) {
	localFile, err := os.Open(localPath)
	if err != nil {
		return 0, err
	}
	defer localFile.Close()
	localInfo, err := localFile.Stat()
	if err != nil {
		return 0, err
	}
	if localInfo.IsDir() {
		return 0, fmt.Errorf("%s is a directory", localPath)
	}

	var startOffset int64
	openFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if remoteInfo, statErr := sftpClient.Stat(remotePath); statErr == nil && remoteInfo.Size() <= localInfo.Size() {
		startOffset = remoteInfo.Size()
		openFlags = os.O_WRONLY // keep the already-transferred prefix
	}

	remoteFile, err := sftpClient.OpenFile(remotePath, openFlags)
	if err != nil {
		return 0, err
	}
	defer remoteFile.Close()

	return copyAtOffset(localFile, remoteFile, startOffset)
}

// sftpGetFile downloads remotePath to localPath with the same minimal resume
// rule as uploads: a complete-or-partial local copy continues at its size,
// anything else (missing, larger, corrupt) restarts from scratch.
func sftpGetFile(sftpClient *sftp.Client, localPath, remotePath string) (int64, error) {
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		return 0, err
	}
	defer remoteFile.Close()
	remoteInfo, err := remoteFile.Stat()
	if err != nil {
		return 0, err
	}
	if remoteInfo.IsDir() {
		return 0, fmt.Errorf("%s is a remote directory", remotePath)
	}

	var startOffset int64
	openFlags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if localInfo, statErr := os.Stat(localPath); statErr == nil && localInfo.Size() <= remoteInfo.Size() {
		startOffset = localInfo.Size()
		openFlags = os.O_WRONLY // keep the already-transferred prefix
	}

	localFile, err := os.OpenFile(localPath, openFlags, 0o644)
	if err != nil {
		return 0, err
	}
	defer localFile.Close()

	return copyAtOffset(remoteFile, localFile, startOffset)
}

// copyAtOffset copies the remainder of src (read from startOffset on) onto
// dst at the matching absolute offsets, so interrupted transfers resume
// instead of restarting.
func copyAtOffset(src io.ReaderAt, dst io.WriterAt, startOffset int64) (int64, error) {
	var copied int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.ReadAt(buf, startOffset+copied)
		if n > 0 {
			if _, writeErr := dst.WriteAt(buf[:n], startOffset+copied); writeErr != nil {
				return copied, writeErr
			}
			copied += int64(n)
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return copied, nil
			}
			return copied, readErr
		}
	}
}

// --- agent forwarding mode ---

// runAgentExec runs one remote command on a session channel with agent
// forwarding requested: OpenSession sends the LARVAL "forward-agent" data and
// serves the resulting server-initiated "agent-connection" channels by
// bridging them to the local SSH_AUTH_SOCK (library-side forwardAgent).
func runAgentExec(sshClient *client.Client, command string) int {
	channel, _, err := sshClient.OpenSession(context.Background(), client.SessionSpec{
		Command:      []string{command},
		ForwardAgent: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open agent-forwarding session: %s\n", err)
		return 1
	}
	defer channel.Close()

	stdout, stderr, exitStatus, err := captureSessionOutput(channel)
	if len(stdout) > 0 {
		_, _ = os.Stdout.Write(stdout)
	}
	if len(stderr) > 0 {
		_, _ = os.Stderr.Write(stderr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "go interop client failed: %s\n", err)
		return 1
	}
	fmt.Printf("AGENT-CLIENT-DONE exit=%d\n", exitStatus)
	return exitStatus
}
