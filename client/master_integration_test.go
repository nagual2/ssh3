package client

// Integration test for the ControlMaster session bridging (stage 3.5,
// increment 3): a real ssh3-server binary runs on loopback as the current
// user, an in-process master serves a UDS control socket, and slave
// sessions execute through it.
//
// Gated behind SSH3_CM_INTEGRATION=1 like the binary-level suite: it needs
// an authorized private key (default $HOME/.ssh/ssh3test_ed25519, override
// with SSH3_CM_PRIVKEY) and a Unix-domain-socket capable OS.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/client/cm"
	client_config "github.com/francoismichel/ssh3/client/config"
)

const cmTestURLPath = "/ssh3-term"

func TestControlMasterSlaveSessionIntegration(t *testing.T) {
	if os.Getenv("SSH3_CM_INTEGRATION") != "1" {
		t.Skip("SSH3_CM_INTEGRATION != 1")
	}
	if runtime := os.Getenv("GOOS"); runtime == "windows" {
		t.Skip("unix socket master requires a POSIX OS")
	}

	privKeyPath := os.Getenv("SSH3_CM_PRIVKEY")
	if privKeyPath == "" {
		privKeyPath = filepath.Join(os.Getenv("HOME"), ".ssh", "ssh3test_ed25519")
	}
	if _, err := os.Stat(privKeyPath); err != nil {
		t.Skipf("no authorized private key at %s: %v", privKeyPath, err)
	}
	username := os.Getenv("USER")
	if username == "" {
		t.Skip("USER is not set")
	}

	dir := t.TempDir()
	port := freeUDPPort(t)
	certPath, keyPath := writeSelfSignedCert(t, dir)

	serverPath := filepath.Join(dir, "ssh3-server")
	build := exec.Command("go", "build", "-tags", "disable_password_auth", "-o", serverPath, "./cmd/ssh3-server")
	build.Dir = ".." // the test runs in the client package; build from the repo root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, out)
	}

	bind := fmt.Sprintf("127.0.0.1:%d", port)
	cmd := exec.Command(serverPath,
		"-bind", bind,
		"-url-path", cmTestURLPath,
		"-cert", certPath,
		"-key", keyPath)
	cmd.Env = append(os.Environ(), "SSH3_LOG_FILE=/tmp/cm-server.log", "SSH3_LOG_LEVEL=debug")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	master := dialMasterClient(t, ctx, username, bind, privKeyPath)

	sockPath := filepath.Join(dir, "cm.sock")
	ln, err := ListenControlMaster(sockPath)
	if err != nil {
		t.Fatalf("listen control master: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- ServeControlMaster(ctx, master, ln, nil) }()

	t.Run("exec output and status", func(t *testing.T) {
		var out, errBuf strings.Builder
		code, err := RunSlaveSession(ctx, sockPath, SessionSpec{Command: []string{"echo", "cm-increment3-ok"}},
			strings.NewReader(""), &out, &errBuf)
		if err != nil {
			t.Fatalf("slave session: %v", err)
		}
		if code != 0 {
			t.Fatalf("exit status = %d, want 0", code)
		}
		if !strings.Contains(out.String(), "cm-increment3-ok") {
			t.Fatalf("stdout = %q, want the echo output", out.String())
		}
	})

	t.Run("exec exit code", func(t *testing.T) {
		var out, errBuf strings.Builder
		// NB: the exec request joins argv with spaces (CLI semantics), so a
		// quoted "exit 7" would arrive unquoted; use a command whose exit
		// code needs no quoting
		code, err := RunSlaveSession(ctx, sockPath, SessionSpec{Command: []string{"false"}},
			strings.NewReader(""), &out, &errBuf)
		if err != nil {
			t.Fatalf("slave session: %v", err)
		}
		if code != 1 {
			t.Fatalf("exit status = %d, want 1", code)
		}
	})

	t.Run("stdin bridging", func(t *testing.T) {
		var out, errBuf strings.Builder
		code, err := RunSlaveSession(ctx, sockPath, SessionSpec{Command: []string{"cat"}},
			strings.NewReader("ping-through-master"), &out, &errBuf)
		if err != nil {
			t.Fatalf("slave session: %v", err)
		}
		if code != 0 {
			t.Fatalf("exit status = %d, want 0", code)
		}
		if out.String() != "ping-through-master" {
			t.Fatalf("stdout = %q, want the stdin echoed byte-exact", out.String())
		}
	})

	t.Run("TCP forward through master", func(t *testing.T) {
		// echo server on the server side (same host in this stand)
		echo, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("echo listen: %v", err)
		}
		defer echo.Close()
		go func() {
			for {
				conn, err := echo.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					io.Copy(c, c)
					c.Close()
				}(conn)
			}
		}()

		bound, err := OpenMasterForwardTCP(ctx, sockPath, "127.0.0.1:0", echo.Addr().String())
		if err != nil {
			t.Fatalf("open forward: %v", err)
		}
		conn, err := net.Dial("tcp", bound)
		if err != nil {
			t.Fatalf("dial forwarded listener %s: %v", bound, err)
		}
		defer conn.Close()
		payload := "ping-through-tcp-forward"
		if _, err := io.WriteString(conn, payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		// a forwarded connection never EOFs on its own: read exactly the
		// expected echo length instead of waiting for an end of stream
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got) != payload {
			t.Fatalf("echoed %q, want %q", got, payload)
		}
	})

	t.Run("UDP forward through master", func(t *testing.T) {
		echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("echo listen: %v", err)
		}
		defer echo.Close()
		go func() {
			buf := make([]byte, 2048)
			for {
				n, addr, err := echo.ReadFromUDP(buf)
				if err != nil {
					return
				}
				echo.WriteToUDP(buf[:n], addr)
			}
		}()

		bound, err := OpenMasterForwardUDP(ctx, sockPath, "127.0.0.1:0", echo.LocalAddr().String())
		if err != nil {
			t.Fatalf("open forward: %v", err)
		}
		conn, err := net.Dial("udp", bound)
		if err != nil {
			t.Fatalf("dial forwarded listener %s: %v", bound, err)
		}
		defer conn.Close()
		payload := "ping-through-udp-forward"
		if _, err := conn.Write([]byte(payload)); err != nil {
			t.Fatalf("write: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, 2048)
		n, err := conn.Read(got)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(got[:n]) != payload {
			t.Fatalf("echoed %q, want %q", got[:n], payload)
		}
	})

	t.Run("-O exit stops the master", func(t *testing.T) {
		if err := ExitMaster(ctx, sockPath); err != nil {
			t.Fatalf("exit op: %v", err)
		}
		select {
		case err := <-serveDone:
			if err != nil {
				t.Fatalf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("master did not stop after the exit op")
		}
		// clean teardown: the socket file is gone
		if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
			t.Fatalf("socket file still present after master exit (stat err = %v)", err)
		}
		// and a new slave cannot reach it
		if _, err := RunSlaveSession(ctx, sockPath, SessionSpec{Command: []string{"true"}},
			strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatalf("slave session succeeded after master exit, want failure")
		}
	})

	t.Run("idle timeout stops the master", func(t *testing.T) {
		idleSock := filepath.Join(dir, "cm-idle.sock")
		ln2, err := ListenControlMaster(idleSock)
		if err != nil {
			t.Fatalf("listen idle master: %v", err)
		}
		idleDone := make(chan error, 1)
		go func() {
			idleDone <- ServeControlMaster(ctx, master, ln2, &MasterOptions{IdleTimeout: time.Second})
		}()

		// touching the control socket counts as activity and must postpone
		// the idle exit past the 1s window
		touch := func() {
			conn, err := net.Dial("unix", idleSock)
			if err != nil {
				return
			}
			cm.Hello(conn)
			conn.Close()
		}
		deadline := time.Now().Add(1500 * time.Millisecond)
		for time.Now().Before(deadline) {
			touch()
			time.Sleep(300 * time.Millisecond)
			select {
			case err := <-idleDone:
				t.Fatalf("master exited too early: %v", err)
			default:
			}
		}
		// touches stop: the master must idle out within the window + slack
		select {
		case err := <-idleDone:
			if err != nil {
				t.Fatalf("serve: %v", err)
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("master did not stop after the idle timeout")
		}
		if _, err := os.Stat(idleSock); !os.IsNotExist(err) {
			t.Fatalf("idle master socket file still present (stat err = %v)", err)
		}
	})

	// master #1 was already stopped by the -O exit subtest (its serveDone
	// value was consumed there); cancel is cleanup for the QUIC client
	cancel()
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("pick free port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func writeSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// dialMasterClient performs the QUIC dial and ssh3 auth the CLI would do,
// reduced to the insecure loopback case; the dial mirrors
// cmd.setupQUICConnection (bound UDP socket, same qconf fields).
func dialMasterClient(t *testing.T, ctx context.Context, username, bind, privKeyPath string) *Client {
	t.Helper()
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         "localhost",
	}
	qconf := quic.Config{
		MaxIncomingStreams: 10,
		Allow0RTT:          true,
		EnableDatagrams:    true,
		KeepAlivePeriod:    time.Second,
		InitialPacketSize:  1350,
	}
	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	// no Close: the QUIC connection owns the socket for its lifetime, the
	// process exits with the test
	remote, err := net.ResolveUDPAddr("udp4", bind)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var qconn *quic.Conn
	for attempt := 0; attempt < 20; attempt++ {
		qconn, err = quic.DialEarly(ctx, udpConn, remote, tlsConf, &qconf)
		if err == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	config, err := client_config.NewConfig(username, "127.0.0.1", portOf(bind), cmTestURLPath,
		[]any{ssh3.NewPrivkeyFileAuthMethod(privKeyPath)}, nil)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	c, err := Dial(ctx, config, qconn, &http3.Transport{}, nil, WithMultiplexed())
	if err != nil {
		t.Fatalf("ssh3 dial: %v", err)
	}
	return c
}

func portOf(bind string) int {
	_, portStr, _ := net.SplitHostPort(bind)
	port, _ := strconv.Atoi(portStr)
	return port
}
