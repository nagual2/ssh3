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
	cmd.Env = append(os.Environ(), "SSH3_LOG_FILE="+filepath.Join(dir, "server.log"))
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
	go func() { serveDone <- ServeControlMaster(ctx, master, ln) }()

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

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("master did not stop after context cancel")
	}
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
// reduced to the insecure loopback case.
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
	}
	var qconn *quic.Conn
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		qconn, err = quic.DialAddrEarly(ctx, bind, tlsConf, &qconf)
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
	c, err := Dial(ctx, config, qconn, &http3.Transport{}, nil)
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
