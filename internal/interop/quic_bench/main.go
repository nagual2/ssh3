// Command quic_bench measures raw vendored quic-go single-stream throughput
// on loopback: the transport ceiling without any ssh3 layer overhead.
// Stage 1.5 increment 1 (docs/BENCH + CTO_TASK §6a).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

var (
	addr     = flag.String("addr", "127.0.0.1:46443", "UDP address to listen on / dial")
	mode     = flag.String("mode", "server", "server|client")
	mib      = flag.Int("mib", 512, "MiB to transfer (client)")
	chunk    = flag.Int("chunk-kb", 64, "write chunk size KiB (client)")
	dialmode = flag.String("dialmode", "direct", "direct (DialAddr) | conn (ssh3-style pre-created dual-stack socket)")
)

// dialLikeSSH3 reproduces the ssh3 client socket creation: a dual-stack
// net.ListenUDP("udp", nil) passed to quic.Dial.
func dialLikeSSH3(ctx context.Context, tlsConf *tls.Config) (quic.Connection, error) {
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		return nil, err
	}
	return quic.Dial(ctx, udpConn, remote, tlsConf, nil)
}

func selfSigned() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "quic-bench"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func runServer(ctx context.Context, cert *tls.Certificate) error {
	l, err := quic.ListenAddr(*addr, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"quic-bench"},
	}, nil)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			wg.Wait()
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			stream, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			n, err := io.Copy(io.Discard, stream)
			if err != nil {
				fmt.Fprintf(os.Stderr, "server copy: %v\n", err)
				return
			}
			stream.Write([]byte{1}) // drain marker
			stream.Close()
			fmt.Fprintf(os.Stderr, "server received %d bytes\n", n)
		}()
	}
}

func runClient(ctx context.Context) error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // self-signed bench certificate
		NextProtos:         []string{"quic-bench"},
	}
	var conn quic.Connection
	var err error
	if *dialmode == "conn" {
		conn, err = dialLikeSSH3(ctx, tlsConf)
	} else {
		conn, err = quic.DialAddr(ctx, *addr, tlsConf, nil)
	}
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	buf := make([]byte, (*chunk)<<10)
	total := *mib << 20

	t0 := time.Now()
	for sent := 0; sent < total; {
		n, err := stream.Write(buf)
		if err != nil {
			return err
		}
		sent += n
	}
	if err := stream.Close(); err != nil { // FIN: the server starts draining
		return err
	}
	// the run is over when the server has consumed everything and acknowledged
	if _, err := io.Copy(io.Discard, stream); err != nil {
		return err
	}
	dt := time.Since(t0)
	fmt.Printf("quic-go single stream: %d MiB in %s -> %.1f MB/s\n",
		*mib, dt.Round(time.Millisecond), float64(total)/1e6/dt.Seconds())
	return nil
}

func main() {
	flag.Parse()
	ctx := context.Background()
	cert, err := selfSigned()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *mode == "server" {
		err = runServer(ctx, cert)
	} else {
		err = runClient(ctx)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
