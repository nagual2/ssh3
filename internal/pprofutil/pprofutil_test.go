package pprofutil

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServeIfEnabledServesPprof(t *testing.T) {
	// grab a free port, then release it for the pprof server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	ServeIfEnabled(addr)

	deadline := time.Now().Add(3 * time.Second)
	var resp *http.Response
	for {
		resp, err = http.Get("http://" + addr + "/debug/pprof/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pprof server never came up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
}

func TestServeIfEnabledNoopOnEmpty(t *testing.T) {
	ServeIfEnabled("") // must not panic or start anything
}
