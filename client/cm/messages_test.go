package cm

// Message codec tests: round-trips and garbage rejection (increment 2).

import (
	"reflect"
	"testing"
)

func TestOpenSessionRoundTripFull(t *testing.T) {
	in := &OpenSession{
		Command: []string{"bash", "-lc", "echo hi; printf 'кавычки \" и $VAR'"},
		Env:     []string{"TERM=xterm-256color", "LANG=ru_RU.UTF-8"},
		Pty:     &PtySpec{Term: "xterm-256color", Columns: 120, Rows: 40, PixelWidth: 960, PixelHeight: 640},
		ForwardAgent: true,
	}
	b, err := in.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out := &OpenSession{}
	if err := out.Decode(b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch:\n in = %+v\nout = %+v", in, out)
	}
}

func TestOpenSessionRoundTripNoPty(t *testing.T) {
	in := &OpenSession{Command: []string{"true"}}
	b, err := in.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out := &OpenSession{}
	if err := out.Decode(b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch:\n in = %+v\nout = %+v", in, out)
	}
}

// A shell request is Command == nil (not just empty): empty must also work.
func TestOpenSessionShellVsExec(t *testing.T) {
	shell := &OpenSession{}
	b, err := shell.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out := &OpenSession{}
	if err := out.Decode(b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Command) != 0 {
		t.Fatalf("command = %v, want empty", out.Command)
	}
}

func TestOpenSessionRejectsGarbage(t *testing.T) {
	in := &OpenSession{Command: []string{"echo", "hi"}, Env: []string{"A=B"}}
	good, err := in.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"empty":            {},
		"short count":      {0, 0, 0},
		"huge count":       {0xff, 0xff, 0xff, 0xff},
		"truncated valid":  good[:len(good)/2],
		"trailing garbage": append(append([]byte{}, good...), 0xde, 0xad),
	}
	for name, payload := range cases {
		err := (&OpenSession{}).Decode(payload)
		if err == nil {
			t.Fatalf("%s: decode succeeded, want error", name)
		}
	}
}

func TestOpenForwardRoundTrip(t *testing.T) {
	in := &OpenForward{ListenAddr: "127.0.0.1:8080", TargetAddr: "example.lan:80"}
	b := in.Encode()
	out := &OpenForward{}
	if err := out.Decode(b); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if *in != *out {
		t.Fatalf("round trip mismatch: in = %+v, out = %+v", in, out)
	}
}

func TestOpenForwardRejectsGarbage(t *testing.T) {
	for _, payload := range [][]byte{{}, {0, 0, 0}, {0xff, 0xff, 0xff, 0xff, 'x'}} {
		if err := (&OpenForward{}).Decode(payload); err == nil {
			t.Fatalf("decode(%v) succeeded, want error", payload)
		}
	}
}
