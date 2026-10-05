// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package client

// The escape filter of the interactive stdin pump (OpenSSH-style): an
// escape character at the start of a line introduces ~. (disconnect),
// ~^Z (suspend, unix), ~~ (a literal tilde); anything else after the
// escape character forwards literally. The filter must survive sequences
// split across read chunks.

import (
	"bytes"
	"testing"
)

func feedAll(t *testing.T, cfg *EscapeConfig, chunks ...string) (string, string) {
	t.Helper()

	f := newEscapeFilter(cfg)
	var out bytes.Buffer
	action := ""

	for _, chunk := range chunks {
		forwarded, act := f.Feed([]byte(chunk))
		out.Write(forwarded)

		if act != "" {
			action = act
		}
	}

	return out.String(), action
}

func TestEscapeDisconnect(t *testing.T) {
	out, action := feedAll(t, testEscapeConfig(), "\n~.")
	if out != "\n" {
		t.Errorf("the sequence must not be forwarded: %q", out)
	}

	if action != "disconnect" {
		t.Errorf("action = %q, want disconnect", action)
	}
}

func TestEscapeAtSessionStart(t *testing.T) {
	out, action := feedAll(t, testEscapeConfig(), "~.")
	if out != "" {
		t.Errorf("the sequence must not be forwarded: %q", out)
	}

	if action != "disconnect" {
		t.Errorf("action = %q, want disconnect", action)
	}
}

func TestEscapeNotAtLineStart(t *testing.T) {
	out, action := feedAll(t, testEscapeConfig(), "echo ~x\n")
	if out != "echo ~x\n" || action != "" {
		t.Errorf("a tilde off the line start must pass through: %q %q", out, action)
	}
}

func TestEscapeUnknownSequenceForwardsLiterally(t *testing.T) {
	out, action := feedAll(t, testEscapeConfig(), "\n~a")
	if out != "\n~a" || action != "" {
		t.Errorf("an unknown sequence must forward literally: %q %q", out, action)
	}
}

func TestEscapeDoubleTildeCollapses(t *testing.T) {
	out, action := feedAll(t, testEscapeConfig(), "\n~~x")
	if out != "\n~x" || action != "" {
		t.Errorf("~~ must collapse to one literal tilde: %q %q", out, action)
	}
}

func TestEscapeCarriageReturnArmsToo(t *testing.T) {
	// raw mode sends \r for Enter: the line start must arm on it as well
	out, action := feedAll(t, testEscapeConfig(), "abc\r~.")
	if out != "abc\r" || action != "disconnect" {
		t.Errorf("\\r must arm the line start: %q %q", out, action)
	}
}

func TestEscapeSplitAcrossChunks(t *testing.T) {
	out, action := feedAll(t, testEscapeConfig(), "\n~", ".rest")
	if out != "\n" {
		t.Errorf("after the disconnect nothing further must forward: %q", out)
	}

	if action != "disconnect" {
		t.Errorf("the split sequence must still fire: %q", action)
	}
}

func TestEscapeSuspend(t *testing.T) {
	cfg := testEscapeConfig()
	out, action := feedAll(t, cfg, "\n~\x1a")
	if out != "\n" {
		t.Errorf("the sequence must not be forwarded: %q", out)
	}

	if action != "suspend" {
		t.Errorf("action = %q, want suspend", action)
	}
}

func TestEscapeSuspendWithoutCallbackForwards(t *testing.T) {
	cfg := testEscapeConfig()
	cfg.Suspend = nil // no console suspend available (e.g. windows)

	out, action := feedAll(t, cfg, "\n~\x1a")
	if out != "\n~\x1a" || action != "" {
		t.Errorf("without a suspend callback the sequence must forward: %q %q", out, action)
	}
}

func TestEscapeDisabledPassesThrough(t *testing.T) {
	out, action := feedAll(t, nil, "\n~.")
	if out != "\n~." || action != "" {
		t.Errorf("a nil config must pass everything through: %q %q", out, action)
	}
}

func testEscapeConfig() *EscapeConfig {
	return &EscapeConfig{
		Char:       '~',
		Suspend:    func() error { return nil },
		Disconnect: func() error { return nil },
	}
}
