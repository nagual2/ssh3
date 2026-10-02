// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

// resolveJailed tests (bug 6 fix): jail-relative and server-absolute paths
// share the wire; escapes stay rejected in both spellings.

import (
	"path/filepath"
	"testing"
)

func TestResolveJailedRelativePaths(t *testing.T) {
	h := &sftpHandlers{root: `/home/user`}
	cases := map[string]string{
		"docs/f.txt":      `/home/user/docs/f.txt`,
		"/docs/f.txt":     `/home/user/docs/f.txt`,
		"":                `/home/user`,
		"/":               `/home/user`,
		".":               `/home/user`,
		"a/../b":          `/home/user/b`,
		"/sub/./x.tar.gz": `/home/user/sub/x.tar.gz`,
	}
	for in, want := range cases {
		got, err := h.resolveJailed(in)
		if err != nil {
			t.Fatalf("resolveJailed(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("resolveJailed(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveJailedServerAbsolutePaths(t *testing.T) {
	h := &sftpHandlers{root: `/home/user`}
	cases := map[string]string{
		`/home/user`:            `/home/user`,
		`/home/user/docs/f.txt`: `/home/user/docs/f.txt`,
		`/home/user/../user/f`:  `/home/user/f`,
	}
	for in, want := range cases {
		got, err := h.resolveJailed(in)
		if err != nil {
			t.Fatalf("resolveJailed(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("resolveJailed(%q) = %q, want %q", in, got, want)
		}
	}
}

// ".." segments can never escape the jail: they collapse into the
// home-relative namespace, matching chroot-like containment.
func TestResolveJailedCollapsesDotDotIntoJail(t *testing.T) {
	h := &sftpHandlers{root: `/home/user`}
	cases := map[string]string{
		"../../etc/passwd":            `/home/user/etc/passwd`,
		"/home/user/../../etc/passwd": `/home/user/etc/passwd`,
	}
	for in, want := range cases {
		got, err := h.resolveJailed(in)
		if err != nil {
			t.Fatalf("resolveJailed(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("resolveJailed(%q) = %q, want %q", in, got, want)
		}
	}
}

// Absolute paths outside the jail fall back to the jail-relative namespace
// (pre-fix behavior): they can only ever land inside the home directory.
func TestResolveJailedAbsoluteOutsideJailFallsBack(t *testing.T) {
	h := &sftpHandlers{root: `/home/user`}
	cases := map[string]string{
		"/etc/passwd":       `/home/user/etc/passwd`,
		"/home/other/f.txt": `/home/user/home/other/f.txt`,
	}
	for in, want := range cases {
		got, err := h.resolveJailed(in)
		if err != nil {
			t.Fatalf("resolveJailed(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("resolveJailed(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveJailedTrailingSeparator(t *testing.T) {
	h := &sftpHandlers{root: string(filepath.Separator) + `home` + string(filepath.Separator) + `user`}
	got, err := h.resolveJailed(`/home/user/docs/`)
	if err != nil {
		t.Fatalf("resolveJailed: %v", err)
	}
	if got != `/home/user/docs` && got != `/home/user/docs/` {
		t.Fatalf("resolveJailed trailing separator = %q", got)
	}
}
