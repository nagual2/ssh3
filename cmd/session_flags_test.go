package cmd

import "testing"

// -t has to work with no local terminal at all: the geometry then falls back to
// 80x24 and the terminal type to the caller-resolved value, which is what a
// remote ncurses program needs to render anything sensible.
func TestNewForcedPtySpecWithoutTerminal(t *testing.T) {
	t.Setenv("TERM", "")
	spec, err := newForcedPtySpec(nil, resolveTermType("", ""))
	if err != nil {
		t.Fatalf("newForcedPtySpec(nil) returned error: %s", err)
	}
	if spec.Term != "xterm-256color" {
		t.Errorf("term = %q, want xterm-256color", spec.Term)
	}
	if spec.Columns != 80 || spec.Rows != 24 {
		t.Errorf("geometry = %dx%d, want 80x24", spec.Columns, spec.Rows)
	}
}

// The caller-resolved terminal type is passed through to the pty request,
// as OpenSSH does with the local console type.
func TestNewForcedPtySpecUsesResolvedTerm(t *testing.T) {
	spec, err := newForcedPtySpec(nil, "xterm-256color")
	if err != nil {
		t.Fatalf("newForcedPtySpec(nil) returned error: %s", err)
	}
	if spec.Term != "xterm-256color" {
		t.Errorf("term = %q, want xterm-256color", spec.Term)
	}
}

// The interactive sftp client parses its commands before touching the network,
// so a typo is reported without a round trip.
func TestParseSFTPCommand(t *testing.T) {
	tests := []struct {
		line     string
		wantName string
		wantArgs []string
		wantErr  bool
	}{
		{line: "pwd\n", wantName: "pwd", wantArgs: []string{}},
		{line: "ls\n", wantName: "ls", wantArgs: []string{}},
		{line: "ls /tmp\n", wantName: "ls", wantArgs: []string{"/tmp"}},
		{line: "cd\n", wantName: "cd", wantArgs: []string{}},
		{line: "cd /var/log\n", wantName: "cd", wantArgs: []string{"/var/log"}},
		{line: "get notes.txt\n", wantName: "get", wantArgs: []string{"notes.txt"}},
		{line: "put local.txt /tmp/remote.txt\n", wantName: "put", wantArgs: []string{"local.txt", "/tmp/remote.txt"}},
		{line: "put \"two words.txt\" /tmp/x\n", wantName: "put", wantArgs: []string{"two words.txt", "/tmp/x"}},
		{line: "mkdir /tmp/new\n", wantName: "mkdir", wantArgs: []string{"/tmp/new"}},
		{line: "rm /tmp/old\n", wantName: "rm", wantArgs: []string{"/tmp/old"}},
		{line: "quit\n", wantName: "quit", wantArgs: []string{}},
		{line: "exit", wantName: "exit", wantArgs: []string{}},
		{line: "\n", wantErr: true},
		{line: "   \n", wantErr: true},
		{line: "bogus arg\n", wantErr: true},
		{line: "get\n", wantErr: true},
		{line: "put only-one-argument\n", wantErr: true},
		{line: "cd a b\n", wantErr: true},
		{line: "put \"unbalanced\n", wantErr: true},
	}

	for _, test := range tests {
		command, err := parseSFTPCommand(test.line)
		if test.wantErr {
			if err == nil {
				t.Errorf("parseSFTPCommand(%q) = %+v, want an error", test.line, command)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSFTPCommand(%q) returned error: %s", test.line, err)
			continue
		}
		if command.name != test.wantName {
			t.Errorf("parseSFTPCommand(%q).name = %q, want %q", test.line, command.name, test.wantName)
		}
		if len(command.args) != len(test.wantArgs) {
			t.Errorf("parseSFTPCommand(%q).args = %v, want %v", test.line, command.args, test.wantArgs)
			continue
		}
		for i, arg := range test.wantArgs {
			if command.args[i] != arg {
				t.Errorf("parseSFTPCommand(%q).args[%d] = %q, want %q", test.line, i, command.args[i], arg)
			}
		}
	}
}

// A remote path is resolved against the current remote directory, exactly like
// the sftp(1) shell does, and an absolute path ignores it.
func TestResolveRemoteSFTPPath(t *testing.T) {
	tests := []struct {
		current  string
		path     string
		want     string
		wantIsCd bool
	}{
		{current: "/home/user", path: "", want: "/home/user", wantIsCd: true},
		{current: "/home/user", path: "notes.txt", want: "/home/user/notes.txt"},
		{current: "/home/user", path: "/etc/hosts", want: "/etc/hosts"},
		{current: "/home/user", path: "..", want: "/home", wantIsCd: true},
		{current: "/home/user", path: ".", want: "/home/user", wantIsCd: true},
	}
	for _, test := range tests {
		resolved, isCd := resolveRemoteSFTPPath(test.current, test.path)
		if resolved != test.want {
			t.Errorf("resolveRemoteSFTPPath(%q, %q) = %q, want %q", test.current, test.path, resolved, test.want)
		}
		if isCd != test.wantIsCd {
			t.Errorf("resolveRemoteSFTPPath(%q, %q) isCd = %v, want %v", test.current, test.path, isCd, test.wantIsCd)
		}
	}
}
