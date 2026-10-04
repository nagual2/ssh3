package matchcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kevinburke/ssh_config"
)

// mustNew builds a Resolver, overriding the local user for deterministic
// user/localuser criteria tests.
func mustNew(t *testing.T, content, localUser string) *Resolver {
	t.Helper()
	r, err := New(filepath.Join(t.TempDir(), "config"), []byte(content))
	if err != nil {
		t.Fatalf("New() returned an unexpected error: %v", err)
	}
	r.localUser = localUser
	return r
}

// writeConfigFile writes content to name (a slash-separated relative path)
// under dir, creating the parent directories, and returns the full path.
func writeConfigFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("could not create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("could not write %s: %v", path, err)
	}
	return path
}

// mustResolveFile reads the config stored at path and resolves it for
// alias/user, mirroring the real client flow (ReadFile then New).
func mustResolveFile(t *testing.T, path, localUser, alias, user string) *ssh_config.Config {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	r, err := New(path, content)
	if err != nil {
		t.Fatalf("New(%q) returned an unexpected error: %v", path, err)
	}
	r.localUser = localUser
	cfg, err := r.ConfigForHost(alias, user)
	if err != nil {
		t.Fatalf("ConfigForHost(%q, %q) returned an unexpected error: %v", alias, user, err)
	}
	return cfg
}

// mustResolve resolves content for alias/user and returns the parsed config.
func mustResolve(t *testing.T, content, alias, user string) *ssh_config.Config {
	t.Helper()
	cfg, err := mustNew(t, content, "pilot").ConfigForHost(alias, user)
	if err != nil {
		t.Fatalf("ConfigForHost(%q, %q) returned an unexpected error: %v", alias, user, err)
	}
	return cfg
}

// mustGet is a Get wrapper that fails the test on error.
func mustGet(t *testing.T, cfg *ssh_config.Config, alias, key string) string {
	t.Helper()
	val, err := cfg.Get(alias, key)
	if err != nil {
		t.Fatalf("Get(%q, %q) returned an unexpected error: %v", alias, key, err)
	}
	return val
}

// mustGetAll is a GetAll wrapper that fails the test on error.
func mustGetAll(t *testing.T, cfg *ssh_config.Config, alias, key string) []string {
	t.Helper()
	vals, err := cfg.GetAll(alias, key)
	if err != nil {
		t.Fatalf("GetAll(%q, %q) returned an unexpected error: %v", alias, key, err)
	}
	return vals
}

// TestConfigWithoutMatchMatchesRawParse is the regression test: a config
// without Match blocks must resolve exactly like the plain ssh_config parse
// that ssh3 used before Match support existed.
func TestConfigWithoutMatchMatchesRawParse(t *testing.T) {
	content := `
# global defaults
Port 443
URLPath /

Host *.example.org !secret.example.org
	Port 8443
	IdentityFile ~/.ssh/id_a
	IdentityFile ~/.ssh/id_b

Host secret.example.org
	HostName 127.0.0.1
	User admin

Host web1
	HostName web1.example.org
`
	r := mustNew(t, content, "pilot")
	if r.hasMatch {
		t.Fatalf("a config without Match must not be flagged as having Match blocks")
	}
	raw, err := ssh_config.DecodeBytes([]byte(content))
	if err != nil {
		t.Fatalf("DecodeBytes() returned an unexpected error: %v", err)
	}
	for _, alias := range []string{"web1", "web2.example.org", "secret.example.org", "unknown.example.net"} {
		resolved, err := r.ConfigForHost(alias, "")
		if err != nil {
			t.Fatalf("ConfigForHost(%q) returned an unexpected error: %v", alias, err)
		}
		for _, key := range []string{"HostName", "Port", "User", "URLPath"} {
			want := mustGet(t, raw, alias, key)
			got := mustGet(t, resolved, alias, key)
			if got != want {
				t.Errorf("alias %q key %q: got %q, want %q", alias, key, got, want)
			}
		}
		wantIDs := mustGetAll(t, raw, alias, "IdentityFile")
		gotIDs := mustGetAll(t, resolved, alias, "IdentityFile")
		if strings.Join(gotIDs, "|") != strings.Join(wantIDs, "|") {
			t.Errorf("alias %q IdentityFile: got %v, want %v", alias, gotIDs, wantIDs)
		}
	}
}

// TestMatchHost checks that a Match host block applies only to the matching
// alias and that its values use the same first-wins rules. Note that the
// "host" criterion follows the HostName rewrite, exactly like OpenSSH.
func TestMatchHost(t *testing.T) {
	content := `
Host web1
	HostName web1.example.com

Match host web1.example.com
	Port 2222
`
	cfg := mustResolve(t, content, "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2222" {
		t.Errorf("matched host: got Port %q, want %q", got, "2222")
	}
	if got := mustGet(t, cfg, "web1", "HostName"); got != "web1.example.com" {
		t.Errorf("matched host: got HostName %q, want %q", got, "web1.example.com")
	}
	cfg = mustResolve(t, content, "otherhost", "")
	if got := mustGet(t, cfg, "otherhost", "Port"); got != "" {
		t.Errorf("non-matched host: got Port %q, want an empty value", got)
	}
}

// TestMatchHostNegation checks '!' and comma-separated pattern lists,
// including the OpenSSH rule that a matching negated pattern rejects the
// whole list even when another pattern matches.
func TestMatchHostNegation(t *testing.T) {
	content := `
Match host !web1,*.example.org
	Port 2222
`
	// web1 is excluded by the negated pattern.
	cfg := mustResolve(t, content, "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "" {
		t.Errorf("negated host: got Port %q, want an empty value", got)
	}
	// web2.example.org matches the positive pattern.
	cfg = mustResolve(t, content, "web2.example.org", "")
	if got := mustGet(t, cfg, "web2.example.org", "Port"); got != "2222" {
		t.Errorf("wildcard host: got Port %q, want %q", got, "2222")
	}
	// plain "other" matches nothing.
	cfg = mustResolve(t, content, "other", "")
	if got := mustGet(t, cfg, "other", "Port"); got != "" {
		t.Errorf("unrelated host: got Port %q, want an empty value", got)
	}
}

// TestMatchOriginalHostVersusHost checks that originalhost always matches the
// command-line alias while host follows the HostName rewrites of applied
// sections.
func TestMatchOriginalHostVersusHost(t *testing.T) {
	content := `
Match originalhost foo
	URLPath /by-original

Host foo
	HostName bar.internal

Match host bar.internal
	Port 2202

Match host foo
	Port 2203
`
	cfg := mustResolve(t, content, "foo", "")
	if got := mustGet(t, cfg, "foo", "URLPath"); got != "/by-original" {
		t.Errorf("originalhost: got URLPath %q, want %q", got, "/by-original")
	}
	// "Match host bar.internal" applies (effective host was rewritten by the
	// Host foo block) and its port is the first obtained one.
	if got := mustGet(t, cfg, "foo", "Port"); got != "2202" {
		t.Errorf("host after HostName rewrite: got Port %q, want %q", got, "2202")
	}
	// "Match host foo" no longer matches once the host was rewritten.
	ports := mustGetAll(t, cfg, "foo", "Port")
	if len(ports) != 1 || ports[0] != "2202" {
		t.Errorf("host after HostName rewrite: got all ports %v, want [2202]", ports)
	}

	// Connecting directly to the rewritten name also matches "host".
	cfg = mustResolve(t, content, "bar.internal", "")
	if got := mustGet(t, cfg, "bar.internal", "Port"); got != "2202" {
		t.Errorf("direct rewritten host: got Port %q, want %q", got, "2202")
	}
}

// TestMatchUserAndEvolution checks the user criterion, its negations and the
// fact that a User directive from an earlier section feeds later Match user
// evaluations, while an explicit user argument has priority.
func TestMatchUserAndEvolution(t *testing.T) {
	content := `
Host db
	User admin

Match user admin
	Port 2222

Match user !admin,*
	Port 2223
`
	// No CLI user: the Host db section sets User=admin, which the Match user
	// block then sees.
	cfg := mustResolve(t, content, "db", "")
	if got := mustGet(t, cfg, "db", "Port"); got != "2222" {
		t.Errorf("user from config: got Port %q, want %q", got, "2222")
	}
	// Explicit user=root: the config User directive must not override it.
	cfg = mustResolve(t, content, "db", "root")
	if got := mustGet(t, cfg, "db", "Port"); got != "2223" {
		t.Errorf("explicit user: got Port %q, want %q", got, "2223")
	}
	// Unrelated alias with no user anywhere: falls back to the local user.
	cfg = mustResolve(t, content, "other", "")
	if got := mustGet(t, cfg, "other", "Port"); got != "2223" {
		t.Errorf("local user fallback: got Port %q, want %q", got, "2223")
	}
}

// TestMatchLocalUser checks the localuser criterion against the local OS
// user name.
func TestMatchLocalUser(t *testing.T) {
	content := `
Match localuser pilot
	Port 2222

Match localuser !pilot
	Port 2223
`
	cfg := mustResolve(t, content, "anyhost", "")
	if got := mustGet(t, cfg, "anyhost", "Port"); got != "2222" {
		t.Errorf("localuser: got Port %q, want %q", got, "2222")
	}
}

// TestNonMatchingMatchBlockHasNoEffect checks acceptance case (c): a Match
// block whose criteria fail must not inject any value.
func TestNonMatchingMatchBlockHasNoEffect(t *testing.T) {
	content := `
Host web1
	HostName web1.example.com

Match final host nosuchhost
	Port 2222
	IdentityFile /nonexistent/key
`
	cfg := mustResolve(t, content, "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "" {
		t.Errorf("non-matching block leaked Port %q", got)
	}
	if got := mustGet(t, cfg, "web1", "HostName"); got != "web1.example.com" {
		t.Errorf("got HostName %q, want %q", got, "web1.example.com")
	}
	if ids := mustGetAll(t, cfg, "web1", "IdentityFile"); len(ids) != 0 {
		t.Errorf("non-matching block leaked IdentityFile %v", ids)
	}
}

// TestMultipleMatchFirstWins checks acceptance case (d): with several
// applicable Match blocks the first obtained value wins.
func TestMultipleMatchFirstWins(t *testing.T) {
	content := `
Match all
	Port 1111

Match host *
	Port 2222
`
	cfg := mustResolve(t, content, "anyhost", "")
	if got := mustGet(t, cfg, "anyhost", "Port"); got != "1111" {
		t.Errorf("got Port %q, want %q", got, "1111")
	}
	ports := mustGetAll(t, cfg, "anyhost", "Port")
	if strings.Join(ports, ",") != "1111,2222" {
		t.Errorf("got all ports %v, want [1111 2222]", ports)
	}
}

// TestMatchAllFinalCanonical checks acceptance case (e): "all" and "final"
// always match in the single ssh3 pass, "canonical" never does.
func TestMatchAllFinalCanonical(t *testing.T) {
	content := `
Match final
	Port 2201

Match canonical
	Port 2202

Match all
	Port 2203
`
	cfg := mustResolve(t, content, "anyhost", "")
	if got := mustGet(t, cfg, "anyhost", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
	ports := mustGetAll(t, cfg, "anyhost", "Port")
	if strings.Join(ports, ",") != "2201,2203" {
		t.Errorf("got all ports %v, want [2201 2203]", ports)
	}
}

// TestMatchPriorityAcrossHostBlocks checks that Match blocks interleave with
// Host blocks in document order for priorities.
func TestMatchPriorityAcrossHostBlocks(t *testing.T) {
	content := `
Match host web*
	Port 2222

Host *
	Port 22

Host web1
	Port 2201
`
	cfg := mustResolve(t, content, "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2222" {
		t.Errorf("web1: got Port %q, want %q", got, "2222")
	}
	cfg = mustResolve(t, content, "db", "")
	if got := mustGet(t, cfg, "db", "Port"); got != "22" {
		t.Errorf("db: got Port %q, want %q", got, "22")
	}
}

// TestHostBlockWinsBeforeMatch checks that an earlier matching Host block
// keeps priority over a later Match block.
func TestHostBlockWinsBeforeMatch(t *testing.T) {
	content := `
Host web1
	Port 2201

Match all
	Port 2222
`
	cfg := mustResolve(t, content, "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("web1: got Port %q, want %q", got, "2201")
	}
	cfg = mustResolve(t, content, "other", "")
	if got := mustGet(t, cfg, "other", "Port"); got != "2222" {
		t.Errorf("other: got Port %q, want %q", got, "2222")
	}
}

// TestMatchExec checks the exec criterion with an injected command runner.
func TestMatchExec(t *testing.T) {
	content := `
Match exec yes
	Port 2211

Match exec no
	Port 2212

Match host * exec yes
	Port 2213
`
	r := mustNew(t, content, "pilot")
	r.execRunner = func(command string) bool { return command == "yes" }
	cfg, err := r.ConfigForHost("anyhost", "")
	if err != nil {
		t.Fatalf("ConfigForHost() returned an unexpected error: %v", err)
	}
	if got := mustGet(t, cfg, "anyhost", "Port"); got != "2211" {
		t.Errorf("got Port %q, want %q", got, "2211")
	}
	ports := mustGetAll(t, cfg, "anyhost", "Port")
	if strings.Join(ports, ",") != "2211,2213" {
		t.Errorf("got all ports %v, want [2211 2213]", ports)
	}
}

// TestDefaultExecRunner checks the real command runner on both platforms.
func TestDefaultExecRunner(t *testing.T) {
	if !defaultExecRunner("exit 0") {
		t.Errorf("exit 0 must match")
	}
	if defaultExecRunner("exit 7") {
		t.Errorf("exit 7 must not match")
	}
	if defaultExecRunner("this-command-does-not-exist-xyz") {
		t.Errorf("a failing command must not match")
	}
}

// TestQuotedExecArgument checks that double quotes group exec arguments.
func TestQuotedExecArgument(t *testing.T) {
	content := `Match exec "my command with spaces"
	Port 2222
`
	r := mustNew(t, content, "pilot")
	var got string
	r.execRunner = func(command string) bool { got = command; return true }
	cfg, err := r.ConfigForHost("anyhost", "")
	if err != nil {
		t.Fatalf("ConfigForHost() returned an unexpected error: %v", err)
	}
	if got != "my command with spaces" {
		t.Errorf("exec received command %q", got)
	}
	if port := mustGet(t, cfg, "anyhost", "Port"); port != "2222" {
		t.Errorf("got Port %q, want %q", port, "2222")
	}
}

// TestMatchSyntaxErrors checks acceptance case (f): invalid Match criteria
// produce explicit errors, never panics.
func TestMatchSyntaxErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{"unknown criterion", "Match bogus foo\n", `unsupported Match criterion "bogus"`},
		{"missing host value", "Match host\n", `criterion "host" requires a value`},
		{"missing exec command", "Match exec\n", `criterion "exec" requires a value`},
		{"no criteria", "Match\n", "Match directive without criteria"},
		{"empty pattern list", "Match host ,\n", "empty pattern list"},
		{"unterminated quote", "Match exec \"unterminated\n", "unterminated quoted argument"},
		{"all combined with others", "Match all host web1\n", `cannot be combined with other Match attributes`},
		{"no-arg criterion with value", "Match final=yes\n", `unsupported Match criterion "final=yes"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New("config", []byte(c.content))
			if err == nil {
				t.Fatalf("New() succeeded, want an error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("got error %q, want it to contain %q", err.Error(), c.wantErr)
			}
		})
	}
}

// TestHostPatternEdgeParity checks that edge-case-but-valid Host patterns
// (regex metacharacters are escaped by ssh_config.NewPattern) resolve the
// same way on the fast path and on the Match path.
func TestHostPatternEdgeParity(t *testing.T) {
	content := `
Host a[b
	Port 2201

Match all
	Port 2222
`
	r := mustNew(t, content, "pilot")
	cfg, err := r.ConfigForHost("a[b", "")
	if err != nil {
		t.Fatalf("ConfigForHost() returned an unexpected error: %v", err)
	}
	if got := mustGet(t, cfg, "a[b", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
}

// TestMatchWithCRLFLineEndings checks that windows line endings are handled.
func TestMatchWithCRLFLineEndings(t *testing.T) {
	content := "Host web1\r\n\tPort 2201\r\n\r\nMatch all\r\n\tPort 2222\r\n"
	cfg := mustResolve(t, content, "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
	cfg = mustResolve(t, content, "other", "")
	if got := mustGet(t, cfg, "other", "Port"); got != "2222" {
		t.Errorf("got Port %q, want %q", got, "2222")
	}
}

// TestNilResolver checks that a nil Resolver resolves to a nil config.
func TestNilResolver(t *testing.T) {
	var r *Resolver
	cfg, err := r.ConfigForHost("anyhost", "")
	if cfg != nil || err != nil {
		t.Errorf("nil resolver: got (%v, %v), want (nil, nil)", cfg, err)
	}
}

// TestMatchAttributeNegationAndEqualsForm checks the OpenSSH '!' attribute
// negation and the "attr=value" inline form.
func TestMatchAttributeNegationAndEqualsForm(t *testing.T) {
	content := `
Match !host web1
	Port 2211

Match host=web1
	Port 2212
`
	cfg := mustResolve(t, content, "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2212" {
		t.Errorf("web1: got Port %q, want %q", got, "2212")
	}
	cfg = mustResolve(t, content, "other", "")
	if got := mustGet(t, cfg, "other", "Port"); got != "2211" {
		t.Errorf("other: got Port %q, want %q", got, "2211")
	}
}

// TestMatchNegatedAllNeverApplies checks that a negated "all" criterion is
// valid but never matches.
func TestMatchNegatedAllNeverApplies(t *testing.T) {
	content := `
Match !all
	Port 2211

Match final
	Port 2212
`
	cfg := mustResolve(t, content, "anyhost", "")
	if got := mustGet(t, cfg, "anyhost", "Port"); got != "2212" {
		t.Errorf("got Port %q, want %q", got, "2212")
	}
}

// TestConfigFromFileOnDisk exercises New with a real file path, as the client
// will use it.
func TestConfigFromFileOnDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	content := "Match host web1\n\tPort 2222\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("could not write temp config: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read temp config: %v", err)
	}
	r, err := New(path, b)
	if err != nil {
		t.Fatalf("New() returned an unexpected error: %v", err)
	}
	cfg, err := r.ConfigForHost("web1", "")
	if err != nil {
		t.Fatalf("ConfigForHost() returned an unexpected error: %v", err)
	}
	if got := mustGet(t, cfg, "web1", "Port"); got != "2222" {
		t.Errorf("got Port %q, want %q", got, "2222")
	}
}

// TestIncludeMatchBlocksAreFiltered checks the core acceptance case: Match
// blocks inside an included file must be evaluated like blocks of the main
// file. Without Include support the ssh_config parser rejects the included
// file (or ignores it), so nothing is filtered.
func TestIncludeMatchBlocksAreFiltered(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/web.conf", "Match host nosuchhost\n"+
		"\tPort 9999\n"+
		"\tIdentityFile /nonexistent/key\n"+
		"\n"+
		"Match host web1\n"+
		"\tPort 2202\n")
	path := writeConfigFile(t, dir, "config", "Include conf.d/web.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2202" {
		t.Errorf("matching Match in included file: got Port %q, want %q", got, "2202")
	}
	cfg = mustResolveFile(t, path, "pilot", "other", "")
	if got := mustGet(t, cfg, "other", "Port"); got != "" {
		t.Errorf("non-matching Match in included file leaked Port %q", got)
	}
	if ids := mustGetAll(t, cfg, "other", "IdentityFile"); len(ids) != 0 {
		t.Errorf("non-matching Match in included file leaked IdentityFile %v", ids)
	}
}

// TestIncludeHostSectionsApply checks that Host sections of an included file
// reach the ssh_config parser and are filtered by the alias.
func TestIncludeHostSectionsApply(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/hosts.conf", "Host web1\n"+
		"\tHostName web1.example.com\n"+
		"\tPort 2201\n"+
		"\n"+
		"Match host web1.example.com\n"+
		"\tURLPath /from-include\n")
	path := writeConfigFile(t, dir, "config", "Include conf.d/hosts.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "HostName"); got != "web1.example.com" {
		t.Errorf("got HostName %q, want %q", got, "web1.example.com")
	}
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
	// The Match block of the included file sees the HostName it provides.
	if got := mustGet(t, cfg, "web1", "URLPath"); got != "/from-include" {
		t.Errorf("got URLPath %q, want %q", got, "/from-include")
	}
	cfg = mustResolveFile(t, path, "pilot", "web2", "")
	if got := mustGet(t, cfg, "web2", "Port"); got != "" {
		t.Errorf("unrelated alias got Port %q, want an empty value", got)
	}
}

// TestIncludeContinuesEnclosingSection checks the OpenSSH rule that the
// content of an included file takes the place of the directive: lines that
// are not preceded by a Host/Match header stay in the surrounding block.
func TestIncludeContinuesEnclosingSection(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/extra.conf", "\tPort 2200\n\tURLPath /extra\n")
	path := writeConfigFile(t, dir, "config", "Host db\n"+
		"\tPort 22\n"+
		"Include conf.d/extra.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "db", "")
	// First obtained value wins, so the Port set before the Include applies.
	if got := mustGet(t, cfg, "db", "Port"); got != "22" {
		t.Errorf("got Port %q, want %q", got, "22")
	}
	if got := mustGet(t, cfg, "db", "URLPath"); got != "/extra" {
		t.Errorf("got URLPath %q, want %q", got, "/extra")
	}
	cfg = mustResolveFile(t, path, "pilot", "other", "")
	if got := mustGet(t, cfg, "other", "URLPath"); got != "" {
		t.Errorf("included directives leaked to the implicit Host * block: got URLPath %q", got)
	}
}

// TestIncludeInsideMatchBlock checks that an Include placed inside a Match
// block stays conditional on that block.
func TestIncludeInsideMatchBlock(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/web1.conf", "\tPort 2201\n\tIdentityFile ~/.ssh/id_web1\n")
	path := writeConfigFile(t, dir, "config", "Match host web1\nInclude conf.d/web1.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("web1: got Port %q, want %q", got, "2201")
	}
	if ids := mustGetAll(t, cfg, "web1", "IdentityFile"); len(ids) != 1 || ids[0] != "~/.ssh/id_web1" {
		t.Errorf("web1: got IdentityFile %v, want [~/.ssh/id_web1]", ids)
	}
	cfg = mustResolveFile(t, path, "pilot", "other", "")
	if got := mustGet(t, cfg, "other", "Port"); got != "" {
		t.Errorf("other: got Port %q, want an empty value", got)
	}
}

// TestNestedInclude checks that Include directives inside included files are
// expanded as well.
func TestNestedInclude(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/level1.conf", "Host web1\n\tPort 2201\nInclude level2.conf\n")
	writeConfigFile(t, dir, "conf.d/level2.conf", "Match host web1\n\tURLPath /nested\n")
	path := writeConfigFile(t, dir, "config", "Include conf.d/level1.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
	if got := mustGet(t, cfg, "web1", "URLPath"); got != "/nested" {
		t.Errorf("nested Match block: got URLPath %q, want %q", got, "/nested")
	}
	cfg = mustResolveFile(t, path, "pilot", "other", "")
	if got := mustGet(t, cfg, "other", "URLPath"); got != "" {
		t.Errorf("nested Match block leaked URLPath %q to an unrelated alias", got)
	}
}

// TestMultipleIncludeDirectives checks several Include directives in a row,
// including the first-obtained-wins order across files.
func TestMultipleIncludeDirectives(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/a.conf", "Host web1\n\tPort 2201\n")
	writeConfigFile(t, dir, "conf.d/b.conf", "Match host web1\n\tPort 2202\n\tURLPath /b\n")
	path := writeConfigFile(t, dir, "config", "Include conf.d/a.conf\nInclude conf.d/b.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
	if got := mustGet(t, cfg, "web1", "URLPath"); got != "/b" {
		t.Errorf("got URLPath %q, want %q", got, "/b")
	}
	ports := mustGetAll(t, cfg, "web1", "Port")
	if strings.Join(ports, ",") != "2201,2202" {
		t.Errorf("got all ports %v, want [2201 2202]", ports)
	}
}

// TestIncludeWildcardPath checks a glob pattern matching several files, which
// must be included in glob (lexicographic) order.
func TestIncludeWildcardPath(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/10-first.conf", "Match host web1\n\tPort 2201\n")
	writeConfigFile(t, dir, "conf.d/20-second.conf", "Match host web1\n\tPort 2202\n\tURLPath /second\n")
	writeConfigFile(t, dir, "conf.d/30-skipped.conf", "Match host nosuchhost\n\tPort 9999\n")
	path := writeConfigFile(t, dir, "config", "Include conf.d/*.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("first globbed file must win: got Port %q, want %q", got, "2201")
	}
	if got := mustGet(t, cfg, "web1", "URLPath"); got != "/second" {
		t.Errorf("got URLPath %q, want %q", got, "/second")
	}
	cfg = mustResolveFile(t, path, "pilot", "other", "")
	if got := mustGet(t, cfg, "other", "Port"); got != "" {
		t.Errorf("wildcard include leaked Port %q", got)
	}
}

// TestIncludeWithCRLFLineEndings checks that included files with windows line
// endings are handled, both for the file's own Host/Match headers and for the
// Match criteria.
func TestIncludeWithCRLFLineEndings(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/win.conf", "Match host web1\r\n\tPort 2201\r\n\r\nMatch host other\r\n\tURLPath /win\r\n")
	path := writeConfigFile(t, dir, "config", "Include conf.d/win.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("web1: got Port %q, want %q", got, "2201")
	}
	cfg = mustResolveFile(t, path, "pilot", "other", "")
	if got := mustGet(t, cfg, "other", "URLPath"); got != "/win" {
		t.Errorf("other: got URLPath %q, want %q", got, "/win")
	}
}

// TestIncludeMissingFileIsIgnored checks that an Include matching no file is
// silently ignored, as ssh(1) does with a non-matching glob.
func TestIncludeMissingFileIsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "config", "Include conf.d/no-such-file-xyz.conf\nHost web1\n\tPort 2201\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
}

// TestIncludeWithoutArgumentsIsIgnored checks that a bare Include directive is
// consumed by the pre-parser instead of reaching the ssh_config parser, which
// would glob the whole ~/.ssh directory for it.
func TestIncludeWithoutArgumentsIsIgnored(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "config", "Include\nHost web1\n\tPort 2201\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
}

// TestIncludeMultipleTargetsOnOneLine checks that one Include directive may
// list several files, like ssh(1).
func TestIncludeMultipleTargetsOnOneLine(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/a.conf", "Match host web1\n\tPort 2201\n")
	writeConfigFile(t, dir, "other/b.conf", "Match host web1\n\tURLPath /other\n")
	path := writeConfigFile(t, dir, "config", "Include conf.d/a.conf other/b.conf\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
	if got := mustGet(t, cfg, "web1", "URLPath"); got != "/other" {
		t.Errorf("got URLPath %q, want %q", got, "/other")
	}
}

// TestIncludeSelfReferenceTerminates checks that a cyclic Include does not
// loop forever.
func TestIncludeSelfReferenceTerminates(t *testing.T) {
	dir := t.TempDir()
	path := writeConfigFile(t, dir, "config", "Include config\nHost web1\n\tPort 2201\n")

	cfg := mustResolveFile(t, path, "pilot", "web1", "")
	if got := mustGet(t, cfg, "web1", "Port"); got != "2201" {
		t.Errorf("got Port %q, want %q", got, "2201")
	}
}

// TestIncludeMatchSyntaxErrorNamesIncludedFile checks that a Match syntax
// error inside an included file is reported with the included file name and
// line, not with those of the main config.
func TestIncludeMatchSyntaxErrorNamesIncludedFile(t *testing.T) {
	dir := t.TempDir()
	writeConfigFile(t, dir, "conf.d/broken.conf", "\nMatch bogus criterion\n")
	path := writeConfigFile(t, dir, "config", "Include conf.d/broken.conf\n")

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read %s: %v", path, err)
	}
	_, err = New(path, content)
	if err == nil {
		t.Fatalf("New() succeeded, want a Match syntax error from the included file")
	}
	if !strings.Contains(err.Error(), filepath.Join("conf.d", "broken.conf")) {
		t.Errorf("error %q must name the included file", err.Error())
	}
	if !strings.Contains(err.Error(), `unsupported Match criterion "bogus"`) {
		t.Errorf("error %q must explain the unsupported criterion", err.Error())
	}
}
