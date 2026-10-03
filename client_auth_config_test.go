package ssh3

import (
	"os"
	"path/filepath"
	"testing"

	matchcfg "github.com/francoismichel/ssh3/client/config/matchcfg"
)

// TestGetConfigForHostWithMatch checks the client wiring: a config containing
// Match blocks resolves values through the matchcfg resolver.
func TestGetConfigForHostWithMatch(t *testing.T) {
	content := `
Host web1
	HostName web1.example.com
	Port 8443
	User web

Match host web1.example.com
	URLPath /matched
	IdentityFile ~/.ssh/id_a
	IdentityFile ~/.ssh/id_b
`
	r, err := matchcfg.New(filepath.Join(t.TempDir(), "config"), []byte(content))
	if err != nil {
		t.Fatalf("matchcfg.New() returned an unexpected error: %v", err)
	}
	hostname, port, user, urlPath, authMethods, pluginOptions, err := GetConfigForHost("web1", "", r, nil)
	if err != nil {
		t.Fatalf("GetConfigForHost() returned an unexpected error: %v", err)
	}
	if hostname != "web1.example.com" {
		t.Errorf("hostname = %q, want %q", hostname, "web1.example.com")
	}
	if port != 8443 {
		t.Errorf("port = %d, want 8443", port)
	}
	if user != "web" {
		t.Errorf("user = %q, want %q", user, "web")
	}
	if urlPath != "/matched" {
		t.Errorf("urlPath = %q, want %q", urlPath, "/matched")
	}
	if len(authMethods) != 2 {
		t.Errorf("authMethods = %v, want 2 identity file methods", authMethods)
	}
	if len(pluginOptions) != 0 {
		t.Errorf("pluginOptions = %v, want empty", pluginOptions)
	}

	// An alias not covered by the Host/Match blocks resolves to zero values.
	hostname, port, user, urlPath, authMethods, pluginOptions, err = GetConfigForHost("other", "", r, nil)
	if err != nil {
		t.Fatalf("GetConfigForHost() returned an unexpected error: %v", err)
	}
	if hostname != "" || port != -1 || user != "" || urlPath != "" || len(authMethods) != 0 || len(pluginOptions) != 0 {
		t.Errorf("unexpected values for uncovered alias: hostname=%q port=%d user=%q urlPath=%q authMethods=%v pluginOptions=%v",
			hostname, port, user, urlPath, authMethods, pluginOptions)
	}
}

// TestGetConfigForHostWithoutConfig checks the nil-resolver path (no config
// file or unparseable config): zero values and no error, as before Match
// support.
func TestGetConfigForHostWithoutConfig(t *testing.T) {
	hostname, port, user, urlPath, authMethods, pluginOptions, err := GetConfigForHost("web1", "", nil, nil)
	if err != nil {
		t.Fatalf("GetConfigForHost() returned an unexpected error: %v", err)
	}
	if hostname != "" || port != -1 || user != "" || urlPath != "" || len(authMethods) != 0 || len(pluginOptions) != 0 {
		t.Errorf("unexpected values without config: hostname=%q port=%d user=%q urlPath=%q authMethods=%v pluginOptions=%v",
			hostname, port, user, urlPath, authMethods, pluginOptions)
	}
}

// TestGetConfigForHostConfigFileOnDisk loads a config from a real temp file,
// mirroring the cmd flow (ReadFile then matchcfg.New).
func TestGetConfigForHostConfigFileOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	content := "Match host db\n\tPort 5432\n\tUser dbadmin\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("could not write temp config: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read temp config: %v", err)
	}
	r, err := matchcfg.New(path, b)
	if err != nil {
		t.Fatalf("matchcfg.New() returned an unexpected error: %v", err)
	}
	_, port, user, _, _, _, err := GetConfigForHost("db", "", r, nil)
	if err != nil {
		t.Fatalf("GetConfigForHost() returned an unexpected error: %v", err)
	}
	if port != 5432 || user != "dbadmin" {
		t.Errorf("port=%d user=%q, want 5432 and %q", port, user, "dbadmin")
	}
}
