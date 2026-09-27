package client_pubkey_authentication

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// Regression test for CTO task stage 1 bug 4: a private key file that cannot
// be read must yield a clean error from PrepareRequestForAuth instead of a
// nil signing key that panics later in jwt.NewWithClaims. The conversation
// and round tripper are nil on purpose: the error path must trigger before
// any of them is dereferenced.
func TestPrepareRequestForAuthMissingPrivkeyReturnsError(t *testing.T) {
	method := &PrivkeyFileAuthMethod{filename: filepath.Join(t.TempDir(), "id_missing")}
	req := httptest.NewRequest(http.MethodPost, "https://example.com/ssh3-term", nil)
	err := method.PrepareRequestForAuth(req, nil, nil, "user", nil)
	if err == nil {
		t.Fatal("expected an error for an unreadable private key file, got nil")
	}
}
