// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package server_pubkey_authentication

// The proof of the jti binding (CTO_TASK Stage 4.1, token replay): the JWT
// the client mints carries the base64-encoded conversation ID in its jti
// claim and the verifier must reject the very same token replayed against
// another conversation.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mintToken(t *testing.T, key ed25519.PrivateKey, username, jti string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss":       username,
		"exp":       jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
		"sub":       "ssh3",
		"aud":       "unused",
		"client_id": "ssh3-" + username,
		"jti":       jti,
	})

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("could not sign the token: %v", err)
	}

	return signed
}

func TestJtiBindingPreventsTokenReplay(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate the key: %v", err)
	}

	verifier := &PubkeyJWTIdentityVerifier{
		pubkey:   priv.Public(),
		username: "tester",
	}

	convA := base64.StdEncoding.EncodeToString([]byte("conversation-A"))
	convB := base64.StdEncoding.EncodeToString([]byte("conversation-B"))

	token := mintToken(t, priv, "tester", convA)

	// the token of conversation A verifies on conversation A...
	request, err := http.NewRequest(http.MethodConnect, "https://example.invalid/ssh3-term", nil)
	if err != nil {
		t.Fatalf("could not build the request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)

	if !verifier.Verify(request, convA) {
		t.Fatal("the token must verify on the conversation it was minted for")
	}

	// ...and must be refused when replayed against conversation B
	if verifier.Verify(request, convB) {
		t.Fatal("a token replayed against another conversation must be refused (jti binding)")
	}

	// a token whose jti does not match at all (empty) is refused as well
	bareToken := mintToken(t, priv, "tester", "")
	request.Header.Set("Authorization", "Bearer "+bareToken)
	if verifier.Verify(request, convA) {
		t.Fatal("a token with a mismatching jti must be refused")
	}
}
