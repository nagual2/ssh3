// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package server_auth

// The DoS guards of the auth phase: the cap on conversations sitting
// unauthenticated (the MaxStartups analog) and the per-user password
// brute-force lockout.

import (
	"testing"
	"time"
)

func TestUnauthenticatedConversationLimit(t *testing.T) {
	restore := SetUnauthenticatedConversationLimitForTest(2)
	defer restore()

	if !TryAcquireUnauthenticatedConversation() || !TryAcquireUnauthenticatedConversation() {
		t.Fatal("the first two conversations must be admitted")
	}

	if TryAcquireUnauthenticatedConversation() {
		t.Error("the third conversation must be refused at the limit of 2")
	}

	ReleaseUnauthenticatedConversation()

	if !TryAcquireUnauthenticatedConversation() {
		t.Error("a conversation must be admitted again after a release")
	}

	// releasing more than acquired must not corrupt the counter
	ReleaseUnauthenticatedConversation()
	ReleaseUnauthenticatedConversation()
	ReleaseUnauthenticatedConversation()

	if !TryAcquireUnauthenticatedConversation() || !TryAcquireUnauthenticatedConversation() {
		t.Error("two conversations must be admitted again after the releases")
	}
}

func TestPasswordLockout(t *testing.T) {
	restore := SetPasswordLockoutForTest(3, 30*time.Millisecond)
	defer restore()

	user := "lockout-test-user"

	// under the limit every failure only books the count
	for i := 0; i < 2; i++ {
		if PasswordAuthLocked(user) {
			t.Fatalf("failure %d: the user must not be locked yet", i+1)
		}
		PasswordAuthFailure(user)
	}

	// the failure that reaches the limit locks the user
	if PasswordAuthLocked(user) {
		t.Fatal("the user must not be locked before the limit is hit")
	}
	PasswordAuthFailure(user)

	if !PasswordAuthLocked(user) {
		t.Fatal("the user must be locked after the third failure")
	}

	// a success clears the lockout (the legit user recovered)
	PasswordAuthSuccess(user)
	if PasswordAuthLocked(user) {
		t.Fatal("a success must clear the lockout")
	}

	// the lockout expires with the window
	for i := 0; i < 3; i++ {
		PasswordAuthFailure(user)
	}
	if !PasswordAuthLocked(user) {
		t.Fatal("the user must be locked again after three more failures")
	}

	time.Sleep(50 * time.Millisecond)

	if PasswordAuthLocked(user) {
		t.Fatal("the lockout must expire with the window")
	}
}

// the lockout is per user: another account is unaffected
func TestPasswordLockoutPerUser(t *testing.T) {
	restore := SetPasswordLockoutForTest(1, time.Second)
	defer restore()

	PasswordAuthFailure("victim-a")
	if !PasswordAuthLocked("victim-a") {
		t.Fatal("victim-a must be locked after the first failure")
	}

	if PasswordAuthLocked("victim-b") {
		t.Error("victim-b must be unaffected by victim-a's lockout")
	}
}
