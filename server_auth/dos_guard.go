// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package server_auth

// The DoS guards of the auth phase, the CTO_TASK Stage 4.1 items:
//
//   - the MaxStartups analog: conversations sitting unauthenticated are
//     capped, a conversation over the cap is refused with 503 before any
//     identity work happens;
//   - the password brute-force lockout: after MaxPasswordAuthFailures
//     failures inside the window the user stays locked out for
//     PasswordLockoutDuration; a successful authentication clears the
//     record.
//
// The knobs are package variables settable from the server startup
// (-max-unauthenticated-conversations, -max-password-failures,
// -password-lockout-seconds / their SSH3_* env counterparts).

import (
	"sync"
	"time"
)

// MaxUnauthenticatedConversations caps the conversations that passed the
// CONNECT but not the authentication yet.
var MaxUnauthenticatedConversations = 100

// MaxPasswordAuthFailures is the number of failed password authentications
// that locks the account out of the password backend.
var MaxPasswordAuthFailures = 10

// PasswordLockoutDuration is how long the password backend refuses an
// account once the failure limit is hit.
var PasswordLockoutDuration = 60 * time.Second

var (
	unauthenticatedMu    sync.Mutex
	unauthenticatedCount int
)

// TryAcquireUnauthenticatedConversation admits one more conversation into
// the unauthenticated phase while the total stays under
// MaxUnauthenticatedConversations.
func TryAcquireUnauthenticatedConversation() bool {
	unauthenticatedMu.Lock()
	defer unauthenticatedMu.Unlock()

	if unauthenticatedCount >= MaxUnauthenticatedConversations {
		return false
	}

	unauthenticatedCount++
	return true
}

// ReleaseUnauthenticatedConversation gives one unauthenticated slot back;
// releasing more than acquired clamps at zero.
func ReleaseUnauthenticatedConversation() {
	unauthenticatedMu.Lock()
	defer unauthenticatedMu.Unlock()

	if unauthenticatedCount > 0 {
		unauthenticatedCount--
	}
}

// SetUnauthenticatedConversationLimitForTest swaps the cap for a test and
// returns its restore func.
func SetUnauthenticatedConversationLimitForTest(max int) func() {
	unauthenticatedMu.Lock()
	saved := MaxUnauthenticatedConversations
	MaxUnauthenticatedConversations = max
	unauthenticatedMu.Unlock()

	return func() {
		unauthenticatedMu.Lock()
		MaxUnauthenticatedConversations = saved
		unauthenticatedMu.Unlock()
	}
}

// passwordFailureRecord books the consecutive failures of one account and
// the instant its lockout expires.
type passwordFailureRecord struct {
	failures    int
	lockedUntil time.Time
}

var (
	passwordFailuresMu sync.Mutex
	passwordFailures   = make(map[string]*passwordFailureRecord)
)

// PasswordAuthLocked reports whether the account is currently locked out of
// the password backend. An expired lockout clears the record lazily.
func PasswordAuthLocked(user string) bool {
	passwordFailuresMu.Lock()
	defer passwordFailuresMu.Unlock()

	record, ok := passwordFailures[user]
	if !ok {
		return false
	}

	if time.Now().Before(record.lockedUntil) {
		return true
	}

	if !record.lockedUntil.IsZero() {
		delete(passwordFailures, user)
	}

	return false
}

// PasswordAuthFailure books one failed password authentication; hitting
// MaxPasswordAuthFailures locks the account for PasswordLockoutDuration.
func PasswordAuthFailure(user string) {
	passwordFailuresMu.Lock()
	defer passwordFailuresMu.Unlock()

	record, ok := passwordFailures[user]
	if !ok {
		record = &passwordFailureRecord{}
		passwordFailures[user] = record
	}

	if time.Now().Before(record.lockedUntil) {
		// the account is already locked: the lockout does not extend on
		// failures that never reached the password backend
		return
	}

	record.failures++
	if record.failures >= MaxPasswordAuthFailures {
		record.lockedUntil = time.Now().Add(PasswordLockoutDuration)
	}
}

// PasswordAuthSuccess clears the failure bookkeeping of the account.
func PasswordAuthSuccess(user string) {
	passwordFailuresMu.Lock()
	defer passwordFailuresMu.Unlock()

	delete(passwordFailures, user)
}

// SetPasswordLockoutForTest swaps the lockout knobs for a test and returns
// their restore func.
func SetPasswordLockoutForTest(maxFailures int, duration time.Duration) func() {
	passwordFailuresMu.Lock()
	savedMax, savedDuration := MaxPasswordAuthFailures, PasswordLockoutDuration
	MaxPasswordAuthFailures, PasswordLockoutDuration = maxFailures, duration
	passwordFailuresMu.Unlock()

	return func() {
		passwordFailuresMu.Lock()
		MaxPasswordAuthFailures, PasswordLockoutDuration = savedMax, savedDuration
		passwordFailuresMu.Unlock()
	}
}
