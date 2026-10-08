// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

import "testing"

func TestBudgetCapAdmitsAndRefuses(t *testing.T) {
	b := newBudget(2)
	if !b.tryAcquire() || !b.tryAcquire() {
		t.Fatal("the first two acquires must be admitted")
	}
	if b.tryAcquire() {
		t.Error("the third acquire must be refused at cap 2")
	}
	if got := b.current(); got != 2 {
		t.Errorf("current = %d, want 2", got)
	}
	b.release()
	if !b.tryAcquire() {
		t.Error("an acquire after a release must be admitted")
	}
}

func TestBudgetZeroCapIsUnlimited(t *testing.T) {
	b := newBudget(0)
	for i := 0; i < 1000; i++ {
		if !b.tryAcquire() {
			t.Fatalf("acquire %d must be admitted with cap 0", i)
		}
	}
}

func TestBudgetReleaseAboveAcquiredClampsAtZero(t *testing.T) {
	b := newBudget(1)
	b.release()
	if got := b.current(); got != 0 {
		t.Errorf("current = %d, want 0 (no negative counts)", got)
	}
}

func TestUserBudgetsRefusesPerUser(t *testing.T) {
	u := newUserBudgets(1)
	alice := u.budgetFor("alice")
	if !alice.tryAcquire() {
		t.Fatal("the first alice acquire must be admitted")
	}
	if alice.tryAcquire() {
		t.Error("the second alice acquire must be refused at limit 1")
	}
	// budgets are per user: bob is unaffected by alice's slot
	if !u.budgetFor("bob").tryAcquire() {
		t.Error("bob's first acquire must be admitted")
	}
	// the same user gets the same budget back
	if u.budgetFor("alice") != alice {
		t.Error("budgetFor must return a stable budget per user")
	}
}
