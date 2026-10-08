// Copyright 2026 The nagual2 ssh3 Authors.
// SPDX-License-Identifier: Apache-2.0

package cmd

// Admission budgets for the resource-expensive server work (S2-02): a
// conversation's concurrent channels and a user's concurrent sftp children.
// A cap of 0 disables the budget (the historical unbounded behavior).

import (
	"sync"
)

// budget is a counting semaphore with an optional cap: tryAcquire admits
// work only while the current count stays under the cap.
type budget struct {
	mu  sync.Mutex
	cur int
	cap int
}

func newBudget(cap int) *budget {
	return &budget{cap: cap}
}

// tryAcquire reports whether one more unit fits the budget.
func (b *budget) tryAcquire() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cap > 0 && b.cur >= b.cap {
		return false
	}
	b.cur++
	return true
}

// release returns one unit to the budget; releasing more than acquired
// clamps at zero.
func (b *budget) release() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cur > 0 {
		b.cur--
	}
}

func (b *budget) current() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cur
}

// userBudgets bounds concurrent work per authenticated user across their
// conversations (the sftp children are process-per-channel, so the
// per-conversation channel budget alone cannot bound one user's footprint).
type userBudgets struct {
	mu      sync.Mutex
	limit   int
	perUser map[string]*budget
}

func newUserBudgets(limit int) *userBudgets {
	return &userBudgets{limit: limit, perUser: make(map[string]*budget)}
}

func (u *userBudgets) budgetFor(user string) *budget {
	u.mu.Lock()
	defer u.mu.Unlock()
	b, ok := u.perUser[user]
	if !ok {
		b = newBudget(u.limit)
		u.perUser[user] = b
	}
	return b
}
