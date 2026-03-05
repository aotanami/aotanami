/*
Copyright 2026 Zelyo AI
*/

package llm

import (
	"fmt"
	"sync"
	"time"
)

// TokenBudget tracks and enforces token usage limits across hourly, daily,
// and monthly windows. It is goroutine-safe.
type TokenBudget struct {
	mu sync.Mutex

	// Limits (0 = unlimited).
	hourlyLimit  int
	dailyLimit   int
	monthlyLimit int

	// Alert threshold percentage (0-100).
	alertThreshold int

	// Current usage.
	hourlyUsed  int
	dailyUsed   int
	monthlyUsed int

	// Window reset timestamps.
	hourlyReset  time.Time
	dailyReset   time.Time
	monthlyReset time.Time

	// AlertFunc is called when usage crosses the alert threshold.
	AlertFunc func(window string, used, limit int)
}

// NewTokenBudget creates a new token budget with the given limits.
func NewTokenBudget(hourly, daily, monthly, alertThresholdPct int) *TokenBudget {
	now := time.Now()
	return &TokenBudget{
		hourlyLimit:    hourly,
		dailyLimit:     daily,
		monthlyLimit:   monthly,
		alertThreshold: alertThresholdPct,
		hourlyReset:    now.Add(time.Hour),
		dailyReset:     now.Add(24 * time.Hour),
		monthlyReset:   now.AddDate(0, 1, 0),
	}
}

// Check returns an error if the requested tokens would exceed any budget.
// This does not consume tokens — call Record after a successful request.
func (tb *TokenBudget) Check(estimatedTokens int) error {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.resetExpiredWindows()

	if tb.hourlyLimit > 0 && tb.hourlyUsed+estimatedTokens > tb.hourlyLimit {
		return fmt.Errorf("llm: hourly token budget exhausted (%d/%d used, need %d)",
			tb.hourlyUsed, tb.hourlyLimit, estimatedTokens)
	}
	if tb.dailyLimit > 0 && tb.dailyUsed+estimatedTokens > tb.dailyLimit {
		return fmt.Errorf("llm: daily token budget exhausted (%d/%d used, need %d)",
			tb.dailyUsed, tb.dailyLimit, estimatedTokens)
	}
	if tb.monthlyLimit > 0 && tb.monthlyUsed+estimatedTokens > tb.monthlyLimit {
		return fmt.Errorf("llm: monthly token budget exhausted (%d/%d used, need %d)",
			tb.monthlyUsed, tb.monthlyLimit, estimatedTokens)
	}

	return nil
}

// Record records actual token usage after a completed request.
func (tb *TokenBudget) Record(tokens int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.resetExpiredWindows()

	tb.hourlyUsed += tokens
	tb.dailyUsed += tokens
	tb.monthlyUsed += tokens

	// Check alert thresholds.
	if tb.AlertFunc != nil && tb.alertThreshold > 0 {
		tb.checkAlert("hourly", tb.hourlyUsed, tb.hourlyLimit)
		tb.checkAlert("daily", tb.dailyUsed, tb.dailyLimit)
		tb.checkAlert("monthly", tb.monthlyUsed, tb.monthlyLimit)
	}
}

// Usage returns current usage across all windows.
func (tb *TokenBudget) Usage() (hourly, daily, monthly int) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.resetExpiredWindows()
	return tb.hourlyUsed, tb.dailyUsed, tb.monthlyUsed
}

func (tb *TokenBudget) resetExpiredWindows() {
	now := time.Now()
	if now.After(tb.hourlyReset) {
		tb.hourlyUsed = 0
		tb.hourlyReset = now.Add(time.Hour)
	}
	if now.After(tb.dailyReset) {
		tb.dailyUsed = 0
		tb.dailyReset = now.Add(24 * time.Hour)
	}
	if now.After(tb.monthlyReset) {
		tb.monthlyUsed = 0
		tb.monthlyReset = now.AddDate(0, 1, 0)
	}
}

func (tb *TokenBudget) checkAlert(window string, used, limit int) {
	if limit == 0 {
		return
	}
	pct := (used * 100) / limit
	if pct >= tb.alertThreshold {
		tb.AlertFunc(window, used, limit)
	}
}
