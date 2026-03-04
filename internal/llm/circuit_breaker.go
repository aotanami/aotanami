/*
Copyright 2026 Zelyo AI.
*/

package llm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// circuitState represents the state of the circuit breaker.
type circuitState int

const (
	circuitClosed   circuitState = iota // Normal operation — requests flow through
	circuitOpen                         // Failing — requests rejected immediately
	circuitHalfOpen                     // Testing — one request allowed through
)

// circuitBreakerClient wraps an LLM client with circuit breaker logic.
type circuitBreakerClient struct {
	inner            Client
	failureThreshold int
	resetTimeout     time.Duration

	mu               sync.Mutex
	state            circuitState
	consecutiveFails int
	lastFailure      time.Time
}

// Complete sends a request through the circuit breaker.
func (cb *circuitBreakerClient) Complete(ctx context.Context, req Request) (*Response, error) {
	if err := cb.allowRequest(); err != nil {
		return nil, err
	}

	resp, err := cb.inner.Complete(ctx, req)
	cb.recordResult(err)

	return resp, err
}

func (cb *circuitBreakerClient) allowRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case circuitClosed:
		return nil

	case circuitOpen:
		// Check if enough time has passed to try again.
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = circuitHalfOpen
			return nil
		}
		return fmt.Errorf("llm: circuit breaker OPEN — provider %s has %d consecutive failures, retrying after %s",
			cb.inner.Provider(), cb.consecutiveFails, cb.resetTimeout-time.Since(cb.lastFailure))

	case circuitHalfOpen:
		return nil
	}

	return nil
}

func (cb *circuitBreakerClient) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.consecutiveFails++
		cb.lastFailure = time.Now()

		threshold := cb.failureThreshold
		if threshold == 0 {
			threshold = 5
		}

		if cb.consecutiveFails >= threshold {
			cb.state = circuitOpen
		}
	} else {
		// Success — reset to closed.
		cb.consecutiveFails = 0
		cb.state = circuitClosed
	}
}

// Provider returns the underlying LLM provider.
func (cb *circuitBreakerClient) Provider() Provider { return cb.inner.Provider() }

// Close releases resources held by this client.
func (cb *circuitBreakerClient) Close() error { return cb.inner.Close() }
