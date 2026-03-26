/*
Copyright 2026 Zelyo AI
*/

package llm

import (
	"context"
	"errors"
	"fmt"
)

// FallbackClient wraps a primary LLM client with a fallback. When the primary
// client's circuit breaker is open, requests are automatically routed to the
// fallback client (e.g. a local Ollama instance).
type FallbackClient struct {
	primary  Client
	fallback Client
}

// NewFallbackClient creates a client that falls back to the secondary client
// when the primary's circuit breaker is open.
// If fallback is nil, this behaves identically to the primary client.
func NewFallbackClient(primary, fallback Client) Client {
	if fallback == nil {
		return primary
	}
	return &FallbackClient{primary: primary, fallback: fallback}
}

// Complete sends a request to the primary client. If the primary's circuit
// breaker is open, the request is transparently routed to the fallback.
func (f *FallbackClient) Complete(ctx context.Context, req Request) (*Response, error) {
	resp, err := f.primary.Complete(ctx, req)
	if err != nil && isCircuitBreakerOpen(err) {
		fbResp, fbErr := f.fallback.Complete(ctx, req)
		if fbErr != nil {
			return nil, fmt.Errorf("fallback failed: %w (primary: %v)", fbErr, err)
		}
		return fbResp, nil
	}
	return resp, err
}

// Provider returns the primary provider name.
func (f *FallbackClient) Provider() Provider { return f.primary.Provider() }

// Close releases resources held by both clients.
func (f *FallbackClient) Close() error {
	return errors.Join(f.primary.Close(), f.fallback.Close())
}

// isCircuitBreakerOpen checks if the error indicates the circuit breaker is open.
func isCircuitBreakerOpen(err error) bool {
	return errors.Is(err, ErrCircuitBreakerOpen)
}
