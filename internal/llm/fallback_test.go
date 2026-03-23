/*
Copyright 2026 Zelyo AI
*/

package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFallbackClient_PrimarySucceeds(t *testing.T) {
	primary := &stubClient{provider: ProviderOpenAI}
	fallback := &stubClient{provider: ProviderOllama}

	fc := NewFallbackClient(primary, fallback)
	resp, err := fc.Complete(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
	if resp.Content != "ok" {
		t.Errorf("expected 'ok', got %q", resp.Content)
	}
}

func TestFallbackClient_CircuitBreakerOpenFallsBack(t *testing.T) {
	primary := &stubClient{
		provider: ProviderOpenAI,
		err:      errors.New("llm: circuit breaker OPEN — provider openai has 5 consecutive failures, retrying after 30s"),
	}
	fallback := &stubClient{provider: ProviderOllama}

	fc := NewFallbackClient(primary, fallback)
	resp, err := fc.Complete(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected fallback to succeed, got: %v", err)
	}
	if resp.Content != "ok" {
		t.Errorf("expected fallback response 'ok', got %q", resp.Content)
	}
}

func TestFallbackClient_NonCircuitBreakerErrorPropagates(t *testing.T) {
	primary := &stubClient{
		provider: ProviderOpenAI,
		err:      errors.New("llm: API error 401: unauthorized"),
	}
	fallback := &stubClient{provider: ProviderOllama}

	fc := NewFallbackClient(primary, fallback)
	_, err := fc.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected error to propagate, got nil")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("expected original error, got: %v", err)
	}
}

func TestFallbackClient_NilFallbackReturnsPrimary(t *testing.T) {
	primary := &stubClient{provider: ProviderOpenAI}
	fc := NewFallbackClient(primary, nil)

	// Should return the primary directly (not wrapped).
	if _, ok := fc.(*FallbackClient); ok {
		t.Error("expected nil fallback to return primary directly, got FallbackClient wrapper")
	}
}

func TestIsCircuitBreakerOpen(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("some random error"), false},
		{errors.New("llm: circuit breaker OPEN — provider openai"), true},
		{errors.New("circuit breaker OPEN"), true},
	}

	for _, tt := range tests {
		got := isCircuitBreakerOpen(tt.err)
		if got != tt.want {
			t.Errorf("isCircuitBreakerOpen(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}
