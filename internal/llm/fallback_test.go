/*
Copyright 2026 Zelyo AI
*/

package llm

import (
	"context"
	"errors"
	"fmt"
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
		err:      fmt.Errorf("provider openai has 5 consecutive failures, retrying after 30s: %w", ErrCircuitBreakerOpen),
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
		{fmt.Errorf("provider openai: %w", ErrCircuitBreakerOpen), true},
		{ErrCircuitBreakerOpen, true},
	}

	for _, tt := range tests {
		got := isCircuitBreakerOpen(tt.err)
		if got != tt.want {
			t.Errorf("isCircuitBreakerOpen(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestFallbackClient_BothFailPreservesContext(t *testing.T) {
	primaryErr := fmt.Errorf("provider openai: %w", ErrCircuitBreakerOpen)
	fallbackErr := errors.New("ollama: connection refused")

	primary := &stubClient{provider: ProviderOpenAI, err: primaryErr}
	fallback := &stubClient{provider: ProviderOllama, err: fallbackErr}

	fc := NewFallbackClient(primary, fallback)
	_, err := fc.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected error when both primary and fallback fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "fallback failed") {
		t.Errorf("expected 'fallback failed' in error, got: %s", msg)
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("expected fallback error in message, got: %s", msg)
	}
	if !strings.Contains(msg, "primary") {
		t.Errorf("expected 'primary' context in message, got: %s", msg)
	}
}

func TestNewClient_FallbackConfigCreatesWrappedClient(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Provider = ProviderOllama
	cfg.APIKey = "" // Ollama doesn't need API key
	cfg.Fallback = &FallbackConfig{
		Provider: ProviderOllama,
		Model:    "llama3",
		Endpoint: "http://localhost:11434/v1",
	}

	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	fc, ok := client.(*FallbackClient)
	if !ok {
		t.Fatalf("expected *FallbackClient, got %T", client)
	}
	if fc.primary.Provider() != ProviderOllama {
		t.Errorf("expected primary provider %s, got %s", ProviderOllama, fc.primary.Provider())
	}
	if fc.fallback.Provider() != ProviderOllama {
		t.Errorf("expected fallback provider %s, got %s", ProviderOllama, fc.fallback.Provider())
	}
}
