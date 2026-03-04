package llm

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubClient struct {
	provider Provider
	err      error
}

func (s *stubClient) Complete(_ context.Context, _ Request) (*Response, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &Response{Content: "ok"}, nil
}

func (s *stubClient) Provider() Provider { return s.provider }
func (s *stubClient) Close() error       { return nil }

func TestCircuitBreakerHalfOpenAllowsSingleProbe(t *testing.T) {
	cb := &circuitBreakerClient{
		inner:            &stubClient{provider: ProviderOpenAI, err: errors.New("boom")},
		failureThreshold: 1,
		resetTimeout:     20 * time.Millisecond,
	}

	// First failure opens the circuit.
	_, err := cb.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected first request to fail")
	}

	// Immediate retries should be blocked while OPEN.
	_, err = cb.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected open circuit to reject")
	}

	time.Sleep(25 * time.Millisecond)

	// After reset timeout, a single probe is allowed and transitions to HALF-OPEN.
	_, err = cb.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected half-open probe to fail with stub error")
	}

	// While HALF-OPEN probe result is pending/recorded, further requests should be rejected.
	_, err = cb.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected half-open circuit to reject concurrent probes")
	}
}

func TestCircuitBreakerClosesAfterSuccessfulProbe(t *testing.T) {
	stub := &stubClient{provider: ProviderOpenAI, err: errors.New("boom")}
	cb := &circuitBreakerClient{
		inner:            stub,
		failureThreshold: 1,
		resetTimeout:     20 * time.Millisecond,
	}

	_, _ = cb.Complete(context.Background(), Request{}) // open circuit
	time.Sleep(25 * time.Millisecond)

	// Make probe succeed.
	stub.err = nil
	_, err := cb.Complete(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected successful probe, got error: %v", err)
	}

	// Circuit should now be fully closed and allow normal traffic.
	_, err = cb.Complete(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected closed circuit to allow requests, got: %v", err)
	}
}
