package llm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type stubClient struct {
	provider  Provider
	err       error
	blockCh   <-chan struct{}
	startedCh chan<- struct{}
}

func (s *stubClient) Complete(_ context.Context, _ Request) (*Response, error) {
	if s.startedCh != nil {
		s.startedCh <- struct{}{}
	}
	if s.blockCh != nil {
		<-s.blockCh
	}
	if s.err != nil {
		return nil, s.err
	}
	return &Response{Content: "ok"}, nil
}

func (s *stubClient) Provider() Provider { return s.provider }
func (s *stubClient) Close() error       { return nil }

func TestCircuitBreakerOpenStateRejectsUntilResetTimeout(t *testing.T) {
	cb := &circuitBreakerClient{
		inner:            &stubClient{provider: ProviderOpenAI, err: errors.New("boom")},
		failureThreshold: 1,
		resetTimeout:     30 * time.Second,
	}

	_, err := cb.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected failure to open circuit")
	}

	_, err = cb.Complete(context.Background(), Request{})
	if err == nil || !errors.Is(err, ErrCircuitBreakerOpen) {
		t.Fatalf("expected open-circuit rejection, got: %v", err)
	}

	cb.mu.Lock()
	cb.lastFailure = time.Now().Add(-cb.resetTimeout - time.Second)
	cb.mu.Unlock()

	_, err = cb.Complete(context.Background(), Request{})
	if err == nil {
		t.Fatal("expected probe request to fail with stub client error")
	}
}

func TestCircuitBreakerHalfOpenAllowsOnlyOneInFlightProbe(t *testing.T) {
	unblock := make(chan struct{})
	started := make(chan struct{}, 1)
	cb := &circuitBreakerClient{
		inner:            &stubClient{provider: ProviderOpenAI, blockCh: unblock, startedCh: started},
		failureThreshold: 1,
		resetTimeout:     time.Second,
		state:            circuitHalfOpen,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var firstErr error
	go func() {
		defer wg.Done()
		_, firstErr = cb.Complete(context.Background(), Request{})
	}()

	<-started

	_, err := cb.Complete(context.Background(), Request{})
	if err == nil || !strings.Contains(err.Error(), "circuit breaker HALF-OPEN") {
		t.Fatalf("expected half-open rejection while probe is in flight, got: %v", err)
	}

	close(unblock)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("expected probe to succeed, got: %v", firstErr)
	}
}

func TestCircuitBreakerClosesAfterSuccessfulProbe(t *testing.T) {
	stub := &stubClient{provider: ProviderOpenAI, err: errors.New("boom")}
	cb := &circuitBreakerClient{
		inner:            stub,
		failureThreshold: 1,
		resetTimeout:     time.Second,
	}

	_, _ = cb.Complete(context.Background(), Request{})

	cb.mu.Lock()
	cb.lastFailure = time.Now().Add(-cb.resetTimeout - time.Second)
	cb.mu.Unlock()

	stub.err = nil
	_, err := cb.Complete(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected successful probe, got error: %v", err)
	}

	_, err = cb.Complete(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected closed circuit to allow requests, got: %v", err)
	}
}
