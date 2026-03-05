/*
Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.
*/

package notifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

func TestNotifier_Send(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New([]ChannelConfig{
		{
			Type:       ChannelWebhook,
			Name:       "test-webhook",
			WebhookURL: server.URL,
		},
	}, logr.Discard())

	err := n.Send(context.Background(), &Notification{
		Title:    "Test Alert",
		Message:  "Something happened",
		Severity: SeverityHigh,
		Source:   "test",
	})

	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	if received.Load() != 1 {
		t.Errorf("Expected 1 webhook call, got %d", received.Load())
	}
}

func TestNotifier_SeverityFiltering(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New([]ChannelConfig{
		{
			Type:        ChannelWebhook,
			Name:        "high-only",
			WebhookURL:  server.URL,
			MinSeverity: SeverityHigh,
		},
	}, logr.Discard())

	// Low severity — should be filtered out.
	_ = n.Send(context.Background(), &Notification{
		Title:    "Low Alert",
		Severity: SeverityLow,
		Source:   "test",
	})

	if received.Load() != 0 {
		t.Errorf("Expected 0 calls for low severity, got %d", received.Load())
	}

	// High severity — should be delivered.
	_ = n.Send(context.Background(), &Notification{
		Title:    "High Alert",
		Severity: SeverityHigh,
		Source:   "test",
	})

	if received.Load() != 1 {
		t.Errorf("Expected 1 call for high severity, got %d", received.Load())
	}
}

func TestNotifier_Deduplication(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New([]ChannelConfig{
		{
			Type:       ChannelWebhook,
			Name:       "dedup-test",
			WebhookURL: server.URL,
		},
	}, logr.Discard())

	notif := &Notification{
		Title:            "Duplicate Alert",
		Severity:         SeverityHigh,
		Source:           "test",
		DeduplicationKey: "same-key",
	}

	// First send should work.
	_ = n.Send(context.Background(), notif)
	// Second send with same key should be deduplicated.
	_ = n.Send(context.Background(), notif)

	if received.Load() != 1 {
		t.Errorf("Expected 1 call due to dedup, got %d", received.Load())
	}
}

func TestNotifier_WebhookPayloadFormat(t *testing.T) {
	var payload map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := New([]ChannelConfig{
		{
			Type:       ChannelWebhook,
			Name:       "payload-test",
			WebhookURL: server.URL,
		},
	}, logr.Discard())

	_ = n.Send(context.Background(), &Notification{
		Title:     "Security Violation",
		Message:   "Container running as root",
		Severity:  SeverityCritical,
		Source:    "securitypolicy",
		Namespace: "production",
	})

	if payload == nil {
		t.Fatal("Expected webhook payload")
	}
	// Webhook payloads should contain the notification fields.
	if _, ok := payload["title"]; !ok {
		t.Error("Expected 'title' key in webhook payload")
	}
}

func TestMeetsMinSeverity(t *testing.T) {
	tests := []struct {
		actual   Severity
		minimum  Severity
		expected bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityCritical, false},
		{SeverityInfo, SeverityInfo, true},
	}

	for _, tt := range tests {
		result := meetsMinSeverity(tt.actual, tt.minimum)
		if result != tt.expected {
			t.Errorf("meetsMinSeverity(%q, %q) = %v, want %v",
				tt.actual, tt.minimum, result, tt.expected)
		}
	}
}

func TestSeverityEmoji(t *testing.T) {
	for _, sev := range []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		emoji := severityEmoji(sev)
		if emoji == "" {
			t.Errorf("Expected non-empty emoji for %q", sev)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	rl := &rateLimiter{limit: 2, window: time.Now()}

	if !rl.allow() {
		t.Error("First call should be allowed")
	}
	if !rl.allow() {
		t.Error("Second call should be allowed")
	}
	if rl.allow() {
		t.Error("Third call should be rate limited")
	}
}
