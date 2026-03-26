/*
Copyright 2026 Zelyo AI
*/

package llm

import (
	"net/http"
	"testing"
	"time"
)

func TestParseRetryAfter_Seconds(t *testing.T) {
	d := parseRetryAfter("30")
	if d != 30*time.Second {
		t.Errorf("expected 30s, got %s", d)
	}
}

func TestParseRetryAfter_Zero(t *testing.T) {
	d := parseRetryAfter("0")
	if d != 0 {
		t.Errorf("expected 0, got %s", d)
	}
}

func TestParseRetryAfter_Empty(t *testing.T) {
	d := parseRetryAfter("")
	if d != 0 {
		t.Errorf("expected 0, got %s", d)
	}
}

func TestParseRetryAfter_InvalidString(t *testing.T) {
	d := parseRetryAfter("not-a-number")
	if d != 0 {
		t.Errorf("expected 0 for invalid input, got %s", d)
	}
}

func TestParseRetryAfter_HTTPDate(t *testing.T) {
	// Use a future time so that parseRetryAfter should return a positive duration.
	expiry := time.Now().Add(30 * time.Second)
	header := expiry.UTC().Format(http.TimeFormat)

	d := parseRetryAfter(header)
	if d <= 0 {
		t.Errorf("expected positive duration for HTTP-date, got %s", d)
	}
	// Allow a small margin for test execution time.
	if d > 30*time.Second+1*time.Second {
		t.Errorf("expected duration no greater than ~30s, got %s", d)
	}
}

func TestParseRetryAfter_HTTPDate_WithWhitespace(t *testing.T) {
	expiry := time.Now().Add(30 * time.Second)
	header := "  " + expiry.UTC().Format(http.TimeFormat) + "  "

	d := parseRetryAfter(header)
	if d <= 0 {
		t.Errorf("expected positive duration for padded HTTP-date, got %s", d)
	}
	if d > 30*time.Second+1*time.Second {
		t.Errorf("expected duration no greater than ~30s for padded HTTP-date, got %s", d)
	}
}
func TestAPIError_RetryAfterIncludedInMessage(t *testing.T) {
	err := &APIError{
		StatusCode: http.StatusTooManyRequests,
		Body:       "rate limited",
		RetryAfter: 60 * time.Second,
	}
	msg := err.Error()
	if msg != "llm: API error 429 (retry after 1m0s): rate limited" {
		t.Errorf("unexpected error message: %s", msg)
	}
}

func TestAPIError_NoRetryAfter(t *testing.T) {
	err := &APIError{
		StatusCode: 500,
		Body:       "internal error",
	}
	msg := err.Error()
	if msg != "llm: API error 500: internal error" {
		t.Errorf("unexpected error message: %s", msg)
	}
}

func TestIsNonRetryable_429IsRetryable(t *testing.T) {
	err := &APIError{StatusCode: http.StatusTooManyRequests, Body: "rate limited"}
	if isNonRetryable(err) {
		t.Error("429 should be retryable")
	}
}

func TestIsNonRetryable_401IsNotRetryable(t *testing.T) {
	err := &APIError{StatusCode: 401, Body: "unauthorized"}
	if !isNonRetryable(err) {
		t.Error("401 should not be retryable")
	}
}

func TestIsNonRetryable_500IsRetryable(t *testing.T) {
	err := &APIError{StatusCode: 500, Body: "server error"}
	if isNonRetryable(err) {
		t.Error("500 should be retryable")
	}
}
