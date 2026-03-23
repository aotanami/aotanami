/*
Copyright 2026 Zelyo AI
*/

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// openAICompatClient implements Client for all OpenAI-compatible APIs
// (OpenRouter, OpenAI, Azure, Ollama, custom).
type openAICompatClient struct {
	cfg      Config
	endpoint string
	client   http.Client
}

// openAIChatRequest is the OpenAI chat completions request body.
type openAIChatRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	Temperature *float64        `json:"temperature,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openAIChatResponse is the OpenAI chat completions response body.
type openAIChatResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Message      openAIMessage `json:"message"`
		FinishReason string        `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

// Complete sends a chat completion request with retry logic.
func (c *openAICompatClient) Complete(ctx context.Context, req Request) (*Response, error) {
	body := c.buildRequestBody(req)
	return c.executeWithRetry(ctx, body)
}

func (c *openAICompatClient) buildRequestBody(req Request) openAIChatRequest {
	model := req.Model
	if model == "" {
		model = c.cfg.Model
	}

	temp := c.cfg.Temperature
	if req.Temperature != nil {
		temp = *req.Temperature
	}

	maxTokens := c.cfg.MaxTokens
	if req.MaxTokens > 0 {
		maxTokens = req.MaxTokens
	}

	messages := make([]openAIMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		messages = append(messages, openAIMessage{
			Role:    string(m.Role),
			Content: m.Content,
		})
	}

	return openAIChatRequest{
		Model:       model,
		Messages:    messages,
		Temperature: &temp,
		MaxTokens:   maxTokens,
	}
}

func (c *openAICompatClient) executeWithRetry(ctx context.Context, body openAIChatRequest) (*Response, error) {
	var lastErr error
	backoff := c.cfg.Retry.InitialBackoff
	if backoff == 0 {
		backoff = 500 * time.Millisecond
	}

	maxRetries := c.cfg.Retry.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			wait := backoff

			// If the previous error was a 429 with Retry-After, use that instead of backoff.
			if apiErr, ok := lastErr.(*APIError); ok && apiErr.RetryAfter > 0 {
				wait = apiErr.RetryAfter
			} else {
				// Apply jitter to the standard backoff.
				wait = time.Duration(float64(backoff) * (0.75 + rand.Float64()*0.5)) //nolint:gosec // Not security-sensitive
			}

			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("llm: context canceled during retry: %w", ctx.Err())
			case <-time.After(wait):
			}

			backoff = c.nextBackoff(backoff)
		}

		resp, err := c.doRequest(ctx, body)
		if err == nil {
			return resp, nil
		}

		lastErr = err
		if isNonRetryable(err) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("llm: all %d retries exhausted: %w", maxRetries, lastErr)
}

func (c *openAICompatClient) nextBackoff(current time.Duration) time.Duration {
	multiplier := c.cfg.Retry.BackoffMultiplier
	if multiplier == 0 {
		multiplier = 2.0
	}
	next := time.Duration(float64(current) * multiplier)
	maxBackoff := c.cfg.Retry.MaxBackoff
	if maxBackoff == 0 {
		maxBackoff = 10 * time.Second
	}
	if next > maxBackoff {
		next = maxBackoff
	}
	return next
}

func (c *openAICompatClient) doRequest(ctx context.Context, body openAIChatRequest) (*Response, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("llm: marshal request: %w", err)
	}

	url := c.endpoint + "/chat/completions"

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("llm: create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Set auth header based on provider.
	switch c.cfg.Provider {
	case ProviderAnthropic:
		httpReq.Header.Set("x-api-key", c.cfg.APIKey)
		httpReq.Header.Set("anthropic-version", "2023-06-01")
	default:
		httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	// Set extra headers for OpenRouter.
	if c.cfg.Provider == ProviderOpenRouter {
		httpReq.Header.Set("HTTP-Referer", "https://github.com/zelyo-ai/zelyo-operator")
		httpReq.Header.Set("X-Title", "Zelyo Operator")
	}

	start := time.Now()

	httpClient := c.client
	if c.cfg.Timeout > 0 {
		httpClient.Timeout = c.cfg.Timeout
	}

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm: HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("llm: read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		apiErr := &APIError{
			StatusCode: httpResp.StatusCode,
			Body:       string(respBody),
		}
		// Parse Retry-After header for 429 responses.
		if httpResp.StatusCode == http.StatusTooManyRequests {
			apiErr.RetryAfter = parseRetryAfter(httpResp.Header.Get("Retry-After"))
		}
		return nil, apiErr
	}

	var chatResp openAIChatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("llm: unmarshal response: %w", err)
	}

	if chatResp.Error != nil {
		return nil, &APIError{
			StatusCode: httpResp.StatusCode,
			Body:       chatResp.Error.Message,
		}
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("llm: empty response (no choices returned)")
	}

	return &Response{
		Content: chatResp.Choices[0].Message.Content,
		Model:   chatResp.Model,
		Usage: Usage{
			PromptTokens:     chatResp.Usage.PromptTokens,
			CompletionTokens: chatResp.Usage.CompletionTokens,
			TotalTokens:      chatResp.Usage.TotalTokens,
		},
		FinishReason: chatResp.Choices[0].FinishReason,
		Latency:      time.Since(start),
	}, nil
}

// Provider returns the underlying LLM provider.
func (c *openAICompatClient) Provider() Provider { return c.cfg.Provider }

// Close releases resources held by this client.
func (c *openAICompatClient) Close() error { return nil }

// APIError represents an error response from the LLM API.
type APIError struct {
	StatusCode int
	Body       string
	RetryAfter time.Duration // Parsed from Retry-After header on 429 responses.
}

func (e *APIError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("llm: API error %d (retry after %s): %s", e.StatusCode, e.RetryAfter, e.Body)
	}
	return fmt.Sprintf("llm: API error %d: %s", e.StatusCode, e.Body)
}

// parseRetryAfter parses a Retry-After header value.
// It supports both seconds (integer) and HTTP-date formats.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	// Try integer seconds first (most common for LLM APIs).
	if seconds, err := strconv.Atoi(val); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	// Try HTTP-date format.
	if t, err := http.ParseTime(val); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}

// isNonRetryable returns true for errors that should not be retried.
func isNonRetryable(err error) bool {
	apiErr, ok := err.(*APIError)
	if !ok {
		return false
	}
	// Retry 429 (rate limit) and 5xx (server errors).
	// Don't retry 4xx (client errors) except 429.
	return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 && apiErr.StatusCode != http.StatusTooManyRequests
}
