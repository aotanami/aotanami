/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package llm provides a unified client for interacting with Large Language
// Models (LLMs). It supports multiple providers (OpenRouter, OpenAI, Anthropic,
// Azure OpenAI, Ollama, custom) behind a common interface with production
// features: retry with exponential backoff, circuit breaker, token budgeting,
// and prompt/response caching.
package llm

import (
	"context"
	"fmt"
	"time"
)

// Provider identifies which LLM backend to use.
type Provider string

// Enumeration values.
const (
	ProviderOpenRouter Provider = "openrouter"
	ProviderOpenAI     Provider = "openai"
	ProviderAnthropic  Provider = "anthropic"
	ProviderAzure      Provider = "azure-openai"
	ProviderOllama     Provider = "ollama"
	ProviderCustom     Provider = "custom"
)

// Role identifies the sender of a message in a conversation.
type Role string

// Enumeration values.
const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message represents a single message in a conversation.
type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// Request represents a completion request to an LLM.
type Request struct {
	// Messages is the conversation history to send.
	Messages []Message `json:"messages"`

	// Model overrides the default model for this request.
	Model string `json:"model,omitempty"`

	// Temperature controls randomness (0.0 = deterministic, 1.0 = creative).
	Temperature *float64 `json:"temperature,omitempty"`

	// MaxTokens limits the response length.
	MaxTokens int `json:"max_tokens,omitempty"`

	// Metadata is opaque data passed through for logging/tracing.
	Metadata map[string]string `json:"-"`
}

// Response represents the LLM's reply.
type Response struct {
	// Content is the generated text.
	Content string `json:"content"`

	// Model is the model that produced this response.
	Model string `json:"model"`

	// Usage is the token usage for this request.
	Usage Usage `json:"usage"`

	// FinishReason indicates why generation stopped.
	FinishReason string `json:"finish_reason"`

	// Latency is the round-trip time for this request.
	Latency time.Duration `json:"-"`

	// Cached indicates whether this response was served from cache.
	Cached bool `json:"-"`
}

// Usage tracks token consumption for a single request.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Client is the interface for LLM interactions. All providers implement this.
type Client interface {
	// Complete sends a completion request and returns the response.
	Complete(ctx context.Context, req Request) (*Response, error)

	// Provider returns the name of the underlying provider.
	Provider() Provider

	// Close releases any resources held by the client.
	Close() error
}

// Config holds the configuration for creating an LLM client.
type Config struct {
	// Provider is the LLM backend to use.
	Provider Provider `json:"provider"`

	// Model is the default model identifier.
	Model string `json:"model"`

	// APIKey is the authentication key.
	APIKey string `json:"-"`

	// Endpoint is the API base URL (required for ollama/custom, optional otherwise).
	Endpoint string `json:"endpoint,omitempty"`

	// Temperature is the default temperature for requests.
	Temperature float64 `json:"temperature"`

	// MaxTokens is the default max tokens per request.
	MaxTokens int `json:"max_tokens"`

	// Timeout is the per-request timeout.
	Timeout time.Duration `json:"timeout"`

	// RetryConfig configures retry behavior.
	Retry RetryConfig `json:"retry"`

	// CircuitBreaker configures circuit breaker behavior.
	CircuitBreaker CircuitBreakerConfig `json:"circuit_breaker"`

	// Fallback configures an optional fallback provider (e.g. local Ollama)
	// that is used when the primary provider's circuit breaker opens.
	Fallback *FallbackConfig `json:"fallback,omitempty"`
}

// RetryConfig configures exponential backoff retry.
type RetryConfig struct {
	// MaxRetries is the maximum number of retry attempts.
	MaxRetries int `json:"max_retries"`

	// InitialBackoff is the initial wait between retries.
	InitialBackoff time.Duration `json:"initial_backoff"`

	// MaxBackoff is the maximum wait between retries.
	MaxBackoff time.Duration `json:"max_backoff"`

	// BackoffMultiplier is the multiplier for exponential backoff.
	BackoffMultiplier float64 `json:"backoff_multiplier"`
}

// CircuitBreakerConfig controls when to stop sending requests to a failing provider.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening the circuit.
	FailureThreshold int `json:"failure_threshold"`

	// ResetTimeout is how long to wait before attempting to close the circuit.
	ResetTimeout time.Duration `json:"reset_timeout"`
}

// DefaultConfig returns a production-ready default configuration.
func DefaultConfig() Config {
	return Config{
		Provider:    ProviderOpenRouter,
		Model:       "anthropic/claude-sonnet-4-20250514",
		Temperature: 0.1,
		MaxTokens:   4096,
		Timeout:     30 * time.Second,
		Retry: RetryConfig{
			MaxRetries:        3,
			InitialBackoff:    500 * time.Millisecond,
			MaxBackoff:        10 * time.Second,
			BackoffMultiplier: 2.0,
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 5,
			ResetTimeout:     30 * time.Second,
		},
	}
}

// FallbackConfig configures a fallback LLM provider.
type FallbackConfig struct {
	// Provider is the fallback LLM backend (typically "ollama").
	Provider Provider `json:"provider"`

	// Model is the fallback model identifier.
	Model string `json:"model"`

	// Endpoint is the fallback API URL.
	Endpoint string `json:"endpoint,omitempty"`

	// APIKey is the fallback auth key (empty for Ollama).
	APIKey string `json:"-"`
}

// NewClient creates a new LLM client for the given provider.
//
//nolint:gocritic // Config is a constructor param; intentional value copy
func NewClient(cfg Config) (Client, error) {
	if cfg.APIKey == "" && cfg.Provider != ProviderOllama {
		return nil, fmt.Errorf("llm: API key required for provider %s", cfg.Provider)
	}

	var endpoint string
	switch cfg.Provider {
	case ProviderOpenRouter:
		endpoint = defaultEndpoint(cfg.Endpoint, "https://openrouter.ai/api/v1")
	case ProviderOpenAI:
		endpoint = defaultEndpoint(cfg.Endpoint, "https://api.openai.com/v1")
	case ProviderAnthropic:
		endpoint = defaultEndpoint(cfg.Endpoint, "https://api.anthropic.com/v1")
	case ProviderAzure:
		if cfg.Endpoint == "" {
			return nil, fmt.Errorf("llm: endpoint required for Azure OpenAI")
		}
		endpoint = cfg.Endpoint
	case ProviderOllama:
		endpoint = defaultEndpoint(cfg.Endpoint, "http://localhost:11434/v1")
	case ProviderCustom:
		if cfg.Endpoint == "" {
			return nil, fmt.Errorf("llm: endpoint required for custom provider")
		}
		endpoint = cfg.Endpoint
	default:
		return nil, fmt.Errorf("llm: unknown provider %q", cfg.Provider)
	}

	base := &openAICompatClient{
		cfg:      cfg,
		endpoint: endpoint,
	}

	// Wrap with circuit breaker.
	wrapped := &circuitBreakerClient{
		inner:            base,
		failureThreshold: cfg.CircuitBreaker.FailureThreshold,
		resetTimeout:     cfg.CircuitBreaker.ResetTimeout,
	}

	// Wrap with fallback if configured.
	if cfg.Fallback != nil {
		fallbackCfg := Config{
			Provider:    cfg.Fallback.Provider,
			Model:       cfg.Fallback.Model,
			Endpoint:    cfg.Fallback.Endpoint,
			APIKey:      cfg.Fallback.APIKey,
			Temperature: cfg.Temperature,
			MaxTokens:   cfg.MaxTokens,
			Timeout:     cfg.Timeout,
			Retry:       cfg.Retry,
			CircuitBreaker: CircuitBreakerConfig{
				FailureThreshold: cfg.CircuitBreaker.FailureThreshold,
				ResetTimeout:     cfg.CircuitBreaker.ResetTimeout,
			},
		}
		fallbackClient, fbErr := NewClient(fallbackCfg)
		if fbErr != nil {
			return nil, fmt.Errorf("llm: creating fallback client: %w", fbErr)
		}
		return NewFallbackClient(wrapped, fallbackClient), nil
	}

	return wrapped, nil
}

func defaultEndpoint(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}
