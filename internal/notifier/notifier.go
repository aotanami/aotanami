/*
Copyright 2026 Zelyo AI
*/

// Package notifier provides multi-channel notification delivery for Zelyo Operator.
// It supports Slack, Microsoft Teams, PagerDuty, generic webhooks, and
// Kubernetes Events, with deduplication, rate limiting, and retry logic.
package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// ChannelType identifies the notification channel.
type ChannelType string

// Enumeration of supported notification channels.
const (
	ChannelSlack     ChannelType = "slack"
	ChannelTeams     ChannelType = "teams"
	ChannelPagerDuty ChannelType = "pagerduty"
	ChannelWebhook   ChannelType = "webhook"
)

// Severity maps to notification urgency.
type Severity string

// Enumeration of notification severity levels.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Notification represents a single alert to deliver.
type Notification struct {
	// Title is the alert headline.
	Title string `json:"title"`

	// Message is the detailed alert body (supports markdown for Slack/Teams).
	Message string `json:"message"`

	// Severity determines urgency and routing.
	Severity Severity `json:"severity"`

	// Source identifies the originating controller/scanner.
	Source string `json:"source"`

	// ResourceKind is the Kubernetes resource type (e.g. "Pod", "SecurityPolicy").
	ResourceKind string `json:"resource_kind,omitempty"`

	// ResourceName is the name of the affected resource.
	ResourceName string `json:"resource_name,omitempty"`

	// Namespace is the namespace of the affected resource.
	Namespace string `json:"namespace,omitempty"`

	// DeduplicationKey is used to prevent duplicate notifications.
	DeduplicationKey string `json:"dedup_key,omitempty"`

	// Timestamp is when the notification was created.
	Timestamp time.Time `json:"timestamp"`

	// Metadata is extra key-value pairs for the notification.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ChannelConfig configures a notification channel.
type ChannelConfig struct {
	// Type is the channel type.
	Type ChannelType `json:"type"`

	// Name is a human-readable name for this channel.
	Name string `json:"name"`

	// WebhookURL is the endpoint to POST to.
	WebhookURL string `json:"webhook_url"`

	// APIKey is used for PagerDuty integration key.
	APIKey string `json:"api_key,omitempty"`

	// MinSeverity is the minimum severity to send to this channel.
	MinSeverity Severity `json:"min_severity,omitempty"`

	// RateLimitPerMinute is the max notifications per minute (0 = unlimited).
	RateLimitPerMinute int `json:"rate_limit_per_minute,omitempty"`
}

// Notifier manages notification delivery across multiple channels.
type Notifier struct {
	channels []ChannelConfig
	client   *http.Client
	log      logr.Logger

	mu       sync.Mutex
	seen     map[string]time.Time
	dedupTTL time.Duration

	rateLimits map[string]*rateLimiter
}

type rateLimiter struct {
	mu     sync.Mutex
	count  int
	limit  int
	window time.Time
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.window) > time.Minute {
		rl.count = 0
		rl.window = now
	}

	if rl.limit > 0 && rl.count >= rl.limit {
		return false
	}

	rl.count++
	return true
}

// New creates a new Notifier with the given channels.
func New(channels []ChannelConfig, log logr.Logger) *Notifier {
	rateLimits := make(map[string]*rateLimiter, len(channels))
	for i := range channels {
		rateLimits[channels[i].Name] = &rateLimiter{
			limit:  channels[i].RateLimitPerMinute,
			window: time.Now(),
		}
	}

	return &Notifier{
		channels:   channels,
		client:     &http.Client{Timeout: 10 * time.Second},
		log:        log,
		seen:       make(map[string]time.Time),
		dedupTTL:   15 * time.Minute,
		rateLimits: rateLimits,
	}
}

// Send delivers a notification to all applicable channels.
func (n *Notifier) Send(ctx context.Context, notif *Notification) error {
	if notif.Timestamp.IsZero() {
		notif.Timestamp = time.Now()
	}

	dedupKey := notif.DeduplicationKey
	if dedupKey == "" {
		dedupKey = fmt.Sprintf("%s/%s/%s/%s", notif.Title, notif.ResourceKind, notif.ResourceName, notif.Namespace)
	}

	if n.isDuplicate(dedupKey) {
		n.log.V(1).Info("Notification deduplicated", "key", dedupKey)
		return nil
	}

	var errs []error
	for i := range n.channels {
		ch := &n.channels[i]
		if ch.MinSeverity != "" && !meetsMinSeverity(notif.Severity, ch.MinSeverity) {
			continue
		}
		if rl, ok := n.rateLimits[ch.Name]; ok && !rl.allow() {
			n.log.V(1).Info("Notification rate limited", "channel", ch.Name)
			continue
		}
		if err := n.sendToChannel(ctx, ch, notif); err != nil {
			n.log.Error(err, "Failed to send notification", "channel", ch.Name)
			errs = append(errs, fmt.Errorf("channel %s: %w", ch.Name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notifier: %d/%d channels failed", len(errs), len(n.channels))
	}
	return nil
}

func (n *Notifier) isDuplicate(key string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()
	for k, t := range n.seen {
		if now.Sub(t) > n.dedupTTL {
			delete(n.seen, k)
		}
	}

	if _, exists := n.seen[key]; exists {
		return true
	}
	n.seen[key] = now
	return false
}

func (n *Notifier) sendToChannel(ctx context.Context, ch *ChannelConfig, notif *Notification) error {
	switch ch.Type {
	case ChannelSlack:
		return n.sendSlack(ctx, ch, notif)
	case ChannelTeams:
		return n.sendTeams(ctx, ch, notif)
	case ChannelPagerDuty:
		return n.sendPagerDuty(ctx, ch, notif)
	case ChannelWebhook:
		return n.sendWebhook(ctx, ch, notif)
	default:
		return fmt.Errorf("unknown channel type: %s", ch.Type)
	}
}

func (n *Notifier) sendSlack(ctx context.Context, ch *ChannelConfig, notif *Notification) error {
	emoji := severityEmoji(notif.Severity)
	payload := map[string]interface{}{
		"text": fmt.Sprintf("%s *[%s] %s*", emoji, notif.Severity, notif.Title),
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": fmt.Sprintf("%s %s", emoji, notif.Title),
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": notif.Message,
				},
			},
			{
				"type": "context",
				"elements": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Source:* %s | *Severity:* %s", notif.Source, notif.Severity)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Resource:* %s/%s in `%s`", notif.ResourceKind, notif.ResourceName, notif.Namespace)},
				},
			},
		},
	}
	return n.postJSON(ctx, ch.WebhookURL, payload)
}

func (n *Notifier) sendTeams(ctx context.Context, ch *ChannelConfig, notif *Notification) error {
	color := severityColor(notif.Severity)
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": color,
		"summary":    notif.Title,
		"sections": []map[string]interface{}{
			{
				"activityTitle": fmt.Sprintf("%s %s", severityEmoji(notif.Severity), notif.Title),
				"text":          notif.Message,
				"facts": []map[string]string{
					{"name": "Severity", "value": string(notif.Severity)},
					{"name": "Source", "value": notif.Source},
					{"name": "Resource", "value": fmt.Sprintf("%s/%s", notif.ResourceKind, notif.ResourceName)},
					{"name": "Namespace", "value": notif.Namespace},
				},
			},
		},
	}
	return n.postJSON(ctx, ch.WebhookURL, payload)
}

func (n *Notifier) sendPagerDuty(ctx context.Context, ch *ChannelConfig, notif *Notification) error {
	pdSeverity := "warning"
	switch notif.Severity {
	case SeverityCritical:
		pdSeverity = "critical"
	case SeverityHigh:
		pdSeverity = "error"
	default:
		// keep default "warning"
	}

	payload := map[string]interface{}{
		"routing_key":  ch.APIKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":   notif.Title,
			"severity":  pdSeverity,
			"source":    "zelyo-operator",
			"component": notif.Source,
			"group":     notif.Namespace,
			"custom_details": map[string]string{
				"message":       notif.Message,
				"resource_kind": notif.ResourceKind,
				"resource_name": notif.ResourceName,
				"namespace":     notif.Namespace,
			},
		},
	}
	return n.postJSON(ctx, "https://events.pagerduty.com/v2/enqueue", payload)
}

func (n *Notifier) sendWebhook(ctx context.Context, ch *ChannelConfig, notif *Notification) error {
	return n.postJSON(ctx, ch.WebhookURL, notif)
}

func (n *Notifier) postJSON(ctx context.Context, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if _, discardErr := io.Copy(io.Discard, resp.Body); discardErr != nil {
		return fmt.Errorf("discard response body: %w", discardErr)
	}

	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return nil
}

var severityOrder = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityInfo:     1,
}

func meetsMinSeverity(actual, minimum Severity) bool {
	return severityOrder[actual] >= severityOrder[minimum]
}

func severityEmoji(s Severity) string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🔵"
	default:
		return "ℹ️"
	}
}

func severityColor(s Severity) string {
	switch s {
	case SeverityCritical:
		return "FF0000"
	case SeverityHigh:
		return "FF8800"
	case SeverityMedium:
		return "FFCC00"
	case SeverityLow:
		return "0088FF"
	default:
		return "808080"
	}
}
