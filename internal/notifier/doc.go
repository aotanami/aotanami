// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package notifier provides the unified notification routing engine for Zelyo Operator.
//
// # Supported Providers
//
//   - Slack: Rich message formatting with severity-colored attachments
//   - Microsoft Teams: Adaptive card notifications via incoming webhooks
//   - PagerDuty: Event-driven incident creation with severity mapping
//   - AlertManager: Prometheus AlertManager API integration
//   - Telegram: Bot API message delivery
//   - WhatsApp: Business API message delivery
//   - Webhook: Generic HTTP POST with configurable headers and payload
//   - Email: SMTP-based email notifications
//
// # Architecture
//
// The notifier receives alert events from controllers and routes them to
// configured NotificationChannel resources. It implements:
//
//   - Rate Limiting: Per-channel throttling to prevent alert storms
//   - Aggregation: Groups related alerts within configurable time windows
//   - Severity Filtering: Per-channel minimum severity thresholds
//   - Template Rendering: Provider-specific message formatting
//   - Retry Logic: Exponential backoff for transient delivery failures
package notifier
