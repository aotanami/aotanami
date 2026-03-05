// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package metrics provides Prometheus metrics and OpenTelemetry tracing for Zelyo Operator.
//
// # Architecture
//
// The metrics package exports operational telemetry:
//
// Prometheus Metrics:
//
//   - zelyo_operator_incidents_total: Counter of detected incidents by severity
//   - zelyo_operator_scans_total: Counter of completed scans by type
//   - zelyo_operator_findings_total: Gauge of active findings by severity
//   - zelyo_operator_remediations_total: Counter of PRs created
//   - zelyo_operator_llm_tokens_total: Counter of LLM tokens consumed
//   - zelyo_operator_llm_requests_total: Counter of LLM API calls
//   - zelyo_operator_notifications_total: Counter of notifications sent by channel
//   - zelyo_operator_drift_resources: Gauge of resources with config drift
//   - zelyo_operator_cost_estimated_monthly: Gauge of estimated monthly cluster cost
//
// OpenTelemetry Tracing:
//
//   - Traces for scan execution, LLM calls, and PR creation workflows
//   - Configurable OTLP exporter endpoint via ZelyoConfig
package metrics
