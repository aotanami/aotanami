// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package correlator provides intelligent incident correlation for Zelyo Operator.
//
// # Architecture
//
// The correlator receives raw events, findings, and anomalies from multiple
// detection engines and performs:
//
//   - Deduplication: Eliminates duplicate alerts for the same underlying issue
//   - Event Linking: Connects related events across different sources
//     (e.g., OOM kill event + memory anomaly + pod restart)
//   - Timeline Construction: Builds chronological incident timelines
//   - Root Cause Suggestion: Groups correlated events to suggest root causes
//   - Noise Reduction: Filters transient blips that self-resolve within
//     a configurable window
//
// This is a critical cost optimization layer — by correlating and deduplicating
// events locally, the correlator dramatically reduces the number of incidents
// that require LLM analysis.
package correlator
