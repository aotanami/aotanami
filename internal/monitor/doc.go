// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package monitor provides the 24/7 real-time cluster monitoring engine.
//
// # Architecture
//
// The monitor package runs continuous watchers using Kubernetes informers
// and streams to detect issues in real-time:
//
//   - Event Watcher: Monitors Kubernetes events (Warning events, error events)
//     using shared informers with configurable filters
//   - Pod Log Streamer: Streams pod logs and matches against configured
//     patterns (regex) defined in MonitoringPolicy resources
//   - Node Condition Watcher: Monitors node conditions (MemoryPressure,
//     DiskPressure, PIDPressure, NetworkUnavailable)
//   - Network Telemetry: Collects network-level signals when available
//     (connection errors, DNS failures)
//
// All detected signals are forwarded to the correlator for deduplication
// and incident construction before any LLM analysis.
//
// The monitor operates with read-only cluster access — it uses only
// get, list, and watch verbs on the Kubernetes API.
package monitor
