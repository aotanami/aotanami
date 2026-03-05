// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package anomaly provides the anomaly detection engine for Zelyo Operator.
//
// # Architecture
//
// The anomaly package learns baseline behavior of workloads over a configurable
// window (default: 7 days) and uses statistical methods to detect deviations.
//
// Detection capabilities include:
//
//   - Resource Usage Anomalies: CPU/memory spikes or drops outside normal bounds
//   - Restart Pattern Detection: OOM kills, CrashLoopBackOff prediction
//   - Latency Anomalies: Response time degradation detected via metrics
//   - Traffic Pattern Shifts: Unusual request volume changes
//   - Baseline Drift: Gradual shifts in workload behavior over time
//
// The engine maintains per-workload baselines using exponential moving averages
// and standard deviation thresholds, configurable via MonitoringPolicy's
// AnomalyDetection settings.
package anomaly
