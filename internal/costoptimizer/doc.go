// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package costoptimizer provides cost monitoring and workload rightsizing for Zelyo Operator.
//
// # Architecture
//
// The costoptimizer monitors resource utilization across the cluster and provides:
//
//   - Resource Usage Analysis: Tracks CPU and memory utilization vs. requests/limits
//   - Rightsizing Recommendations: Suggests optimal resource requests/limits
//     based on actual usage patterns over configurable observation windows
//   - Idle Workload Detection: Identifies workloads consuming minimal resources
//     below configurable thresholds
//   - Spot-Readiness Assessment: Evaluates workload suitability for spot/preemptible
//     instances based on restart tolerance and statelessness
//   - Cost Estimation: Estimates operational costs based on resource consumption
//     and configurable cloud provider pricing
//   - Budget Alerting: Triggers alerts when costs approach configured budget limits
//
// Rightsizing recommendations are delivered as GitOps PRs (Protect Mode)
// or dashboard/notification alerts (Audit Mode).
package costoptimizer
