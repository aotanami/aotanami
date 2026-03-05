// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package threat provides runtime threat detection for Zelyo Operator.
//
// # Architecture
//
// The threat package monitors for active security threats in running workloads:
//
//   - Suspicious Exec: Detects shell access and unexpected command execution
//     in containers (kubectl exec, reverse shells)
//   - Privilege Escalation: Monitors for attempts to gain elevated privileges
//     (setuid binaries, capability additions, namespace escapes)
//   - Filesystem Anomalies: Detects unexpected file modifications in
//     read-only filesystems or sensitive paths (/etc, /proc, /sys)
//   - Network Anomalies: Unusual outbound connections, DNS exfiltration patterns
//   - Cryptomining Detection: Identifies resource usage patterns consistent
//     with cryptocurrency mining
//
// Detected threats are assigned severity levels and routed through the
// correlator and notification system for immediate alerting.
package threat
