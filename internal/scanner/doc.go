// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package scanner provides security and misconfiguration scanning for Zelyo Operator.
//
// # Architecture
//
// The scanner evaluates Kubernetes resources against security best practices
// and identifies misconfigurations. Scanning modules include:
//
//   - RBAC Audit: Over-permissive roles, cluster-admin bindings, wildcard permissions
//   - Image Vulnerability: Checks image tags, pinning, and known CVEs
//   - Network Policy: Missing or overly permissive network policies
//   - PodSecurity: Violations of Pod Security Standards (Restricted, Baseline)
//   - Secrets Exposure: Secrets mounted as environment variables, unencrypted secrets
//   - Resource Limits: Missing CPU/memory requests and limits
//   - Privilege Escalation: Privileged containers, host namespace access
//   - Service Account: Default service account usage, automounted tokens
//
// Scan results are stored as ScanReport CRDs and can be queried via kubectl
// or the Zelyo Operator dashboard.
package scanner
