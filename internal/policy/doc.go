// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package policy provides the CEL-based policy evaluation engine for Zelyo Operator.
//
// # Architecture
//
// The policy engine evaluates Common Expression Language (CEL) expressions
// against Kubernetes resources to determine policy compliance. It supports:
//
//   - Built-in Rules: Pre-defined security and configuration checks
//   - Custom CEL Expressions: User-defined rules in SecurityPolicy CRDs
//   - Compliance Mapping: Maps rule results to compliance framework controls
//   - Severity Classification: Assigns severity levels to evaluation results
//
// CEL was chosen over Rego for its simplicity, type safety, and native
// Kubernetes ecosystem support (used by ValidatingAdmissionPolicies).
package policy
