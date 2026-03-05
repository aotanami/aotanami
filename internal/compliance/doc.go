// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package compliance provides compliance framework evaluation for Zelyo Operator.
//
// # Supported Frameworks
//
//   - CIS Kubernetes Benchmark: Industry-standard security configuration checks
//   - NSA/CISA Kubernetes Hardening Guide: US government security recommendations
//   - PCI-DSS: Payment Card Industry Data Security Standard controls
//   - SOC 2: Service Organization Control 2 trust service criteria
//   - HIPAA: Health Insurance Portability and Accountability Act safeguards
//
// # Architecture
//
// Each framework is implemented as a set of controls mapped to scanner rules.
// The engine evaluates the cluster against selected frameworks and produces
// compliance reports with pass/fail status per control, included in ScanReport
// resources.
//
// Custom framework support is planned for future releases.
package compliance
