// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package drift provides config drift detection for Zelyo Operator.
//
// # Architecture
//
// The drift package compares the live state of Kubernetes resources against
// their declared state in onboarded GitOps repositories (GitOpsRepository CRDs).
//
// Detection workflow:
//
//  1. Sync: Fetches the latest manifests from the GitOps repository
//  2. Parse: Parses Kubernetes manifests from the repo paths
//  3. Map: Maps repo manifests to live cluster resources using namespace mapping
//  4. Diff: Computes structural diffs between repo and live state
//  5. Report: Reports drifts as findings, optionally feeding them into the
//     remediation pipeline for auto-fix PRs
//
// The drift detector ignores managed fields, last-applied-configuration
// annotations, and other metadata that naturally differs between repo
// and live state.
package drift
