// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package gitops provides GitOps repository onboarding and management for Zelyo Operator.
//
// # Architecture
//
// The gitops package handles the lifecycle of onboarded GitOps repositories:
//
//   - Repository Validation: Verifies connectivity, authentication, and read access
//   - Manifest Discovery: Scans configured paths for Kubernetes manifests
//     (YAML/JSON), including Kustomize and Helm chart values
//   - Workload Mapping: Maps discovered manifests to live cluster resources
//     using namespace mapping rules from GitOpsRepository CRDs
//   - Sync Management: Periodically syncs (poll or webhook) to detect
//     new commits and manifest changes
//   - Branch Management: Creates fix branches and manages their lifecycle
//
// The package supports GitHub, GitLab, and Bitbucket as Git providers.
package gitops
