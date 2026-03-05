// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package multicluster provides multi-cluster federation for Zelyo Operator.
//
// # Architecture
//
// The multicluster package enables aggregating views and correlating
// incidents across multiple Kubernetes clusters:
//
//   - Cluster Registration: Each cluster's Zelyo Operator instance registers
//     with a hub cluster for centralized management
//   - Aggregate Views: Combines findings, incidents, and compliance
//     data from all clusters into a unified dashboard
//   - Cross-Cluster Correlation: Identifies patterns and issues that
//     span multiple clusters (e.g., shared vulnerable base images)
//   - Centralized Policy: Enables pushing policies from a hub to
//     all spoke clusters
//
// Federation is optional and disabled by default. When enabled, clusters
// communicate via the Zelyo Operator REST API with mTLS authentication.
package multicluster
