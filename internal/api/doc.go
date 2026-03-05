// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package api provides the REST API server for Zelyo Operator.
//
// # Architecture
//
// The API server exposes an OpenAPI-documented REST API that powers the
// embedded dashboard and enables external integrations. Endpoints include:
//
//   - /api/v1/health: Health check endpoint
//   - /api/v1/incidents: List and manage active incidents
//   - /api/v1/scans: Trigger scans and retrieve results
//   - /api/v1/findings: Query security and compliance findings
//   - /api/v1/costs: Cost analysis and rightsizing data
//   - /api/v1/drift: Config drift status
//   - /api/v1/notifications: Notification history
//   - /api/v1/token-usage: LLM token consumption metrics
//   - /api/v1/clusters: Multi-cluster federation status
//
// The API server runs on the same port as the dashboard and is protected
// by Kubernetes RBAC via ServiceAccount token authentication.
package api
