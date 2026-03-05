// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package dashboard provides the embedded lightweight web dashboard for Zelyo Operator.
//
// # Architecture
//
// The dashboard is a self-contained web UI embedded directly in the operator
// binary using Go's embed.FS. It has zero external dependencies — no Node.js,
// no npm, no separate build step required.
//
// Technology stack:
//
//   - Go net/http: HTTP server and routing
//   - html/template: Server-side HTML rendering
//   - htmx: Client-side interactivity without a JavaScript framework
//   - Server-Sent Events (SSE): Real-time updates pushed to the browser
//   - Embedded static assets: CSS, JS, and icons bundled via embed.FS
//
// # Views
//
//   - Cluster Health Overview: At-a-glance cluster status and active issues
//   - Active Incidents Timeline: Chronological view of detected incidents
//   - Scan Results & Compliance: Security scan findings and compliance posture
//   - Cost Analysis: Resource utilization and rightsizing recommendations
//   - GitOps PR Tracker: Status of open remediation PRs
//   - Drift Detection: Resources with config drift from GitOps repos
//   - Notification History: Sent alerts and their delivery status
//   - LLM Usage: Token consumption, budget status, and cost tracking
//   - Multi-Cluster Overview: Federated view across clusters (when enabled)
package dashboard
