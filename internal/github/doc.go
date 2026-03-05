// Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.
// SPDX-License-Identifier: Apache-2.0

// Package github provides the GitHub App client for Aotanami.
//
// # Architecture
//
// The github package implements GitHub App authentication and API operations:
//
//   - JWT Authentication: Generates JWTs from the GitHub App private key
//   - Installation Token Management: Obtains and refreshes installation access tokens
//   - Pull Request Lifecycle: Create, update, and manage PRs
//   - Status Checks: Report check statuses on PRs
//   - Webhook Handling: Processes GitHub webhooks for PR merge/close events
//   - Repository Access: Read access to repository contents for drift detection
//
// The package uses only Go's standard library (net/http, crypto) with zero
// external dependencies, and is configured via the AotanamiConfig's GitHub
// App settings.
package github
