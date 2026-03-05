// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package remediation provides the GitOps fix generator for Zelyo Operator.
//
// # Architecture
//
// The remediation package takes diagnosed incidents (from the LLM engine)
// and produces concrete Kubernetes manifest patches. These patches are
// submitted as pull requests via the GitHub App integration.
//
// Workflow:
//
//  1. Receive: Accepts a diagnosed incident with LLM-generated fix recommendations
//  2. Generate: Produces valid Kubernetes manifest patches (strategic merge patches)
//  3. Validate: Dry-run validates patches against the Kubernetes API schema
//  4. Impact Analysis: Assesses the blast radius of proposed changes
//  5. Submit: Creates a PR via the github package with clear description,
//     impact analysis, and rollback instructions
//
// In Audit Mode, the remediation package generates fix suggestions but
// delivers them as notifications instead of PRs.
package remediation
