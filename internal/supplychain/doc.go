// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package supplychain provides supply chain security analysis for Zelyo Operator.
//
// # Architecture
//
// The supplychain package analyzes container images and their lineage:
//
//   - SBOM Analysis: Parses and evaluates Software Bills of Materials
//     to identify vulnerable dependencies
//   - Image Signature Verification: Verifies Cosign and Notary signatures
//     on container images before they run in the cluster
//   - Base Image CVE Tracking: Monitors base images for newly disclosed CVEs
//   - Image Provenance: Validates SLSA provenance attestations
//   - Registry Scanning: Checks image pull policies and registry trust
//
// All analysis operates in read-only mode — the package inspects image
// metadata and signatures without pulling or modifying images.
package supplychain
