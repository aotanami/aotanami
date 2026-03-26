// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package version provides build-time version information for Zelyo Operator.
//
// # Usage
//
// Version, commit, and build date are injected at build time via ldflags:
//
//	go build -ldflags "-X github.com/zelyo-ai/zelyo/internal/version.Version=v1.0.0
//	  -X github.com/zelyo-ai/zelyo/internal/version.Commit=abc1234
//	  -X github.com/zelyo-ai/zelyo/internal/version.Date=2026-03-02T00:00:00Z"
package version

// Version is the semantic version of the build. Set via ldflags.
var Version = "dev"

// Commit is the git commit SHA of the build. Set via ldflags.
var Commit = "unknown"

// Date is the build timestamp in ISO 8601 format. Set via ldflags.
var Date = "unknown"
