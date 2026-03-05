// Copyright 2026 Zelyo AI
// SPDX-License-Identifier: Apache-2.0

// Package llm provides the LLM client abstraction for Zelyo Operator's AI-powered
// diagnosis and remediation capabilities.
//
// # Architecture
//
// The llm package supports multiple LLM providers (OpenRouter, OpenAI, Anthropic,
// Azure OpenAI, Ollama) through a unified Client interface. Users bring their own
// API keys, and the package is heavily optimized to minimize token consumption.
//
// # Cost Optimization Strategy
//
// The package implements several strategies to reduce LLM API costs:
//
//   - Prompt Template Caching: Reusable prompt templates are cached and shared
//     across similar finding types, avoiding redundant prompt construction.
//
//   - Structured Output: All LLM calls use structured output schemas (JSON mode)
//     to get machine-parseable responses on the first attempt, eliminating
//     re-prompting.
//
//   - Batching: Multiple related findings are batched into single LLM calls
//     where possible, reducing per-request overhead.
//
//   - Local Triage First: Severity scoring, deduplication, and correlation
//     happen locally before any LLM call. Only genuinely complex, novel
//     incidents requiring AI analysis are escalated to the LLM.
//
//   - Context Compression: Input context is compressed to include only
//     relevant information, stripping boilerplate and redundant metadata.
//
//   - Token Budget Enforcement: Configurable hourly/daily/monthly token limits
//     with alerting at configurable thresholds.
//
// # Usage
//
// The Client is initialized from the ZelyoConfig CRD's LLM configuration
// and injected into controllers that require AI-powered analysis.
package llm
