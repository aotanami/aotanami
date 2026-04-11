/*
Copyright 2026 Zelyo AI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package cloudscanner provides the cloud security scanning engine for Zelyo Operator.
// It defines a CloudScanner interface for scanning cloud provider resources via
// read-only API calls, and a registry for extensible cloud scan modules.
package cloudscanner

import (
	"context"
	"fmt"
	"sync"

	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// CloudContext is an alias for aws.CloudContext for backward compatibility.
// It provides authenticated cloud clients and scan metadata.
type CloudContext = awsclients.CloudContext

// CloudScanner is the interface implemented by all cloud security check modules.
// Each scanner evaluates one specific type of cloud misconfiguration using
// read-only API calls and returns findings in the standard scanner.Finding format.
type CloudScanner interface {
	// Name returns the human-readable name of this scanner.
	Name() string
	// RuleType returns the security rule type this scanner handles
	// (e.g., "cspm-public-s3-bucket", "ciem-overprivileged-iam").
	RuleType() string
	// Category returns the scanner category
	// (cspm, ciem, network, dspm, supply-chain, cicd-pipeline).
	Category() string
	// Provider returns the cloud provider this scanner targets ("aws", "gcp", "azure").
	Provider() string
	// IsGlobal returns true if this scanner checks global resources (e.g., IAM)
	// and should only run once per account, not per-region.
	IsGlobal() bool
	// Scan evaluates cloud resources and returns a list of findings.
	// The CloudContext provides authenticated clients and scan metadata.
	Scan(ctx context.Context, cc *CloudContext) ([]scanner.Finding, error)
}

// Registry is a thread-safe registry of CloudScanner implementations.
// New scanners are registered at init-time and retrieved by rule type or category.
type Registry struct {
	mu       sync.RWMutex
	scanners map[string]CloudScanner
}

// NewRegistry creates an empty cloud scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]CloudScanner),
	}
}

// Register adds a cloud scanner to the registry.
// It panics if a scanner for the same rule type is already registered.
func (r *Registry) Register(s CloudScanner) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.scanners[s.RuleType()]; exists {
		panic(fmt.Sprintf("cloud scanner already registered for rule type: %s", s.RuleType()))
	}
	r.scanners[s.RuleType()] = s
}

// Get returns the scanner for the given rule type, or nil if not found.
func (r *Registry) Get(ruleType string) CloudScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.scanners[ruleType]
}

// List returns all registered rule types.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.scanners))
	for t := range r.scanners {
		types = append(types, t)
	}
	return types
}

// GetByCategory returns all scanners matching the given category.
func (r *Registry) GetByCategory(category string) []CloudScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []CloudScanner
	for _, s := range r.scanners {
		if s.Category() == category {
			result = append(result, s)
		}
	}
	return result
}

// GetByProvider returns all scanners matching the given cloud provider.
func (r *Registry) GetByProvider(provider string) []CloudScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []CloudScanner
	for _, s := range r.scanners {
		if s.Provider() == provider {
			result = append(result, s)
		}
	}
	return result
}

// GetByCategoryAndProvider returns scanners matching both category and provider.
func (r *Registry) GetByCategoryAndProvider(category, provider string) []CloudScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []CloudScanner
	for _, s := range r.scanners {
		if s.Category() == category && s.Provider() == provider {
			result = append(result, s)
		}
	}
	return result
}

// Count returns the total number of registered scanners.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.scanners)
}
