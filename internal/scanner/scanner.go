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

// Package scanner provides the security scanning engine for Zelyo Operator.
// It defines a Scanner interface and a registry for extensible scan modules.
package scanner

import (
	"context"
	"fmt"
	"sync"

	corev1 "k8s.io/api/core/v1"
)

// Finding represents a single security issue discovered by a scanner.
type Finding struct {
	// RuleType is the security rule type that produced this finding.
	RuleType string
	// Severity of the finding (critical, high, medium, low, info).
	Severity string
	// Title is a short, human-readable summary.
	Title string
	// Description is a detailed explanation of the finding.
	Description string
	// ResourceKind is the kind of the affected resource (e.g., "Pod", "Deployment").
	ResourceKind string
	// ResourceNamespace is the namespace of the affected resource.
	ResourceNamespace string
	// ResourceName is the name of the affected resource.
	ResourceName string
	// Recommendation is the suggested fix.
	Recommendation string
}

// Scanner is the interface implemented by all Zelyo Operator scan modules.
// Each scanner evaluates one specific type of security rule against a set of pods.
type Scanner interface {
	// Name returns the human-readable name of this scanner.
	Name() string
	// RuleType returns the security rule type this scanner handles
	// (e.g., "container-security-context", "resource-limits").
	RuleType() string
	// Scan evaluates the given pods and returns a list of findings.
	Scan(ctx context.Context, pods []corev1.Pod, params map[string]string) ([]Finding, error)
}

// Registry is a thread-safe registry of Scanner implementations.
// New scanners are registered at init-time and retrieved by rule type
// during reconciliation.
type Registry struct {
	mu       sync.RWMutex
	scanners map[string]Scanner
}

// NewRegistry creates an empty scanner registry.
func NewRegistry() *Registry {
	return &Registry{
		scanners: make(map[string]Scanner),
	}
}

// Register adds a scanner to the registry. It panics if a scanner
// for the same rule type is already registered (indicating a bug).
func (r *Registry) Register(s Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.scanners[s.RuleType()]; exists {
		panic(fmt.Sprintf("scanner already registered for rule type: %s", s.RuleType()))
	}
	r.scanners[s.RuleType()] = s
}

// Get returns the scanner for the given rule type, or nil if not found.
func (r *Registry) Get(ruleType string) Scanner {
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

// DefaultRegistry returns a new Registry pre-loaded with all built-in scanners.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(&ContainerSecurityContextScanner{})
	r.Register(&ResourceLimitsScanner{})
	r.Register(&ImagePinningScanner{})
	r.Register(&PodSecurityScanner{})
	r.Register(&PrivilegeEscalationScanner{})
	r.Register(&SecretsExposureScanner{})
	r.Register(&NetworkPolicyScanner{})
	r.Register(&RBACAuditScanner{})
	return r
}
