/*
Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.

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

// Package source provides manifest source parsers for Aotanami's GitOps integration.
//
// # Architecture
//
// The source package abstracts how Kubernetes manifests are structured in a GitOps
// repository. Each source type (raw YAML, Helm, Kustomize) implements the Source
// interface, allowing the controller to parse manifests uniformly regardless of
// the underlying format.
//
// Implementations:
//   - RawSource: parses plain YAML/JSON Kubernetes manifests
//   - HelmSource: parses Helm charts (Chart.yaml, templates, values)
//   - KustomizeSource: parses Kustomize overlays (kustomization.yaml)
//
// The Registry provides thread-safe lookup of source parsers by type, following
// the same pattern as the scanner registry.
package source

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
)

// Manifest represents a single Kubernetes manifest discovered in a repository.
type Manifest struct {
	// Path is the file path relative to the repo root.
	Path string

	// Content is the raw manifest YAML/JSON content.
	Content []byte

	// APIVersion is the apiVersion of the manifest (e.g., "apps/v1").
	APIVersion string

	// Kind is the kind of the manifest (e.g., "Deployment").
	Kind string

	// Name is the metadata.name of the manifest.
	Name string

	// Namespace is the metadata.namespace of the manifest.
	Namespace string
}

// ParseOptions holds parameters for parsing manifests from a source.
type ParseOptions struct {
	// RepoRoot is the absolute path to the cloned repository root.
	RepoRoot string

	// Path is the relative path within the repo to parse.
	Path string

	// Files is the list of files discovered under Path (relative to RepoRoot).
	Files []string

	// HelmValuesFiles lists additional Helm values files to merge.
	HelmValuesFiles []string

	// HelmReleaseName is the Helm release name for template rendering.
	HelmReleaseName string

	// HelmReleaseNamespace is the Helm release namespace.
	HelmReleaseNamespace string

	// KustomizeBuildArgs are additional kustomize build arguments.
	KustomizeBuildArgs []string
}

// ParseResult holds the output of a source parser.
type ParseResult struct {
	// Manifests are the discovered Kubernetes manifests.
	Manifests []Manifest

	// SourceType is the detected source type.
	SourceType string

	// Metadata contains source-specific metadata (e.g., chart version).
	Metadata map[string]string
}

// Source represents a manifest source parser.
// Each implementation handles a specific manifest format (raw, helm, kustomize).
type Source interface {
	// Type returns the source type identifier (e.g., "raw", "helm", "kustomize").
	Type() string

	// Detect checks if the given set of files matches this source type.
	// Returns true if this parser should handle the path.
	Detect(files []string) bool

	// Parse extracts Kubernetes manifests from the source.
	Parse(ctx context.Context, opts ParseOptions) (*ParseResult, error)
}

// Registry is a thread-safe registry of Source implementations.
type Registry struct {
	mu      sync.RWMutex
	sources map[string]Source
}

// NewRegistry creates an empty source registry.
func NewRegistry() *Registry {
	return &Registry{
		sources: make(map[string]Source),
	}
}

// Register adds a source parser to the registry.
// It panics if a parser for the same type is already registered.
func (r *Registry) Register(s Source) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sources[s.Type()]; exists {
		panic(fmt.Sprintf("source already registered for type: %s", s.Type()))
	}
	r.sources[s.Type()] = s
}

// Get returns the source parser for the given type, or nil if not found.
func (r *Registry) Get(sourceType string) Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sources[sourceType]
}

// List returns all registered source types.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	types := make([]string, 0, len(r.sources))
	for t := range r.sources {
		types = append(types, t)
	}
	return types
}

// DetectType examines the files in a path and returns the best-matching source type.
// It checks each registered source's Detect method in priority order:
// helm > kustomize > raw.
func (r *Registry) DetectType(files []string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Check in priority order: helm, kustomize, then raw.
	for _, priority := range []string{"helm", "kustomize", "raw"} {
		if s, ok := r.sources[priority]; ok && s.Detect(files) {
			return priority
		}
	}
	return "raw"
}

// DefaultRegistry returns a Registry pre-loaded with all built-in source parsers.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(&RawSource{})
	r.Register(&HelmSourceParser{})
	r.Register(&KustomizeSourceParser{})
	return r
}

// --- Raw Source ---

// RawSource parses plain YAML/JSON Kubernetes manifests.
type RawSource struct{}

// Type returns "raw".
func (s *RawSource) Type() string { return "raw" }

// Detect returns true for any set of files (raw is the fallback).
func (s *RawSource) Detect(_ []string) bool { return true }

// Parse discovers YAML/JSON files and returns them as manifests.
func (s *RawSource) Parse(_ context.Context, opts ParseOptions) (*ParseResult, error) {
	result := &ParseResult{
		SourceType: "raw",
		Metadata:   map[string]string{},
	}

	for _, f := range opts.Files {
		ext := strings.ToLower(filepath.Ext(f))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}

		// Skip Helm and Kustomize marker files.
		base := strings.ToLower(filepath.Base(f))
		if base == "chart.yaml" || base == "chart.yml" ||
			base == "kustomization.yaml" || base == "kustomization.yml" {
			continue
		}

		result.Manifests = append(result.Manifests, Manifest{
			Path: f,
			// Content would be populated by reading the file from the cloned repo.
			// The controller handles actual file I/O; the source parser defines structure.
		})
	}

	return result, nil
}

// --- Helm Source ---

// HelmSourceParser parses Helm chart repositories.
type HelmSourceParser struct{}

// Type returns "helm".
func (s *HelmSourceParser) Type() string { return "helm" }

// Detect checks for Chart.yaml in the file list.
func (s *HelmSourceParser) Detect(files []string) bool {
	for _, f := range files {
		base := strings.ToLower(filepath.Base(f))
		if base == "chart.yaml" || base == "chart.yml" {
			return true
		}
	}
	return false
}

// Parse discovers Helm chart files and returns them as manifests.
func (s *HelmSourceParser) Parse(_ context.Context, opts ParseOptions) (*ParseResult, error) {
	result := &ParseResult{
		SourceType: "helm",
		Metadata:   map[string]string{},
	}

	var chartPath string
	var valuesFiles []string
	var templateFiles []string

	for _, f := range opts.Files {
		base := strings.ToLower(filepath.Base(f))
		ext := strings.ToLower(filepath.Ext(f))

		if base == "chart.yaml" || base == "chart.yml" {
			chartPath = f
			continue
		}

		// Collect values files.
		if base == "values.yaml" || base == "values.yml" ||
			strings.HasPrefix(base, "values-") || strings.HasPrefix(base, "values_") {
			valuesFiles = append(valuesFiles, f)
			continue
		}

		// Collect template files.
		if ext == ".yaml" || ext == ".yml" || ext == ".tpl" {
			rel, _ := filepath.Rel(opts.Path, f)
			if strings.HasPrefix(rel, "templates"+string(filepath.Separator)) || strings.HasPrefix(rel, "templates/") {
				templateFiles = append(templateFiles, f)
			}
		}
	}

	if chartPath != "" {
		result.Metadata["chartPath"] = chartPath
	}

	if opts.HelmReleaseName != "" {
		result.Metadata["releaseName"] = opts.HelmReleaseName
	}
	if opts.HelmReleaseNamespace != "" {
		result.Metadata["releaseNamespace"] = opts.HelmReleaseNamespace
	}

	// Values files — include both discovered and user-specified.
	allValues := append(valuesFiles, opts.HelmValuesFiles...)
	for i, vf := range allValues {
		result.Metadata[fmt.Sprintf("valuesFile.%d", i)] = vf
	}

	// Templates as manifests.
	for _, tf := range templateFiles {
		result.Manifests = append(result.Manifests, Manifest{
			Path: tf,
		})
	}

	return result, nil
}

// --- Kustomize Source ---

// KustomizeSourceParser parses Kustomize overlay repositories.
type KustomizeSourceParser struct{}

// Type returns "kustomize".
func (s *KustomizeSourceParser) Type() string { return "kustomize" }

// Detect checks for kustomization.yaml in the file list.
func (s *KustomizeSourceParser) Detect(files []string) bool {
	for _, f := range files {
		base := strings.ToLower(filepath.Base(f))
		if base == "kustomization.yaml" || base == "kustomization.yml" || base == "kustomization" {
			return true
		}
	}
	return false
}

// Parse discovers Kustomize files and returns them as manifests.
func (s *KustomizeSourceParser) Parse(_ context.Context, opts ParseOptions) (*ParseResult, error) {
	result := &ParseResult{
		SourceType: "kustomize",
		Metadata:   map[string]string{},
	}

	var kustomizationFile string

	for _, f := range opts.Files {
		base := strings.ToLower(filepath.Base(f))
		ext := strings.ToLower(filepath.Ext(f))

		if base == "kustomization.yaml" || base == "kustomization.yml" || base == "kustomization" {
			kustomizationFile = f
			continue
		}

		// Include all YAML resources referenced by kustomization.
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			result.Manifests = append(result.Manifests, Manifest{
				Path: f,
			})
		}
	}

	if kustomizationFile != "" {
		result.Metadata["kustomizationFile"] = kustomizationFile
	}

	if len(opts.KustomizeBuildArgs) > 0 {
		result.Metadata["buildArgs"] = strings.Join(opts.KustomizeBuildArgs, " ")
	}

	return result, nil
}
