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

// Package discovery provides auto-discovery of GitOps repository structures.
//
// # Architecture
//
// The discovery package examines a set of file paths from a cloned repository
// and determines what type of manifest sources are present. It supports:
//
//   - Helm charts (detected by Chart.yaml)
//   - Kustomize overlays (detected by kustomization.yaml / kustomization.yml)
//   - Raw YAML/JSON manifests (fallback)
//
// The discovery engine walks the directory tree and returns all detected sources
// with their paths and metadata. This enables Aotanami to work with monorepos
// containing multiple apps with different source types.
package discovery

import (
	"path/filepath"
	"sort"
	"strings"
)

// SourceType mirrors the API ManifestSourceType for discovery results.
type SourceType string

const (
	// SourceTypeRaw indicates plain YAML/JSON Kubernetes manifests.
	SourceTypeRaw SourceType = "raw"
	// SourceTypeHelm indicates a Helm chart.
	SourceTypeHelm SourceType = "helm"
	// SourceTypeKustomize indicates Kustomize overlays.
	SourceTypeKustomize SourceType = "kustomize"
)

// DetectedSource represents a single source detected in a repository.
type DetectedSource struct {
	// Path is the directory path relative to the repo root.
	Path string

	// Type is the source type (raw, helm, kustomize).
	Type SourceType

	// Metadata contains source-specific metadata.
	Metadata map[string]string
}

// Result holds the output of the auto-discovery engine.
type Result struct {
	// Sources are all detected manifest sources.
	Sources []DetectedSource

	// PrimaryType is the dominant source type across all detected sources.
	PrimaryType SourceType
}

// Discover analyzes a list of file paths (relative to the repo root) and
// determines what kind of manifest sources are present.
//
// It detects:
//   - Helm charts by the presence of Chart.yaml or Chart.yml
//   - Kustomize overlays by the presence of kustomization.yaml, kustomization.yml, or kustomization
//   - Raw manifests by the presence of .yaml, .yml, or .json files
//
// The function supports monorepos with multiple sources in different directories.
//
//nolint:gocyclo // Discovery logic inherently checks many file patterns
func Discover(files []string) *Result {
	result := &Result{}

	// Track detected source directories to avoid duplicates.
	helmDirs := make(map[string]bool)
	kustomizeDirs := make(map[string]bool)
	yamlDirs := make(map[string]bool)

	for _, f := range files {
		dir := filepath.Dir(f)
		base := strings.ToLower(filepath.Base(f))
		ext := strings.ToLower(filepath.Ext(f))

		switch {
		case base == "chart.yaml" || base == "chart.yml":
			if !helmDirs[dir] {
				helmDirs[dir] = true
				result.Sources = append(result.Sources, DetectedSource{
					Path: dir,
					Type: SourceTypeHelm,
					Metadata: map[string]string{
						"chartFile": f,
					},
				})
			}

		case base == "kustomization.yaml" || base == "kustomization.yml" || base == "kustomization":
			if !kustomizeDirs[dir] {
				kustomizeDirs[dir] = true
				result.Sources = append(result.Sources, DetectedSource{
					Path: dir,
					Type: SourceTypeKustomize,
					Metadata: map[string]string{
						"kustomizationFile": f,
					},
				})
			}

		case ext == ".yaml" || ext == ".yml" || ext == ".json":
			// Only add raw YAML dirs that aren't already claimed by Helm or Kustomize.
			// We'll filter these after the full scan.
			yamlDirs[dir] = true
		}
	}

	// Add raw source dirs that aren't already covered by Helm or Kustomize.
	for dir := range yamlDirs {
		if helmDirs[dir] || kustomizeDirs[dir] {
			continue
		}
		// Also skip if this dir is a subdirectory of a Helm chart (e.g., templates/).
		if isSubdirOf(dir, helmDirs) {
			continue
		}

		result.Sources = append(result.Sources, DetectedSource{
			Path:     dir,
			Type:     SourceTypeRaw,
			Metadata: map[string]string{},
		})
	}

	// Sort sources for deterministic output.
	sort.Slice(result.Sources, func(i, j int) bool {
		return result.Sources[i].Path < result.Sources[j].Path
	})

	// Determine primary type.
	result.PrimaryType = determinePrimaryType(result.Sources)

	return result
}

// DiscoverForPaths runs discovery scoped to specific paths within a file list.
// Only files under the specified paths are considered.
func DiscoverForPaths(files, paths []string) *Result {
	var filtered []string
	for _, f := range files {
		for _, p := range paths {
			p = strings.TrimSuffix(p, "/")
			if f == p || strings.HasPrefix(f, p+"/") || strings.HasPrefix(f, p+string(filepath.Separator)) {
				filtered = append(filtered, f)
				break
			}
		}
	}
	return Discover(filtered)
}

// isSubdirOf checks if dir is a subdirectory of any directory in the set.
func isSubdirOf(dir string, parentDirs map[string]bool) bool {
	for parent := range parentDirs {
		if strings.HasPrefix(dir, parent+"/") || strings.HasPrefix(dir, parent+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// determinePrimaryType returns the dominant source type.
// Priority: helm > kustomize > raw.
func determinePrimaryType(sources []DetectedSource) SourceType {
	counts := map[SourceType]int{}
	for _, s := range sources {
		counts[s.Type]++
	}

	// If any Helm sources exist, Helm is primary.
	if counts[SourceTypeHelm] > 0 {
		return SourceTypeHelm
	}
	if counts[SourceTypeKustomize] > 0 {
		return SourceTypeKustomize
	}
	return SourceTypeRaw
}
