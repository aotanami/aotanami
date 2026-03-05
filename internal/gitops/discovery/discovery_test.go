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

package discovery

import (
	"testing"
)

func TestDiscover_HelmChart(t *testing.T) {
	files := []string{
		"charts/myapp/Chart.yaml",
		"charts/myapp/values.yaml",
		"charts/myapp/templates/deployment.yaml",
		"charts/myapp/templates/service.yaml",
		"charts/myapp/templates/_helpers.tpl",
	}

	result := Discover(files)

	if result.PrimaryType != SourceTypeHelm {
		t.Errorf("PrimaryType = %q, want %q", result.PrimaryType, SourceTypeHelm)
	}

	// Should have 1 Helm source, not raw sources for templates/ subdir.
	helmCount := 0
	rawCount := 0
	for _, s := range result.Sources {
		switch s.Type {
		case SourceTypeHelm:
			helmCount++
		case SourceTypeRaw:
			rawCount++
		}
	}
	if helmCount != 1 {
		t.Errorf("helm sources = %d, want 1", helmCount)
	}
	if rawCount != 0 {
		t.Errorf("raw sources = %d, want 0 (templates/ should be excluded)", rawCount)
	}
}

func TestDiscover_Kustomize(t *testing.T) {
	files := []string{
		"overlays/prod/kustomization.yaml",
		"overlays/prod/deployment-patch.yaml",
		"overlays/prod/namespace.yaml",
		"base/kustomization.yaml",
		"base/deployment.yaml",
		"base/service.yaml",
	}

	result := Discover(files)

	if result.PrimaryType != SourceTypeKustomize {
		t.Errorf("PrimaryType = %q, want %q", result.PrimaryType, SourceTypeKustomize)
	}

	kustomizeCount := 0
	for _, s := range result.Sources {
		if s.Type == SourceTypeKustomize {
			kustomizeCount++
		}
	}
	if kustomizeCount != 2 {
		t.Errorf("kustomize sources = %d, want 2", kustomizeCount)
	}
}

func TestDiscover_RawManifests(t *testing.T) {
	files := []string{
		"manifests/deployment.yaml",
		"manifests/service.yaml",
		"manifests/configmap.json",
	}

	result := Discover(files)

	if result.PrimaryType != SourceTypeRaw {
		t.Errorf("PrimaryType = %q, want %q", result.PrimaryType, SourceTypeRaw)
	}

	if len(result.Sources) != 1 {
		t.Errorf("sources = %d, want 1", len(result.Sources))
	}
	if result.Sources[0].Type != SourceTypeRaw {
		t.Errorf("source type = %q, want %q", result.Sources[0].Type, SourceTypeRaw)
	}
}

func TestDiscover_Monorepo(t *testing.T) {
	files := []string{
		// A Helm chart app.
		"apps/frontend/Chart.yaml",
		"apps/frontend/values.yaml",
		"apps/frontend/templates/deployment.yaml",
		// A Kustomize app.
		"apps/backend/kustomization.yaml",
		"apps/backend/deployment.yaml",
		// Raw manifests for infra.
		"infra/namespace.yaml",
		"infra/rbac.yaml",
	}

	result := Discover(files)

	if result.PrimaryType != SourceTypeHelm {
		t.Errorf("PrimaryType = %q, want %q (helm should take priority)", result.PrimaryType, SourceTypeHelm)
	}

	typeMap := map[SourceType]int{}
	for _, s := range result.Sources {
		typeMap[s.Type]++
	}

	if typeMap[SourceTypeHelm] != 1 {
		t.Errorf("helm count = %d, want 1", typeMap[SourceTypeHelm])
	}
	if typeMap[SourceTypeKustomize] != 1 {
		t.Errorf("kustomize count = %d, want 1", typeMap[SourceTypeKustomize])
	}
	if typeMap[SourceTypeRaw] != 1 {
		t.Errorf("raw count = %d, want 1", typeMap[SourceTypeRaw])
	}
}

func TestDiscover_EmptyFiles(t *testing.T) {
	result := Discover(nil)

	if result.PrimaryType != SourceTypeRaw {
		t.Errorf("PrimaryType = %q, want %q", result.PrimaryType, SourceTypeRaw)
	}
	if len(result.Sources) != 0 {
		t.Errorf("sources = %d, want 0", len(result.Sources))
	}
}

func TestDiscover_NonManifestFiles(t *testing.T) {
	files := []string{
		"README.md",
		"Makefile",
		".gitignore",
		"docs/architecture.png",
	}

	result := Discover(files)
	if len(result.Sources) != 0 {
		t.Errorf("sources = %d, want 0 (no manifest files)", len(result.Sources))
	}
}

func TestDiscoverForPaths(t *testing.T) {
	files := []string{
		"apps/frontend/Chart.yaml",
		"apps/frontend/values.yaml",
		"apps/backend/kustomization.yaml",
		"apps/backend/deployment.yaml",
		"infra/namespace.yaml",
	}

	result := DiscoverForPaths(files, []string{"apps/frontend"})

	if result.PrimaryType != SourceTypeHelm {
		t.Errorf("PrimaryType = %q, want %q", result.PrimaryType, SourceTypeHelm)
	}
	if len(result.Sources) != 1 {
		t.Errorf("sources = %d, want 1", len(result.Sources))
	}
}

func TestDiscoverDeterministicOrder(t *testing.T) {
	files := []string{
		"z-app/deployment.yaml",
		"a-app/kustomization.yaml",
		"a-app/deployment.yaml",
		"m-app/Chart.yaml",
	}

	result := Discover(files)
	for i := 1; i < len(result.Sources); i++ {
		if result.Sources[i].Path < result.Sources[i-1].Path {
			t.Errorf("sources not sorted: %q comes after %q",
				result.Sources[i].Path, result.Sources[i-1].Path)
		}
	}
}
