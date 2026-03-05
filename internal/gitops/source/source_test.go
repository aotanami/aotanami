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

package source

import (
	"context"
	"testing"
)

func TestRawSourceType(t *testing.T) {
	s := &RawSource{}
	if s.Type() != "raw" {
		t.Errorf("RawSource.Type() = %q, want %q", s.Type(), "raw")
	}
}

func TestRawSourceDetect(t *testing.T) {
	s := &RawSource{}
	// Raw should always detect.
	if !s.Detect(nil) {
		t.Error("RawSource.Detect(nil) = false, want true")
	}
	if !s.Detect([]string{"foo.yaml", "bar.json"}) {
		t.Error("RawSource.Detect(files) = false, want true")
	}
}

func TestRawSourceParse(t *testing.T) {
	s := &RawSource{}
	result, err := s.Parse(context.Background(), &ParseOptions{
		Files: []string{
			"deployment.yaml",
			"service.yml",
			"config.json",
			"readme.md",
			"chart.yaml",         // should be skipped
			"kustomization.yaml", // should be skipped
		},
	})
	if err != nil {
		t.Fatalf("RawSource.Parse() error = %v", err)
	}
	if result.SourceType != "raw" {
		t.Errorf("ParseResult.SourceType = %q, want %q", result.SourceType, "raw")
	}
	// Should have 3 manifests: deployment.yaml, service.yml, config.json.
	if len(result.Manifests) != 3 {
		t.Errorf("len(Manifests) = %d, want 3", len(result.Manifests))
	}
}

func TestHelmSourceDetect(t *testing.T) {
	s := &HelmSourceParser{}

	tests := []struct {
		name  string
		files []string
		want  bool
	}{
		{"with Chart.yaml", []string{"myapp/Chart.yaml", "myapp/values.yaml"}, true},
		{"with chart.yml", []string{"chart.yml"}, true},
		{"without chart", []string{"deployment.yaml", "service.yaml"}, false},
		{"empty", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.Detect(tt.files); got != tt.want {
				t.Errorf("Detect(%v) = %v, want %v", tt.files, got, tt.want)
			}
		})
	}
}

func TestHelmSourceParse(t *testing.T) {
	s := &HelmSourceParser{}
	result, err := s.Parse(context.Background(), &ParseOptions{
		Path: "charts/myapp",
		Files: []string{
			"charts/myapp/Chart.yaml",
			"charts/myapp/values.yaml",
			"charts/myapp/templates/deployment.yaml",
			"charts/myapp/templates/service.yaml",
			"charts/myapp/templates/_helpers.tpl",
			"charts/myapp/README.md",
		},
		HelmReleaseName:      "my-release",
		HelmReleaseNamespace: "production",
	})
	if err != nil {
		t.Fatalf("HelmSourceParser.Parse() error = %v", err)
	}
	if result.SourceType != "helm" {
		t.Errorf("SourceType = %q, want %q", result.SourceType, "helm")
	}
	if result.Metadata["chartPath"] != "charts/myapp/Chart.yaml" {
		t.Errorf("chartPath = %q, want %q", result.Metadata["chartPath"], "charts/myapp/Chart.yaml")
	}
	if result.Metadata["releaseName"] != "my-release" {
		t.Errorf("releaseName = %q, want %q", result.Metadata["releaseName"], "my-release")
	}
}

func TestKustomizeSourceDetect(t *testing.T) {
	s := &KustomizeSourceParser{}

	tests := []struct {
		name  string
		files []string
		want  bool
	}{
		{"with kustomization.yaml", []string{"overlays/prod/kustomization.yaml"}, true},
		{"with kustomization.yml", []string{"kustomization.yml"}, true},
		{"with kustomization (no ext)", []string{"kustomization"}, true},
		{"without kustomization", []string{"deployment.yaml"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.Detect(tt.files); got != tt.want {
				t.Errorf("Detect(%v) = %v, want %v", tt.files, got, tt.want)
			}
		})
	}
}

func TestKustomizeSourceParse(t *testing.T) {
	s := &KustomizeSourceParser{}
	result, err := s.Parse(context.Background(), &ParseOptions{
		Path: "overlays/prod",
		Files: []string{
			"overlays/prod/kustomization.yaml",
			"overlays/prod/deployment-patch.yaml",
			"overlays/prod/namespace.yaml",
			"overlays/prod/README.md",
		},
		KustomizeBuildArgs: []string{"--enable-helm"},
	})
	if err != nil {
		t.Fatalf("KustomizeSourceParser.Parse() error = %v", err)
	}
	if result.SourceType != "kustomize" {
		t.Errorf("SourceType = %q, want %q", result.SourceType, "kustomize")
	}
	if result.Metadata["kustomizationFile"] != "overlays/prod/kustomization.yaml" {
		t.Errorf("kustomizationFile = %q", result.Metadata["kustomizationFile"])
	}
	if result.Metadata["buildArgs"] != "--enable-helm" {
		t.Errorf("buildArgs = %q, want %q", result.Metadata["buildArgs"], "--enable-helm")
	}
	// 2 YAML manifests (excluding kustomization.yaml itself).
	if len(result.Manifests) != 2 {
		t.Errorf("len(Manifests) = %d, want 2", len(result.Manifests))
	}
}

func TestRegistryDetectType(t *testing.T) {
	r := DefaultRegistry()

	tests := []struct {
		name  string
		files []string
		want  string
	}{
		{"helm repo", []string{"Chart.yaml", "values.yaml", "templates/deploy.yaml"}, "helm"},
		{"kustomize repo", []string{"kustomization.yaml", "deploy.yaml", "patch.yaml"}, "kustomize"},
		{"raw repo", []string{"deploy.yaml", "svc.yaml"}, "raw"},
		{"helm takes priority over kustomize", []string{"Chart.yaml", "kustomization.yaml"}, "helm"},
		{"empty", []string{}, "raw"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.DetectType(tt.files); got != tt.want {
				t.Errorf("DetectType(%v) = %q, want %q", tt.files, got, tt.want)
			}
		})
	}
}

func TestRegistryDefaultRegistry(t *testing.T) {
	r := DefaultRegistry()
	types := r.List()
	if len(types) != 3 {
		t.Errorf("DefaultRegistry has %d sources, want 3", len(types))
	}

	for _, st := range []string{"raw", "helm", "kustomize"} {
		if r.Get(st) == nil {
			t.Errorf("DefaultRegistry missing source type %q", st)
		}
	}
}

func TestRegistryPanicOnDuplicate(t *testing.T) {
	r := NewRegistry()
	r.Register(&RawSource{})

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	r.Register(&RawSource{})
}
