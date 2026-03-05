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

package controller

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestNormalizeRepoURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"https URL", "https://github.com/org/repo.git", "github.com/org/repo"},
		{"https no .git", "https://github.com/org/repo", "github.com/org/repo"},
		{"ssh URL", "git@github.com:org/repo.git", "github.com/org/repo"},
		{"ssh no .git", "git@github.com:org/repo", "github.com/org/repo"},
		{"http URL", "http://github.com/org/repo.git", "github.com/org/repo"},
		{"trailing slash", "https://github.com/org/repo/", "github.com/org/repo"},
		{"case insensitive", "HTTPS://GitHub.COM/Org/Repo.git", "github.com/org/repo"},
		{"whitespace", "  https://github.com/org/repo.git  ", "github.com/org/repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRepoURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeRepoURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsNoMatchError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNoMatchError(tt.err); got != tt.want {
				t.Errorf("isNoMatchError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestArgoCDAdapterType(t *testing.T) {
	a := NewArgoCDAdapter(nil)
	if a.Type() != "argocd" {
		t.Errorf("Type() = %q, want %q", a.Type(), "argocd")
	}
}

func TestFluxAdapterType(t *testing.T) {
	a := NewFluxAdapter(nil)
	if a.Type() != "flux" {
		t.Errorf("Type() = %q, want %q", a.Type(), "flux")
	}
}

func TestRegistryPanicOnDuplicate(t *testing.T) {
	r := NewRegistry()
	r.Register(NewArgoCDAdapter(nil))

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate registration")
		}
	}()
	r.Register(NewArgoCDAdapter(nil))
}

func TestRegistryList(t *testing.T) {
	r := NewRegistry()
	r.Register(NewArgoCDAdapter(nil))
	r.Register(NewFluxAdapter(nil))

	types := r.List()
	if len(types) != 2 {
		t.Errorf("List() has %d types, want 2", len(types))
	}
}

func TestRegistryGet(t *testing.T) {
	r := NewRegistry()
	r.Register(NewArgoCDAdapter(nil))

	if r.Get("argocd") == nil {
		t.Error("Get(argocd) = nil, want non-nil")
	}
	if r.Get("flux") != nil {
		t.Error("Get(flux) != nil, want nil")
	}
}

func TestParseArgoCDApplication(t *testing.T) {
	tests := []struct {
		name     string
		obj      map[string]interface{}
		repoURL  string
		wantNil  bool
		wantName string
		wantType string
	}{
		{
			name: "matching repo",
			obj: map[string]interface{}{
				"apiVersion": "argoproj.io/v1alpha1",
				"kind":       "Application",
				"metadata": map[string]interface{}{
					"name":      "my-app",
					"namespace": "argocd",
				},
				"spec": map[string]interface{}{
					"source": map[string]interface{}{
						"repoURL": "https://github.com/org/repo.git",
						"path":    "deploy/",
					},
				},
				"status": map[string]interface{}{
					"sync": map[string]interface{}{
						"status": "Synced",
					},
					"health": map[string]interface{}{
						"status": "Healthy",
					},
				},
			},
			repoURL:  "github.com/org/repo",
			wantNil:  false,
			wantName: "my-app",
			wantType: "directory",
		},
		{
			name: "helm source",
			obj: map[string]interface{}{
				"apiVersion": "argoproj.io/v1alpha1",
				"kind":       "Application",
				"metadata": map[string]interface{}{
					"name":      "helm-app",
					"namespace": "argocd",
				},
				"spec": map[string]interface{}{
					"source": map[string]interface{}{
						"repoURL": "https://github.com/org/repo",
						"path":    "charts/myapp",
						"helm":    map[string]interface{}{},
					},
				},
			},
			repoURL:  "github.com/org/repo",
			wantNil:  false,
			wantName: "helm-app",
			wantType: "helm",
		},
		{
			name: "non-matching repo",
			obj: map[string]interface{}{
				"apiVersion": "argoproj.io/v1alpha1",
				"kind":       "Application",
				"metadata": map[string]interface{}{
					"name":      "other-app",
					"namespace": "argocd",
				},
				"spec": map[string]interface{}{
					"source": map[string]interface{}{
						"repoURL": "https://github.com/other/repo",
					},
				},
			},
			repoURL: "github.com/org/repo",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := unstructuredFromMap(tt.obj)
			app := parseArgoCDApplication(obj, tt.repoURL)
			if tt.wantNil {
				if app != nil {
					t.Errorf("expected nil, got %+v", app)
				}
				return
			}
			if app == nil {
				t.Fatal("expected non-nil app")
			}
			if app.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", app.Name, tt.wantName)
			}
			if app.SourceType != tt.wantType {
				t.Errorf("SourceType = %q, want %q", app.SourceType, tt.wantType)
			}
		})
	}
}

func TestGetFluxConditionStatus(t *testing.T) {
	tests := []struct {
		name     string
		obj      map[string]interface{}
		condType string
		want     string
	}{
		{
			name: "ready true",
			obj: map[string]interface{}{
				"status": map[string]interface{}{
					"conditions": []interface{}{
						map[string]interface{}{"type": "Ready", "status": "True"},
					},
				},
			},
			condType: "Ready",
			want:     "Healthy",
		},
		{
			name: "ready false",
			obj: map[string]interface{}{
				"status": map[string]interface{}{
					"conditions": []interface{}{
						map[string]interface{}{"type": "Ready", "status": "False"},
					},
				},
			},
			condType: "Ready",
			want:     "Degraded",
		},
		{
			name:     "no conditions",
			obj:      map[string]interface{}{},
			condType: "Ready",
			want:     "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := unstructuredFromMap(tt.obj)
			got := getFluxConditionStatus(obj, tt.condType)
			if got != tt.want {
				t.Errorf("getFluxConditionStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

// unstructuredFromMap creates an unstructured.Unstructured from a map, setting metadata fields.
func unstructuredFromMap(data map[string]interface{}) unstructured.Unstructured {
	obj := unstructured.Unstructured{Object: data}
	return obj
}
