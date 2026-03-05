/*
Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.
*/

package drift

import (
	"testing"
)

func TestClassifySeverity(t *testing.T) {
	tests := []struct {
		kind      string
		fieldPath string
		expected  string
	}{
		{"Deployment", ".spec.containers[*].securityContext", "high"},
		{"Deployment", ".spec.securityContext", "high"},
		{"Deployment", ".spec.replicas", "medium"},
		{"ClusterRole", ".rules", "critical"},
		{"ClusterRoleBinding", ".subjects", "critical"},
		{"Secret", ".data", "high"},
		{"ConfigMap", ".data", "high"},
		{"Service", ".spec.ports", "medium"},
	}

	for _, tt := range tests {
		result := ClassifySeverity(tt.kind, tt.fieldPath)
		if result != tt.expected {
			t.Errorf("ClassifySeverity(%q, %q) = %q, want %q",
				tt.kind, tt.fieldPath, result, tt.expected)
		}
	}
}

func TestFormatDrift(t *testing.T) {
	tests := []struct {
		name     string
		result   Result
		contains string
	}{
		{
			"added",
			Result{Type: TypeAdded, ResourceKind: "Deployment", ResourceName: "nginx"},
			"exists in cluster but not in Git",
		},
		{
			"deleted",
			Result{Type: TypeDeleted, ResourceKind: "ConfigMap", ResourceName: "config"},
			"defined in Git but missing",
		},
		{
			"modified",
			Result{Type: TypeModified, ResourceKind: "Deployment", ResourceName: "api",
				FieldPath: ".spec.replicas", LiveValue: "3", DesiredValue: "2"},
			"has drifted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := FormatDrift(&tt.result)
			if msg == "" {
				t.Error("Expected non-empty message")
			}
			if !containsSubstring(msg, tt.contains) {
				t.Errorf("Expected message to contain %q, got %q", tt.contains, msg)
			}
		})
	}
}

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.IgnoreFields) == 0 {
		t.Error("Expected non-empty IgnoreFields")
	}
	if len(cfg.IgnoreAnnotations) == 0 {
		t.Error("Expected non-empty IgnoreAnnotations")
	}
}

func TestKindToGVK(t *testing.T) {
	tests := []struct {
		kind          string
		expectedGroup string
	}{
		{"Deployment", "apps"},
		{"StatefulSet", "apps"},
		{"Service", ""},
		{"ConfigMap", ""},
		{"NetworkPolicy", "networking.k8s.io"},
		{"Role", "rbac.authorization.k8s.io"},
		{"ClusterRole", "rbac.authorization.k8s.io"},
	}

	for _, tt := range tests {
		gvk := kindToGVK(tt.kind)
		if gvk.Group != tt.expectedGroup {
			t.Errorf("kindToGVK(%q).Group = %q, want %q", tt.kind, gvk.Group, tt.expectedGroup)
		}
		if gvk.Kind != tt.kind {
			t.Errorf("kindToGVK(%q).Kind = %q, want %q", tt.kind, gvk.Kind, tt.kind)
		}
	}
}

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsCheck(s, sub))
}

func containsCheck(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
