/*
Copyright 2026 Zelyo AI
*/

// Package drift detects configuration drift between the live cluster state and
// the desired state defined in Git repositories.
package drift

import (
	"context"
	"fmt"
	"time"
)

// Type classifies the type of configuration drift.
type Type string

// Enumeration of drift types.
const (
	TypeAdded    Type = "added"
	TypeModified Type = "modified"
	TypeDeleted  Type = "deleted"
)

// Result describes a single detected drift between live and desired state.
type Result struct {
	Type         Type      `json:"type"`
	ResourceKind string    `json:"resource_kind"`
	ResourceName string    `json:"resource_name"`
	Namespace    string    `json:"namespace"`
	FieldPath    string    `json:"field_path,omitempty"`
	LiveValue    string    `json:"live_value,omitempty"`
	DesiredValue string    `json:"desired_value,omitempty"`
	DetectedAt   time.Time `json:"detected_at"`
	Severity     string    `json:"severity"`
	Message      string    `json:"message"`
}

// Detector is the interface for drift detection engines.
type Detector interface {
	Detect(ctx context.Context, namespace string) ([]Result, error)
	DetectResource(ctx context.Context, kind, name, namespace string) (*Result, error)
}

// Config configures the drift detector.
type Config struct {
	CheckInterval     time.Duration `json:"check_interval"`
	IgnoreFields      []string      `json:"ignore_fields"`
	IgnoreAnnotations []string      `json:"ignore_annotations"`
	IgnoreLabels      []string      `json:"ignore_labels"`
}

// DefaultConfig returns production defaults.
func DefaultConfig() Config {
	return Config{
		CheckInterval: 5 * time.Minute,
		IgnoreFields: []string{
			".metadata.resourceVersion",
			".metadata.uid",
			".metadata.creationTimestamp",
			".metadata.generation",
			".metadata.managedFields",
			".status",
		},
		IgnoreAnnotations: []string{
			"kubectl.kubernetes.io/last-applied-configuration",
			"deployment.kubernetes.io/revision",
		},
	}
}

// ClassifySeverity determines drift severity based on the resource kind and field.
func ClassifySeverity(kind, fieldPath string) string {
	securityFields := map[string]bool{
		".spec.containers[*].securityContext": true,
		".spec.securityContext":               true,
		".spec.serviceAccountName":            true,
		".spec.hostNetwork":                   true,
		".spec.hostPID":                       true,
		".spec.hostIPC":                       true,
	}
	if securityFields[fieldPath] {
		return "high"
	}

	switch kind {
	case "ClusterRole", "ClusterRoleBinding", "Role", "RoleBinding":
		return "critical"
	case "Secret", "ConfigMap":
		return "high"
	default:
		return "medium"
	}
}

// FormatDrift generates a human-readable description of a drift result.
func FormatDrift(d *Result) string {
	switch d.Type {
	case TypeAdded:
		return fmt.Sprintf("Resource %s/%s exists in cluster but not in Git (shadow resource)",
			d.ResourceKind, d.ResourceName)
	case TypeDeleted:
		return fmt.Sprintf("Resource %s/%s is defined in Git but missing from cluster",
			d.ResourceKind, d.ResourceName)
	case TypeModified:
		return fmt.Sprintf("Resource %s/%s has drifted at %s: live=%q desired=%q",
			d.ResourceKind, d.ResourceName, d.FieldPath, d.LiveValue, d.DesiredValue)
	default:
		return fmt.Sprintf("Unknown drift type %s for %s/%s", d.Type, d.ResourceKind, d.ResourceName)
	}
}
