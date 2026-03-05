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

package drift

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	yamlutil "sigs.k8s.io/yaml"

	"github.com/aotanami/aotanami/internal/gitops"
)

// LiveDetector implements the Detector interface by comparing live cluster
// resources against their desired state in a Git repository.
type LiveDetector struct {
	k8s    client.Client
	git    gitops.Engine
	owner  string
	repo   string
	basRef string
	config Config
	log    logr.Logger
}

// LiveDetectorConfig configures the LiveDetector.
type LiveDetectorConfig struct {
	// K8sClient is the controller-runtime client for cluster access.
	K8sClient client.Client

	// GitEngine is the Git repository access engine.
	GitEngine gitops.Engine

	// RepoOwner is the Git repository owner.
	RepoOwner string

	// RepoName is the Git repository name.
	RepoName string

	// BaseRef is the Git ref to compare against (e.g., "main").
	BaseRef string

	// Config is the drift detection configuration.
	Config Config

	// Log is the logger.
	Log logr.Logger
}

// NewLiveDetector creates a new LiveDetector.
func NewLiveDetector(cfg LiveDetectorConfig) *LiveDetector {
	baseRef := cfg.BaseRef
	if baseRef == "" {
		baseRef = "main"
	}

	config := cfg.Config
	if config.CheckInterval == 0 {
		config = DefaultConfig()
	}

	return &LiveDetector{
		k8s:    cfg.K8sClient,
		git:    cfg.GitEngine,
		owner:  cfg.RepoOwner,
		repo:   cfg.RepoName,
		basRef: baseRef,
		config: config,
		log:    cfg.Log,
	}
}

// watchedGVKs defines the resource types the drift detector monitors.
var watchedGVKs = []schema.GroupVersionKind{
	{Group: "apps", Version: "v1", Kind: "Deployment"},
	{Group: "apps", Version: "v1", Kind: "StatefulSet"},
	{Group: "apps", Version: "v1", Kind: "DaemonSet"},
	{Group: "", Version: "v1", Kind: "Service"},
	{Group: "", Version: "v1", Kind: "ConfigMap"},
	{Group: "", Version: "v1", Kind: "Secret"},
	{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "Role"},
	{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "RoleBinding"},
}

// Detect scans all watched resources in a namespace and compares them against Git.
func (d *LiveDetector) Detect(ctx context.Context, namespace string) ([]Result, error) {
	d.log.Info("Starting drift detection", "namespace", namespace)

	var allDrifts []Result

	for _, gvk := range watchedGVKs {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   gvk.Group,
			Version: gvk.Version,
			Kind:    gvk.Kind + "List",
		})

		if err := d.k8s.List(ctx, list, client.InNamespace(namespace)); err != nil {
			d.log.Error(err, "Failed to list resources", "kind", gvk.Kind, "namespace", namespace)
			continue
		}

		for i := range list.Items {
			item := &list.Items[i]
			result, err := d.compareResource(ctx, item, gvk.Kind)
			if err != nil {
				d.log.Error(err, "Failed to compare resource",
					"kind", gvk.Kind,
					"name", item.GetName())
				continue
			}
			if result != nil {
				allDrifts = append(allDrifts, *result)
			}
		}
	}

	d.log.Info("Drift detection complete",
		"namespace", namespace,
		"driftsFound", len(allDrifts))

	return allDrifts, nil
}

// DetectResource checks a single resource for drift.
func (d *LiveDetector) DetectResource(ctx context.Context, kind, name, namespace string) (*Result, error) {
	obj := &unstructured.Unstructured{}
	gvk := kindToGVK(kind)
	obj.SetGroupVersionKind(gvk)

	if err := d.k8s.Get(ctx, client.ObjectKey{Name: name, Namespace: namespace}, obj); err != nil {
		return nil, fmt.Errorf("getting resource %s/%s: %w", namespace, name, err)
	}

	return d.compareResource(ctx, obj, kind)
}

// compareResource compares a live resource against its Git-stored desired state.
func (d *LiveDetector) compareResource(ctx context.Context, live *unstructured.Unstructured, kind string) (*Result, error) {
	name := live.GetName()
	namespace := live.GetNamespace()

	// Build Git file path using common conventions.
	gitPath := d.inferGitPath(kind, name, namespace)

	// Fetch desired state from Git.
	gitContent, err := d.git.GetFile(ctx, d.owner, d.repo, gitPath, d.basRef)
	if err != nil {
		// File not in Git = shadow resource (exists in cluster but not in Git).
		if strings.Contains(err.Error(), "404") {
			return &Result{
				Type:         TypeAdded,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				DetectedAt:   time.Now(),
				Severity:     ClassifySeverity(kind, ""),
				Message:      FormatDrift(&Result{Type: TypeAdded, ResourceKind: kind, ResourceName: name}),
			}, nil
		}
		return nil, err
	}

	// Parse the Git content as an unstructured object.
	// Try JSON first (fast), then YAML (most K8s manifests are YAML).
	desired := &unstructured.Unstructured{}
	if err := json.Unmarshal(gitContent, &desired.Object); err != nil {
		// Try YAML — handle multi-document files by taking the first document.
		yamlContent := gitContent
		if idx := strings.Index(string(gitContent), "\n---\n"); idx >= 0 {
			yamlContent = gitContent[:idx]
		}
		jsonBytes, yamlErr := yamlutil.YAMLToJSON(yamlContent)
		if yamlErr != nil {
			d.log.V(1).Info("Skipping unparseable Git file", "path", gitPath, "jsonErr", err, "yamlErr", yamlErr)
			return nil, nil
		}
		if err := json.Unmarshal(jsonBytes, &desired.Object); err != nil {
			d.log.V(1).Info("Skipping invalid manifest after YAML conversion", "path", gitPath, "err", err)
			return nil, nil
		}
	}

	// Compare spec fields (ignoring metadata, status, and configured ignore fields).
	drifts := d.diffObjects(live.Object, desired.Object, kind, name, namespace, "")

	if len(drifts) > 0 {
		// Return the most severe drift.
		return &drifts[0], nil
	}

	return nil, nil
}

// diffObjects recursively compares two unstructured objects and returns drifts.
func (d *LiveDetector) diffObjects(live, desired map[string]interface{}, kind, name, namespace, prefix string) []Result {
	var results []Result

	for key, desiredVal := range desired {
		fieldPath := prefix + "." + key

		// Skip ignored fields.
		if d.shouldIgnoreField(fieldPath) {
			continue
		}

		liveVal, exists := live[key]
		if !exists {
			results = append(results, Result{
				Type:         TypeModified,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FieldPath:    fieldPath,
				LiveValue:    "<missing>",
				DesiredValue: fmt.Sprintf("%v", desiredVal),
				DetectedAt:   time.Now(),
				Severity:     ClassifySeverity(kind, fieldPath),
				Message:      fmt.Sprintf("Field %s missing in live resource", fieldPath),
			})
			continue
		}

		// Recursively compare nested objects.
		desiredMap, desiredIsMap := desiredVal.(map[string]interface{})
		liveMap, liveIsMap := liveVal.(map[string]interface{})

		if desiredIsMap && liveIsMap {
			nested := d.diffObjects(liveMap, desiredMap, kind, name, namespace, fieldPath)
			results = append(results, nested...)
			continue
		}

		// Compare scalar values.
		if fmt.Sprintf("%v", liveVal) != fmt.Sprintf("%v", desiredVal) {
			results = append(results, Result{
				Type:         TypeModified,
				ResourceKind: kind,
				ResourceName: name,
				Namespace:    namespace,
				FieldPath:    fieldPath,
				LiveValue:    fmt.Sprintf("%v", liveVal),
				DesiredValue: fmt.Sprintf("%v", desiredVal),
				DetectedAt:   time.Now(),
				Severity:     ClassifySeverity(kind, fieldPath),
				Message:      FormatDrift(&Result{Type: TypeModified, ResourceKind: kind, ResourceName: name, FieldPath: fieldPath, LiveValue: fmt.Sprintf("%v", liveVal), DesiredValue: fmt.Sprintf("%v", desiredVal)}),
			})
		}
	}

	return results
}

// shouldIgnoreField checks if a field path should be ignored during comparison.
func (d *LiveDetector) shouldIgnoreField(fieldPath string) bool {
	for _, ignore := range d.config.IgnoreFields {
		if strings.HasPrefix(fieldPath, ignore) {
			return true
		}
	}
	return false
}

// inferGitPath builds the expected Git file path for a Kubernetes resource.
// Supports common conventions: k8s/<namespace>/<kind>-<name>.yaml
func (d *LiveDetector) inferGitPath(kind, name, namespace string) string {
	kindLower := strings.ToLower(kind)
	return fmt.Sprintf("k8s/%s/%s-%s.yaml", namespace, kindLower, name)
}

// kindToGVK maps common Kubernetes kinds to their GroupVersionKind.
func kindToGVK(kind string) schema.GroupVersionKind {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet":
		return schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: kind}
	case "Service", "ConfigMap", "Secret", "Pod", "Namespace", "ServiceAccount":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: kind}
	case "NetworkPolicy":
		return schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: kind}
	case "Role", "RoleBinding":
		return schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: kind}
	case "ClusterRole", "ClusterRoleBinding":
		return schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: kind}
	case "Ingress":
		return schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: kind}
	default:
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: kind}
	}
}
