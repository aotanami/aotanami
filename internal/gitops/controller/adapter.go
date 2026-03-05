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

// Package controller provides GitOps controller adapters for Zelyo Operator.
//
// # Architecture
//
// The controller package abstracts the interaction with external GitOps controllers
// (ArgoCD, Flux). Each adapter implements the Adapter interface, providing a
// uniform way to:
//
//   - Detect if the controller is installed on the cluster
//   - Discover applications managed by the controller for a given repo
//   - Query sync status from the controller
//   - Trigger syncs on the controller
//
// The Registry provides thread-safe lookup of adapters by type.
package controller

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Application represents a GitOps-managed application discovered on the cluster.
type Application struct {
	// Name is the application resource name.
	Name string

	// Namespace is the namespace of the application resource.
	Namespace string

	// RepoURL is the git repository URL this application references.
	RepoURL string

	// Path is the path within the repo this application deploys from.
	Path string

	// SourceType is the source type (helm, kustomize, directory).
	SourceType string

	// SyncStatus is the current sync status (e.g., "Synced", "OutOfSync").
	SyncStatus string

	// HealthStatus is the current health status (e.g., "Healthy", "Degraded").
	HealthStatus string
}

// SyncStatus holds detailed sync information from a GitOps controller.
type SyncStatus struct {
	// Status is the overall sync status.
	Status string

	// Revision is the git revision (commit SHA) that is synced.
	Revision string

	// SyncedAt is when the last sync occurred.
	SyncedAt *time.Time

	// OutOfSync lists resource names that are out of sync.
	OutOfSync []string
}

// Adapter is the interface for interacting with a GitOps controller.
type Adapter interface {
	// Type returns the controller type identifier (e.g., "argocd", "flux").
	Type() string

	// Detect checks if this controller is installed on the cluster
	// by probing for its CRDs or API groups.
	Detect(ctx context.Context) (bool, error)

	// ListApplications returns applications managed by this controller
	// that reference the given repository URL.
	ListApplications(ctx context.Context, repoURL string) ([]Application, error)

	// GetSyncStatus returns detailed sync status for a specific application.
	GetSyncStatus(ctx context.Context, app *Application) (*SyncStatus, error)
}

// Registry is a thread-safe registry of controller Adapter implementations.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry creates an empty controller adapter registry.
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[string]Adapter),
	}
}

// Register adds an adapter to the registry.
// It panics if an adapter for the same type is already registered.
func (r *Registry) Register(a Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.adapters[a.Type()]; exists {
		panic(fmt.Sprintf("controller adapter already registered for type: %s", a.Type()))
	}
	r.adapters[a.Type()] = a
}

// Get returns the adapter for the given type, or nil if not found.
func (r *Registry) Get(controllerType string) Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.adapters[controllerType]
}

// List returns all registered controller types.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	adapterTypes := make([]string, 0, len(r.adapters))
	for t := range r.adapters {
		adapterTypes = append(adapterTypes, t)
	}
	return adapterTypes
}

// DetectInstalled probes the cluster for installed GitOps controllers.
// Returns the type of the first detected controller, or "none" if none found.
// Uses a 10-second timeout to prevent slow API calls from blocking reconciliation.
func (r *Registry) DetectInstalled(ctx context.Context) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Apply a timeout to prevent slow cluster probes from blocking reconciliation.
	detectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Check ArgoCD first (most common), then Flux.
	for _, priority := range []string{"argocd", "flux"} {
		a, ok := r.adapters[priority]
		if !ok {
			continue
		}
		found, err := a.Detect(detectCtx)
		if err != nil {
			continue // Don't fail on detection errors; try next.
		}
		if found {
			return priority, nil
		}
	}
	return "none", nil
}

// DefaultRegistry returns a Registry pre-loaded with all built-in adapters.
func DefaultRegistry(c client.Client) *Registry {
	r := NewRegistry()
	r.Register(NewArgoCDAdapter(c))
	r.Register(NewFluxAdapter(c))
	return r
}

// --- ArgoCD Adapter ---

// ArgoCDAdapter integrates with ArgoCD by reading its Application CRDs.
type ArgoCDAdapter struct {
	client client.Client
}

// NewArgoCDAdapter creates an ArgoCD adapter with the given client.
func NewArgoCDAdapter(c client.Client) *ArgoCDAdapter {
	return &ArgoCDAdapter{client: c}
}

// Type returns "argocd".
func (a *ArgoCDAdapter) Type() string { return "argocd" }

// Detect checks if ArgoCD is installed by listing Application CRDs.
func (a *ArgoCDAdapter) Detect(ctx context.Context) (bool, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "argoproj.io",
		Version: "v1alpha1",
		Kind:    "ApplicationList",
	})

	err := a.client.List(ctx, list, &client.ListOptions{Limit: 1})
	if err != nil {
		if errors.IsNotFound(err) || isNoMatchError(err) {
			return false, nil
		}
		return false, fmt.Errorf("detecting ArgoCD: %w", err)
	}
	return true, nil
}

// ListApplications finds ArgoCD Applications referencing the given repo URL.
func (a *ArgoCDAdapter) ListApplications(ctx context.Context, repoURL string) ([]Application, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "argoproj.io",
		Version: "v1alpha1",
		Kind:    "ApplicationList",
	})

	if err := a.client.List(ctx, list); err != nil {
		if isNoMatchError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing ArgoCD applications: %w", err)
	}

	normalizedURL := normalizeRepoURL(repoURL)
	var apps []Application

	for _, item := range list.Items {
		app := parseArgoCDApplication(item, normalizedURL)
		if app != nil {
			apps = append(apps, *app)
		}
	}

	return apps, nil
}

// GetSyncStatus returns sync status for an ArgoCD Application.
func (a *ArgoCDAdapter) GetSyncStatus(ctx context.Context, app *Application) (*SyncStatus, error) {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "argoproj.io",
		Version: "v1alpha1",
		Kind:    "Application",
	})

	if err := a.client.Get(ctx, types.NamespacedName{
		Name:      app.Name,
		Namespace: app.Namespace,
	}, obj); err != nil {
		return nil, fmt.Errorf("getting ArgoCD application %s/%s: %w", app.Namespace, app.Name, err)
	}

	return parseArgoCDSyncStatus(obj)
}

// parseArgoCDApplication extracts an Application from an unstructured ArgoCD Application.
func parseArgoCDApplication(obj unstructured.Unstructured, normalizedRepoURL string) *Application {
	// ArgoCD Application spec.source.repoURL or spec.sources[].repoURL.
	repoURL, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "repoURL")
	if normalizeRepoURL(repoURL) != normalizedRepoURL {
		// Check multi-source apps.
		sources, found, _ := unstructured.NestedSlice(obj.Object, "spec", "sources")
		if !found {
			return nil
		}
		matched := false
		for _, src := range sources {
			srcMap, ok := src.(map[string]interface{})
			if !ok {
				continue
			}
			srcURL, _ := srcMap["repoURL"].(string)
			if normalizeRepoURL(srcURL) == normalizedRepoURL {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	}

	path, _, _ := unstructured.NestedString(obj.Object, "spec", "source", "path")
	syncStatus, _, _ := unstructured.NestedString(obj.Object, "status", "sync", "status")
	healthStatus, _, _ := unstructured.NestedString(obj.Object, "status", "health", "status")

	// Determine source type.
	sourceType := "directory"
	if _, found, _ := unstructured.NestedMap(obj.Object, "spec", "source", "helm"); found {
		sourceType = "helm"
	} else if _, found, _ := unstructured.NestedMap(obj.Object, "spec", "source", "kustomize"); found {
		sourceType = "kustomize"
	}

	return &Application{
		Name:         obj.GetName(),
		Namespace:    obj.GetNamespace(),
		RepoURL:      repoURL,
		Path:         path,
		SourceType:   sourceType,
		SyncStatus:   syncStatus,
		HealthStatus: healthStatus,
	}
}

// parseArgoCDSyncStatus extracts SyncStatus from an unstructured ArgoCD Application.
func parseArgoCDSyncStatus(obj *unstructured.Unstructured) (*SyncStatus, error) {
	status := &SyncStatus{}

	syncStatusStr, _, _ := unstructured.NestedString(obj.Object, "status", "sync", "status")
	status.Status = syncStatusStr

	revision, _, _ := unstructured.NestedString(obj.Object, "status", "sync", "revision")
	status.Revision = revision

	// Parse reconciledAt timestamp.
	reconciledAt, _, _ := unstructured.NestedString(obj.Object, "status", "reconciledAt")
	if reconciledAt != "" {
		if t, err := time.Parse(time.RFC3339, reconciledAt); err == nil {
			status.SyncedAt = &t
		}
	}

	// Collect out-of-sync resources.
	resources, found, _ := unstructured.NestedSlice(obj.Object, "status", "resources")
	if found {
		for _, res := range resources {
			resMap, ok := res.(map[string]interface{})
			if !ok {
				continue
			}
			resStatus, _ := resMap["status"].(string)
			if resStatus == "OutOfSync" {
				name, _ := resMap["name"].(string)
				kind, _ := resMap["kind"].(string)
				status.OutOfSync = append(status.OutOfSync, fmt.Sprintf("%s/%s", kind, name))
			}
		}
	}

	return status, nil
}

// --- Flux Adapter ---

// FluxAdapter integrates with Flux by reading its GitRepository, Kustomization,
// and HelmRelease CRDs.
type FluxAdapter struct {
	client client.Client
}

// NewFluxAdapter creates a Flux adapter with the given client.
func NewFluxAdapter(c client.Client) *FluxAdapter {
	return &FluxAdapter{client: c}
}

// Type returns "flux".
func (a *FluxAdapter) Type() string { return "flux" }

// Detect checks if Flux is installed by probing for its source-controller CRDs.
func (a *FluxAdapter) Detect(ctx context.Context) (bool, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "source.toolkit.fluxcd.io",
		Version: "v1",
		Kind:    "GitRepositoryList",
	})

	err := a.client.List(ctx, list, &client.ListOptions{Limit: 1})
	if err != nil {
		if errors.IsNotFound(err) || isNoMatchError(err) {
			return false, nil
		}
		return false, fmt.Errorf("detecting Flux: %w", err)
	}
	return true, nil
}

// ListApplications finds Flux Kustomizations and HelmReleases that reference
// GitRepositories pointing to the given repo URL.
func (a *FluxAdapter) ListApplications(ctx context.Context, repoURL string) ([]Application, error) {
	// First, find GitRepository resources matching the URL.
	gitRepoNames, err := a.findGitRepositories(ctx, repoURL)
	if err != nil {
		return nil, err
	}

	if len(gitRepoNames) == 0 {
		return nil, nil
	}

	var apps []Application

	// Find Kustomizations referencing these GitRepositories.
	kustomizations, err := a.findFluxKustomizations(ctx, gitRepoNames)
	if err != nil {
		return nil, err
	}
	apps = append(apps, kustomizations...)

	// Find HelmReleases referencing these GitRepositories.
	helmReleases, err := a.findFluxHelmReleases(ctx, gitRepoNames)
	if err != nil {
		return nil, err
	}
	apps = append(apps, helmReleases...)

	return apps, nil
}

// GetSyncStatus returns sync status for a Flux Kustomization or HelmRelease.
func (a *FluxAdapter) GetSyncStatus(ctx context.Context, app *Application) (*SyncStatus, error) {
	obj := &unstructured.Unstructured{}

	switch app.SourceType {
	case "helm":
		obj.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "helm.toolkit.fluxcd.io",
			Version: "v2",
			Kind:    "HelmRelease",
		})
	default:
		obj.SetGroupVersionKind(schema.GroupVersionKind{
			Group:   "kustomize.toolkit.fluxcd.io",
			Version: "v1",
			Kind:    "Kustomization",
		})
	}

	if err := a.client.Get(ctx, types.NamespacedName{
		Name:      app.Name,
		Namespace: app.Namespace,
	}, obj); err != nil {
		return nil, fmt.Errorf("getting Flux resource %s/%s: %w", app.Namespace, app.Name, err)
	}

	return parseFluxSyncStatus(obj)
}

// findGitRepositories finds Flux GitRepository resources referencing the given URL.
func (a *FluxAdapter) findGitRepositories(ctx context.Context, repoURL string) (map[string]string, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "source.toolkit.fluxcd.io",
		Version: "v1",
		Kind:    "GitRepositoryList",
	})

	if err := a.client.List(ctx, list); err != nil {
		if isNoMatchError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing Flux GitRepositories: %w", err)
	}

	normalizedURL := normalizeRepoURL(repoURL)
	// Map of namespace/name → URL.
	result := make(map[string]string)

	for _, item := range list.Items {
		url, _, _ := unstructured.NestedString(item.Object, "spec", "url")
		if normalizeRepoURL(url) == normalizedURL {
			key := item.GetNamespace() + "/" + item.GetName()
			result[key] = url
		}
	}

	return result, nil
}

// findFluxKustomizations finds Flux Kustomizations that reference the given GitRepositories.
func (a *FluxAdapter) findFluxKustomizations(ctx context.Context, gitRepoNames map[string]string) ([]Application, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "kustomize.toolkit.fluxcd.io",
		Version: "v1",
		Kind:    "KustomizationList",
	})

	if err := a.client.List(ctx, list); err != nil {
		if isNoMatchError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing Flux Kustomizations: %w", err)
	}

	var apps []Application
	for _, item := range list.Items {
		sourceRef, found, _ := unstructured.NestedMap(item.Object, "spec", "sourceRef")
		if !found {
			continue
		}

		kind, _ := sourceRef["kind"].(string)
		name, _ := sourceRef["name"].(string)
		ns, _ := sourceRef["namespace"].(string)
		if ns == "" {
			ns = item.GetNamespace()
		}

		if kind != "GitRepository" {
			continue
		}

		key := ns + "/" + name
		if _, ok := gitRepoNames[key]; !ok {
			continue
		}

		path, _, _ := unstructured.NestedString(item.Object, "spec", "path")
		readyStatus := getFluxConditionStatus(item, "Ready")

		apps = append(apps, Application{
			Name:         item.GetName(),
			Namespace:    item.GetNamespace(),
			Path:         path,
			SourceType:   "kustomize",
			SyncStatus:   readyStatus,
			HealthStatus: readyStatus,
		})
	}

	return apps, nil
}

// findFluxHelmReleases finds Flux HelmReleases that reference the given GitRepositories.
func (a *FluxAdapter) findFluxHelmReleases(ctx context.Context, gitRepoNames map[string]string) ([]Application, error) {
	list := &unstructured.UnstructuredList{}
	list.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "helm.toolkit.fluxcd.io",
		Version: "v2",
		Kind:    "HelmReleaseList",
	})

	if err := a.client.List(ctx, list); err != nil {
		if isNoMatchError(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing Flux HelmReleases: %w", err)
	}

	var apps []Application
	for _, item := range list.Items {
		// HelmRelease can reference a GitRepository via spec.chart.spec.sourceRef.
		sourceRef, found, _ := unstructured.NestedMap(item.Object, "spec", "chart", "spec", "sourceRef")
		if !found {
			continue
		}

		kind, _ := sourceRef["kind"].(string)
		name, _ := sourceRef["name"].(string)
		ns, _ := sourceRef["namespace"].(string)
		if ns == "" {
			ns = item.GetNamespace()
		}

		if kind != "GitRepository" {
			continue
		}

		key := ns + "/" + name
		if _, ok := gitRepoNames[key]; !ok {
			continue
		}

		chartPath, _, _ := unstructured.NestedString(item.Object, "spec", "chart", "spec", "chart")
		readyStatus := getFluxConditionStatus(item, "Ready")

		apps = append(apps, Application{
			Name:         item.GetName(),
			Namespace:    item.GetNamespace(),
			Path:         chartPath,
			SourceType:   "helm",
			SyncStatus:   readyStatus,
			HealthStatus: readyStatus,
		})
	}

	return apps, nil
}

// parseFluxSyncStatus extracts SyncStatus from a Flux resource.
func parseFluxSyncStatus(obj *unstructured.Unstructured) (*SyncStatus, error) {
	status := &SyncStatus{}

	readyCondStatus := ""
	conditions, found, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if found {
		for _, cond := range conditions {
			condMap, ok := cond.(map[string]interface{})
			if !ok {
				continue
			}
			condType, _ := condMap["type"].(string)
			if condType == "Ready" {
				readyCondStatus, _ = condMap["status"].(string)
				break
			}
		}
	}
	if readyCondStatus == "True" {
		status.Status = "Synced"
	} else {
		status.Status = "OutOfSync"
	}

	// Get last applied revision.
	revision, _, _ := unstructured.NestedString(obj.Object, "status", "lastAppliedRevision")
	status.Revision = revision

	// Parse lastHandledReconcileAt.
	reconciledAt, _, _ := unstructured.NestedString(obj.Object, "status", "lastHandledReconcileAt")
	if reconciledAt != "" {
		if t, err := time.Parse(time.RFC3339, reconciledAt); err == nil {
			status.SyncedAt = &t
		}
	}

	return status, nil
}

// --- Helpers ---

// getFluxConditionStatus retrieves the status of a named condition from a Flux resource.
func getFluxConditionStatus(obj unstructured.Unstructured, condType string) string {
	conditions, found, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	if !found {
		return "Unknown"
	}
	for _, cond := range conditions {
		condMap, ok := cond.(map[string]interface{})
		if !ok {
			continue
		}
		ct, _ := condMap["type"].(string)
		if ct == condType {
			status, _ := condMap["status"].(string)
			if status == "True" {
				return "Healthy"
			}
			return "Degraded"
		}
	}
	return "Unknown"
}

// normalizeRepoURL normalizes a git URL for comparison.
// It strips protocols, trailing .git suffix, and trailing slashes.
func normalizeRepoURL(url string) string {
	url = strings.TrimSpace(url)
	url = strings.ToLower(url)

	// Remove protocol.
	for _, prefix := range []string{"https://", "http://", "git://", "ssh://", "git@"} {
		url = strings.TrimPrefix(url, prefix)
	}

	// Handle git@ style (git@github.com:org/repo.git → github.com/org/repo).
	url = strings.Replace(url, ":", "/", 1)

	// Remove .git suffix and trailing slashes.
	url = strings.TrimSuffix(url, ".git")
	url = strings.TrimSuffix(url, "/")

	return url
}

// isNoMatchError returns true if the error indicates the API resource type
// is not registered on the cluster (CRD not installed).
func isNoMatchError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "no matches for kind") ||
		strings.Contains(err.Error(), "the server could not find the requested resource") ||
		strings.Contains(err.Error(), "no match")
}
