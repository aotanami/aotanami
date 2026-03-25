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

package controller

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo/api/v1alpha1"
	"github.com/zelyo-ai/zelyo/internal/conditions"
	gitopscontroller "github.com/zelyo-ai/zelyo/internal/gitops/controller"
	"github.com/zelyo-ai/zelyo/internal/gitops/discovery"
	"github.com/zelyo-ai/zelyo/internal/gitops/source"
	aotmetrics "github.com/zelyo-ai/zelyo/internal/metrics"
)

// GitOpsRepositoryReconciler reconciles a GitOpsRepository object.
// It validates repo configuration, auto-detects source types (Helm, Kustomize, raw),
// discovers and links GitOps controllers (ArgoCD, Flux), and manages sync lifecycle.
type GitOpsRepositoryReconciler struct {
	client.Client
	Scheme             *runtime.Scheme
	Recorder           record.EventRecorder
	SourceRegistry     *source.Registry
	ControllerRegistry *gitopscontroller.Registry
}

// +kubebuilder:rbac:groups=zelyo.ai,resources=gitopsrepositories,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=gitopsrepositories/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=gitopsrepositories/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=argoproj.io,resources=applications,verbs=get;list;watch
// +kubebuilder:rbac:groups=source.toolkit.fluxcd.io,resources=gitrepositories,verbs=get;list;watch
// +kubebuilder:rbac:groups=kustomize.toolkit.fluxcd.io,resources=kustomizations,verbs=get;list;watch
// +kubebuilder:rbac:groups=helm.toolkit.fluxcd.io,resources=helmreleases,verbs=get;list;watch

// Reconcile validates the GitOpsRepository configuration, detects source types
// and GitOps controllers, and manages sync state.
func (r *GitOpsRepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		aotmetrics.ReconcileDuration.WithLabelValues("gitopsrepository").Observe(time.Since(start).Seconds())
	}()

	repo := &zelyov1alpha1.GitOpsRepository{}
	if err := r.Get(ctx, req.NamespacedName, repo); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching GitOpsRepository: %w", err)
	}

	log.Info("Reconciling GitOpsRepository", "name", repo.Name,
		"url", repo.Spec.URL, "branch", repo.Spec.Branch, "provider", repo.Spec.Provider,
		"sourceType", repo.Spec.SourceType, "controllerType", repo.Spec.ControllerType)

	// Mark as reconciling.
	conditions.MarkReconciling(&repo.Status.Conditions, "Reconciliation in progress", repo.Generation)

	// Phase 1: Validate the auth secret exists.
	if result, err := r.validateAuthSecret(ctx, repo); err != nil || result != nil {
		return *result, err
	}

	// Phase 2: Validate paths are specified.
	if len(repo.Spec.Paths) == 0 {
		conditions.MarkFalse(&repo.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonInvalidConfig, "At least one path must be specified", repo.Generation)
		repo.Status.Phase = zelyov1alpha1.PhaseError
		repo.Status.ObservedGeneration = repo.Generation
		if err := r.Status().Update(ctx, repo); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
		aotmetrics.ReconcileTotal.WithLabelValues("gitopsrepository", "error").Inc()
		return ctrl.Result{}, nil
	}

	// Phase 3: Auto-discover source type.
	r.detectSourceType(ctx, repo)

	// Phase 4: Detect and link GitOps controller.
	r.detectController(ctx, repo)

	// Phase 5: Mark as synced.
	now := metav1.Now()
	repo.Status.Phase = zelyov1alpha1.PhaseSynced
	repo.Status.LastSyncTime = &now
	repo.Status.LastError = ""
	repo.Status.ObservedGeneration = repo.Generation

	conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionGitOpsConnected,
		zelyov1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("Repository %s (branch: %s) is connected", repo.Spec.URL, repo.Spec.Branch), repo.Generation)
	conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess, "Repository is synced and ready", repo.Generation)

	if err := r.Status().Update(ctx, repo); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(repo, corev1.EventTypeNormal, zelyov1alpha1.EventReasonReconciled,
		fmt.Sprintf("GitOpsRepository synced (url=%s, branch=%s, paths=%d, source=%s, controller=%s)",
			repo.Spec.URL, repo.Spec.Branch, len(repo.Spec.Paths),
			r.effectiveSourceType(repo), r.effectiveControllerType(repo)))

	// Requeue at the poll interval.
	requeueAfter := time.Duration(repo.Spec.PollIntervalSeconds) * time.Second
	if requeueAfter == 0 {
		requeueAfter = 5 * time.Minute
	}

	aotmetrics.ReconcileTotal.WithLabelValues("gitopsrepository", "success").Inc()
	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

// validateAuthSecret checks that the authentication secret exists.
func (r *GitOpsRepositoryReconciler) validateAuthSecret(ctx context.Context, repo *zelyov1alpha1.GitOpsRepository) (*ctrl.Result, error) {
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: repo.Spec.AuthSecret, Namespace: repo.Namespace}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(repo, corev1.EventTypeWarning, zelyov1alpha1.EventReasonSecretMissing,
				fmt.Sprintf("Auth Secret %q not found", repo.Spec.AuthSecret))
			conditions.MarkFalse(&repo.Status.Conditions, zelyov1alpha1.ConditionSecretResolved,
				zelyov1alpha1.ReasonSecretNotFound,
				fmt.Sprintf("Secret %q not found", repo.Spec.AuthSecret), repo.Generation)
			conditions.MarkFalse(&repo.Status.Conditions, zelyov1alpha1.ConditionReady,
				zelyov1alpha1.ReasonSecretNotFound, "Authentication secret not available", repo.Generation)
			repo.Status.Phase = zelyov1alpha1.PhaseError
			repo.Status.LastError = fmt.Sprintf("Auth secret %q not found", repo.Spec.AuthSecret)
			repo.Status.ObservedGeneration = repo.Generation
			if statusErr := r.Status().Update(ctx, repo); statusErr != nil {
				return &ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
			}
			aotmetrics.ReconcileTotal.WithLabelValues("gitopsrepository", "error").Inc()
			result := ctrl.Result{RequeueAfter: 2 * time.Minute}
			return &result, nil
		}
		return &ctrl.Result{}, fmt.Errorf("fetching auth secret: %w", err)
	}

	conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionSecretResolved,
		zelyov1alpha1.ReasonSecretResolved, "Authentication secret is available", repo.Generation)
	return nil, nil
}

// detectSourceType determines the manifest source type via auto-discovery or explicit config.
func (r *GitOpsRepositoryReconciler) detectSourceType(ctx context.Context, repo *zelyov1alpha1.GitOpsRepository) {
	log := logf.FromContext(ctx)
	sourceType := repo.Spec.SourceType
	if sourceType == "" {
		sourceType = zelyov1alpha1.ManifestSourceAuto
	}

	if sourceType != zelyov1alpha1.ManifestSourceAuto {
		// Explicitly configured source type.
		repo.Status.DetectedSourceType = sourceType
		conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionSourceDetected,
			zelyov1alpha1.ReasonSourceConfigured,
			fmt.Sprintf("Source type explicitly configured as %q", sourceType), repo.Generation)
		return
	}

	// Auto-detect: simulate file discovery from paths.
	// In a full implementation, this would clone the repo and list files.
	// For now, use the discovery engine with path-based heuristics.
	simulatedFiles := simulateFileDiscovery(repo.Spec.Paths, repo.Spec.Helm, repo.Spec.Kustomize)
	result := discovery.Discover(simulatedFiles)

	detectedType := zelyov1alpha1.ManifestSourceType(result.PrimaryType)
	repo.Status.DetectedSourceType = detectedType

	var reason, message string
	switch detectedType {
	case zelyov1alpha1.ManifestSourceHelm:
		reason = zelyov1alpha1.ReasonHelmDetected
		message = fmt.Sprintf("Helm chart detected in %d path(s)", len(result.Sources))
	case zelyov1alpha1.ManifestSourceKustomize:
		reason = zelyov1alpha1.ReasonKustomizeDetected
		message = fmt.Sprintf("Kustomize overlays detected in %d path(s)", len(result.Sources))
	default:
		reason = zelyov1alpha1.ReasonSourceAutoDetected
		message = fmt.Sprintf("Raw manifests detected in %d path(s)", len(result.Sources))
	}

	conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionSourceDetected,
		reason, message, repo.Generation)

	log.Info("Source type detected", "type", detectedType, "sources", len(result.Sources))

	r.Recorder.Event(repo, corev1.EventTypeNormal, zelyov1alpha1.EventReasonSourceDetected,
		fmt.Sprintf("Source type detected: %s", detectedType))
}

// detectController discovers which GitOps controller manages this repository.
func (r *GitOpsRepositoryReconciler) detectController(ctx context.Context, repo *zelyov1alpha1.GitOpsRepository) {
	log := logf.FromContext(ctx)

	// If controller registry is not available, skip detection.
	if r.ControllerRegistry == nil {
		return
	}

	controllerType := repo.Spec.ControllerType
	if controllerType == "" {
		controllerType = zelyov1alpha1.ControllerAuto
	}

	// If explicit controller ref is provided, link directly.
	if repo.Spec.ControllerRef != nil {
		repo.Status.DetectedController = repo.Spec.ControllerRef.Type
		conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionControllerLinked,
			zelyov1alpha1.ReasonControllerLinked,
			fmt.Sprintf("Linked to %s %s/%s", repo.Spec.ControllerRef.Type,
				repo.Spec.ControllerRef.Namespace, repo.Spec.ControllerRef.Name), repo.Generation)
		repo.Status.DiscoveredApplications = 1
		return
	}

	// If controller type is "none", skip detection.
	if controllerType == zelyov1alpha1.ControllerNone {
		repo.Status.DetectedController = zelyov1alpha1.ControllerNone
		conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionControllerLinked,
			zelyov1alpha1.ReasonControllerNotFound, "No GitOps controller configured (standalone mode)", repo.Generation)
		return
	}

	// Auto-detect or use explicit type.
	var detectedType string
	if controllerType == zelyov1alpha1.ControllerAuto {
		var err error
		detectedType, err = r.ControllerRegistry.DetectInstalled(ctx)
		if err != nil {
			log.Error(err, "Error detecting GitOps controller")
		}
	} else {
		detectedType = string(controllerType)
	}

	repo.Status.DetectedController = zelyov1alpha1.GitOpsControllerType(detectedType)

	if detectedType == "none" {
		conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionControllerLinked,
			zelyov1alpha1.ReasonControllerNotFound, "No GitOps controller detected on cluster", repo.Generation)
		return
	}

	// List applications from the detected controller.
	adapter := r.ControllerRegistry.Get(detectedType)
	if adapter == nil {
		return
	}

	apps, err := adapter.ListApplications(ctx, repo.Spec.URL)
	if err != nil {
		log.Error(err, "Error listing applications from controller", "controller", detectedType)
		conditions.MarkFalse(&repo.Status.Conditions, zelyov1alpha1.ConditionControllerLinked,
			zelyov1alpha1.ReasonReconcileFailed,
			fmt.Sprintf("Error listing applications from %s: %v", detectedType, err), repo.Generation)
		return
	}

	repo.Status.DiscoveredApplications = int32(len(apps)) //nolint:gosec // Application count is bounded by API limits

	if len(apps) > 0 {
		conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionControllerLinked,
			zelyov1alpha1.ReasonControllerLinked,
			fmt.Sprintf("%s detected: %d application(s) linked", detectedType, len(apps)), repo.Generation)

		r.Recorder.Event(repo, corev1.EventTypeNormal, zelyov1alpha1.EventReasonControllerLinked,
			fmt.Sprintf("Linked to %s with %d application(s)", detectedType, len(apps)))

		log.Info("GitOps controller linked", "controller", detectedType, "applications", len(apps))
	} else {
		conditions.MarkTrue(&repo.Status.Conditions, zelyov1alpha1.ConditionControllerLinked,
			zelyov1alpha1.ReasonControllerAutoDetected,
			fmt.Sprintf("%s detected but no matching applications found for %s", detectedType, repo.Spec.URL), repo.Generation)
	}
}

// effectiveSourceType returns the active source type (detected or configured).
func (r *GitOpsRepositoryReconciler) effectiveSourceType(repo *zelyov1alpha1.GitOpsRepository) zelyov1alpha1.ManifestSourceType {
	if repo.Status.DetectedSourceType != "" {
		return repo.Status.DetectedSourceType
	}
	if repo.Spec.SourceType != "" && repo.Spec.SourceType != zelyov1alpha1.ManifestSourceAuto {
		return repo.Spec.SourceType
	}
	return zelyov1alpha1.ManifestSourceRaw
}

// effectiveControllerType returns the active controller type (detected or configured).
func (r *GitOpsRepositoryReconciler) effectiveControllerType(repo *zelyov1alpha1.GitOpsRepository) zelyov1alpha1.GitOpsControllerType {
	if repo.Status.DetectedController != "" {
		return repo.Status.DetectedController
	}
	if repo.Spec.ControllerType != "" && repo.Spec.ControllerType != zelyov1alpha1.ControllerAuto {
		return repo.Spec.ControllerType
	}
	return zelyov1alpha1.ControllerNone
}

// simulateFileDiscovery builds a simulated file list from repo paths and config hints.
// In production, this would be replaced by actual git clone + file listing.
func simulateFileDiscovery(paths []string, helm *zelyov1alpha1.HelmSource, kustomize *zelyov1alpha1.KustomizeSource) []string {
	var files []string

	for _, p := range paths {
		// Add the path itself as a potential YAML directory.
		files = append(files, filepath.Join(strings.TrimSuffix(p, "/"), "deployment.yaml"))
	}

	// If Helm config is present, add Chart.yaml hint.
	if helm != nil {
		chartPath := helm.ChartPath
		if chartPath == "" && len(paths) > 0 {
			chartPath = paths[0]
		}
		files = append(files, filepath.Join(strings.TrimSuffix(chartPath, "/"), "Chart.yaml"))
		files = append(files, helm.ValuesFiles...)
	}

	// If Kustomize config is present, add kustomization.yaml hint.
	if kustomize != nil {
		overlayPaths := kustomize.OverlayPaths
		if len(overlayPaths) == 0 {
			overlayPaths = paths
		}
		for _, op := range overlayPaths {
			files = append(files, filepath.Join(strings.TrimSuffix(op, "/"), "kustomization.yaml"))
		}
	}

	return files
}

// SetupWithManager sets up the controller with the Manager.
func (r *GitOpsRepositoryReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.GitOpsRepository{}).
		Named("gitopsrepository").
		Complete(r)
}
