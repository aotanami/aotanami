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
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	aotanamiv1alpha1 "github.com/aotanami/aotanami/api/v1alpha1"
	"github.com/aotanami/aotanami/internal/conditions"
	"github.com/aotanami/aotanami/internal/correlator"
	aotmetrics "github.com/aotanami/aotanami/internal/metrics"
	"github.com/aotanami/aotanami/internal/scanner"
)

const (
	// requeueIntervalScan is the default continuous scan interval.
	requeueIntervalScan = 5 * time.Minute
)

// severityOrder defines the ordering of severity levels (lower index = higher severity).
var severityOrder = map[string]int{
	aotanamiv1alpha1.SeverityCritical: 0,
	aotanamiv1alpha1.SeverityHigh:     1,
	aotanamiv1alpha1.SeverityMedium:   2,
	aotanamiv1alpha1.SeverityLow:      3,
	aotanamiv1alpha1.SeverityInfo:     4,
}

// SecurityPolicyReconciler reconciles a SecurityPolicy object.
// It resolves target workloads, runs security scanners, filters findings
// by severity, and updates the resource status with violation counts.
type SecurityPolicyReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	Recorder         record.EventRecorder
	ScannerRegistry  *scanner.Registry
	CorrelatorEngine *correlator.Engine // Shared correlator for cross-signal event correlation.
}

// +kubebuilder:rbac:groups=aotanami.com,resources=securitypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aotanami.com,resources=securitypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aotanami.com,resources=securitypolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements the main reconciliation loop for SecurityPolicy.
//
//nolint:gocyclo // Controller reconciliation logic is inherently complex.
func (r *SecurityPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		aotmetrics.ReconcileDuration.WithLabelValues("securitypolicy").Observe(time.Since(start).Seconds())
	}()

	// Fetch the SecurityPolicy resource.
	policy := &aotanamiv1alpha1.SecurityPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			log.Info("SecurityPolicy resource not found — likely deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching SecurityPolicy: %w", err)
	}

	log.Info("Reconciling SecurityPolicy", "name", policy.Name, "namespace", policy.Namespace,
		"generation", policy.Generation, "rulesCount", len(policy.Spec.Rules))

	// ── Step 1: Resolve target pods ──
	pods, err := r.resolveTargetPods(ctx, policy)
	if err != nil {
		r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
			fmt.Sprintf("Failed to resolve target pods: %v", err))
		conditions.MarkFalse(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
			aotanamiv1alpha1.ReasonReconcileFailed, fmt.Sprintf("Failed to resolve targets: %v", err), policy.Generation)
		policy.Status.Phase = aotanamiv1alpha1.PhaseError
		policy.Status.ObservedGeneration = policy.Generation
		if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
		}
		aotmetrics.ReconcileTotal.WithLabelValues("securitypolicy", "error").Inc()
		return ctrl.Result{RequeueAfter: requeueIntervalScan}, nil
	}

	log.Info("Resolved target pods", "count", len(pods))

	r.Recorder.Event(policy, corev1.EventTypeNormal, aotanamiv1alpha1.EventReasonScanStarted,
		fmt.Sprintf("Starting scan: %d rules against %d pods", len(policy.Spec.Rules), len(pods)))

	// ── Step 2: Run scanners for each rule ──
	var allFindings []scanner.Finding
	var scanErrors []string
	minSeverity := severityOrder[policy.Spec.Severity]

	for _, rule := range policy.Spec.Rules {
		s := r.ScannerRegistry.Get(rule.Type)
		if s == nil {
			log.Info("No scanner registered for rule type — skipping", "ruleType", rule.Type)
			continue
		}

		findings, scanErr := s.Scan(ctx, pods, rule.Params)
		if scanErr != nil {
			log.Error(scanErr, "Scanner failed", "scanner", s.Name(), "ruleType", rule.Type)
			r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
				fmt.Sprintf("Scanner %q failed: %v", s.Name(), scanErr))
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", s.Name(), scanErr))
			continue
		}

		// Filter findings by severity threshold.
		for i := range findings {
			f := &findings[i]
			if severityOrder[f.Severity] <= minSeverity {
				allFindings = append(allFindings, *f)
			}
		}
	}

	// Sort findings by severity (critical first).
	sort.Slice(allFindings, func(i, j int) bool {
		return severityOrder[allFindings[i].Severity] < severityOrder[allFindings[j].Severity]
	})

	// ── Step 2b: Feed findings into the correlator for cross-signal correlation ──
	if r.CorrelatorEngine != nil && len(allFindings) > 0 {
		for i := range allFindings {
			f := &allFindings[i]
			r.CorrelatorEngine.Ingest(&correlator.Event{
				Type:         correlator.EventSecurityViolation,
				Source:       fmt.Sprintf("securitypolicy/%s", policy.Name),
				Severity:     f.Severity,
				Namespace:    f.ResourceNamespace,
				Resource:     f.ResourceName,
				ResourceKind: f.ResourceKind,
				Message:      f.Title,
			})
		}
		log.Info("Ingested findings into correlator", "count", len(allFindings))
	}

	// ── Step 3: Update status ──
	now := metav1.Now()
	policy.Status.ViolationCount = int32(len(allFindings)) //nolint:gosec // Count is bounded
	policy.Status.LastEvaluated = &now
	policy.Status.ObservedGeneration = policy.Generation

	if len(allFindings) > 0 {
		conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionScanCompleted,
			aotanamiv1alpha1.ReasonViolationsFound,
			fmt.Sprintf("Scan completed: %d violations found", len(allFindings)), policy.Generation)

		r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonViolationsDetected,
			fmt.Sprintf("Found %d violations across %d pods (severity >= %s)",
				len(allFindings), len(pods), policy.Spec.Severity))

		// Log the top 5 findings for visibility.
		limit := 5
		if len(allFindings) < limit {
			limit = len(allFindings)
		}
		for i := range allFindings[:limit] {
			f := &allFindings[i]
			log.Info("Violation detected",
				"severity", f.Severity,
				"title", f.Title,
				"resource", fmt.Sprintf("%s/%s", f.ResourceNamespace, f.ResourceName))
		}
	} else {
		conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionScanCompleted,
			aotanamiv1alpha1.ReasonNoViolations, "Scan completed with no violations", policy.Generation)

		r.Recorder.Event(policy, corev1.EventTypeNormal, aotanamiv1alpha1.EventReasonScanCompleted,
			fmt.Sprintf("Scan completed with 0 violations across %d pods", len(pods)))
	}

	if len(scanErrors) > 0 {
		conditions.MarkFalse(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
			aotanamiv1alpha1.ReasonReconcileFailed,
			fmt.Sprintf("Scans completed with %d error(s): %s", len(scanErrors), strings.Join(scanErrors, "; ")),
			policy.Generation)
		policy.Status.Phase = aotanamiv1alpha1.PhaseDegraded
	} else {
		conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
			aotanamiv1alpha1.ReasonReconcileSuccess, "Policy is active and scanning", policy.Generation)
		policy.Status.Phase = aotanamiv1alpha1.PhaseActive
	}

	// Record metrics.
	aotmetrics.PolicyViolationsGauge.WithLabelValues(policy.Name, policy.Namespace, policy.Spec.Severity).Set(float64(len(allFindings)))
	for i := range allFindings {
		f := &allFindings[i]
		aotmetrics.ScanFindingsTotal.WithLabelValues("securitypolicy", f.Severity).Inc()
	}
	aotmetrics.ResourcesScannedTotal.WithLabelValues("securitypolicy").Add(float64(len(pods)))

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	log.Info("SecurityPolicy reconciled",
		"phase", policy.Status.Phase,
		"violations", policy.Status.ViolationCount,
		"podsScanned", len(pods))

	aotmetrics.ReconcileTotal.WithLabelValues("securitypolicy", "success").Inc()
	return ctrl.Result{RequeueAfter: requeueIntervalScan}, nil
}

// resolveTargetPods lists pods matching the policy's scope (namespaces, labels, resource kinds).
func (r *SecurityPolicyReconciler) resolveTargetPods(ctx context.Context, policy *aotanamiv1alpha1.SecurityPolicy) ([]corev1.Pod, error) {
	var targetNamespaces []string

	if len(policy.Spec.Match.Namespaces) > 0 {
		// Use explicitly specified namespaces.
		targetNamespaces = policy.Spec.Match.Namespaces
	} else {
		// List all namespaces (excluding system namespaces and excludeNamespaces).
		nsList := &corev1.NamespaceList{}
		if err := r.List(ctx, nsList); err != nil {
			return nil, fmt.Errorf("listing namespaces: %w", err)
		}
		excludeSet := make(map[string]bool, len(policy.Spec.Match.ExcludeNamespaces))
		for _, ns := range policy.Spec.Match.ExcludeNamespaces {
			excludeSet[ns] = true
		}
		for i := range nsList.Items {
			ns := &nsList.Items[i]
			if excludeSet[ns.Name] {
				continue
			}
			targetNamespaces = append(targetNamespaces, ns.Name)
		}
	}

	// Build label selector if specified.
	var labelSelector labels.Selector
	if policy.Spec.Match.LabelSelector != nil {
		var err error
		labelSelector, err = metav1.LabelSelectorAsSelector(policy.Spec.Match.LabelSelector)
		if err != nil {
			return nil, fmt.Errorf("parsing label selector: %w", err)
		}
	}

	// List pods in each target namespace.
	var allPods []corev1.Pod
	for _, ns := range targetNamespaces {
		podList := &corev1.PodList{}
		listOpts := []client.ListOption{
			client.InNamespace(ns),
		}
		if labelSelector != nil {
			listOpts = append(listOpts, client.MatchingLabelsSelector{Selector: labelSelector})
		}

		if err := r.List(ctx, podList, listOpts...); err != nil {
			return nil, fmt.Errorf("listing pods in namespace %q: %w", ns, err)
		}

		// Filter to running pods only (no point scanning terminated pods).
		for i := range podList.Items {
			if podList.Items[i].Status.Phase == corev1.PodRunning {
				allPods = append(allPods, podList.Items[i])
			}
		}
	}

	return allPods, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&aotanamiv1alpha1.SecurityPolicy{}).
		Named("securitypolicy").
		Complete(r)
}
