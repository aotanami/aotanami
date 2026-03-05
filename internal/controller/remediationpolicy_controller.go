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

	aotanamiv1alpha1 "github.com/aotanami/aotanami/api/v1alpha1"
	"github.com/aotanami/aotanami/internal/conditions"
	"github.com/aotanami/aotanami/internal/correlator"
	aotmetrics "github.com/aotanami/aotanami/internal/metrics"
	"github.com/aotanami/aotanami/internal/remediation"
	"github.com/aotanami/aotanami/internal/scanner"
)

// RemediationPolicyReconciler reconciles a RemediationPolicy object.
// It queries the correlator for open incidents, generates remediation plans
// via the LLM, and submits GitOps PRs for detected violations.
type RemediationPolicyReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	Recorder          record.EventRecorder
	CorrelatorEngine  *correlator.Engine  // Shared correlator for incident queries.
	RemediationEngine *remediation.Engine // Generates plans & PRs from findings.
}

// +kubebuilder:rbac:groups=aotanami.com,resources=remediationpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=aotanami.com,resources=remediationpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=aotanami.com,resources=remediationpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=aotanami.com,resources=gitopsrepositories,verbs=get;list;watch
// +kubebuilder:rbac:groups=aotanami.com,resources=securitypolicies,verbs=get;list;watch

// Reconcile implements the active remediation loop:
// 1. Validate GitOpsRepository & SecurityPolicies
// 2. Query correlator for open incidents
// 3. For matching incidents, generate remediation plans via LLM
// 4. Submit GitOps PRs (or dry-run/report)
// 5. Update status with PR counts
func (r *RemediationPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		aotmetrics.ReconcileDuration.WithLabelValues("remediationpolicy").Observe(time.Since(start).Seconds())
	}()

	policy := &aotanamiv1alpha1.RemediationPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching RemediationPolicy: %w", err)
	}

	log.Info("Reconciling RemediationPolicy", "name", policy.Name,
		"gitopsRepo", policy.Spec.GitOpsRepository, "dryRun", policy.Spec.DryRun,
		"severityFilter", policy.Spec.SeverityFilter)

	// Mark as reconciling.
	conditions.MarkReconciling(&policy.Status.Conditions, "Reconciliation in progress", policy.Generation)

	// ── Step 1: Validate GitOpsRepository ──
	repo := &aotanamiv1alpha1.GitOpsRepository{}
	repoKey := types.NamespacedName{Name: policy.Spec.GitOpsRepository, Namespace: policy.Namespace}
	if err := r.Get(ctx, repoKey, repo); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
				fmt.Sprintf("GitOpsRepository %q not found", policy.Spec.GitOpsRepository))
			conditions.MarkFalse(&policy.Status.Conditions, aotanamiv1alpha1.ConditionGitOpsConnected,
				aotanamiv1alpha1.ReasonTargetNotFound,
				fmt.Sprintf("GitOpsRepository %q not found", policy.Spec.GitOpsRepository), policy.Generation)
			conditions.MarkFalse(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
				aotanamiv1alpha1.ReasonTargetNotFound, "Referenced GitOpsRepository not found", policy.Generation)
			policy.Status.Phase = aotanamiv1alpha1.PhaseError
			policy.Status.ObservedGeneration = policy.Generation
			if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
			}
			return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching GitOpsRepository: %w", err)
	}

	conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionGitOpsConnected,
		aotanamiv1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("GitOpsRepository %q is available (phase: %s)", repo.Name, repo.Status.Phase), policy.Generation)

	// ── Step 2: Validate targeted SecurityPolicies ──
	if len(policy.Spec.TargetPolicies) > 0 {
		for _, policyName := range policy.Spec.TargetPolicies {
			sp := &aotanamiv1alpha1.SecurityPolicy{}
			spKey := types.NamespacedName{Name: policyName, Namespace: policy.Namespace}
			if err := r.Get(ctx, spKey, sp); err != nil {
				if errors.IsNotFound(err) {
					r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
						fmt.Sprintf("Target SecurityPolicy %q not found", policyName))
				}
			}
		}
	}

	// ── Step 3: Query correlator for open incidents ──
	var prsCreated int32
	if r.CorrelatorEngine != nil && r.RemediationEngine != nil {
		prsCreated = r.processIncidents(ctx, policy, repo)
	} else {
		log.Info("Correlator or remediation engine not configured — skipping active remediation")
	}

	// ── Step 4: Update status ──
	now := metav1.Now()
	policy.Status.Phase = aotanamiv1alpha1.PhaseActive
	policy.Status.LastRun = &now
	policy.Status.RemediationsApplied += prsCreated
	policy.Status.ObservedGeneration = policy.Generation
	conditions.MarkTrue(&policy.Status.Conditions, aotanamiv1alpha1.ConditionReady,
		aotanamiv1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("RemediationPolicy is active (PRs created this cycle: %d, total: %d)",
			prsCreated, policy.Status.RemediationsApplied), policy.Generation)

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, aotanamiv1alpha1.EventReasonReconciled,
		fmt.Sprintf("RemediationPolicy reconciled (repo=%s, dryRun=%v, prsCreated=%d, severity>=%s)",
			policy.Spec.GitOpsRepository, policy.Spec.DryRun, prsCreated, policy.Spec.SeverityFilter))

	aotmetrics.ReconcileTotal.WithLabelValues("remediationpolicy", "success").Inc()
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// processIncidents queries the correlator for open incidents, filters by severity,
// generates remediation plans, and optionally submits PRs.
func (r *RemediationPolicyReconciler) processIncidents(
	ctx context.Context,
	policy *aotanamiv1alpha1.RemediationPolicy,
	repo *aotanamiv1alpha1.GitOpsRepository,
) int32 {
	log := logf.FromContext(ctx)

	incidents := r.CorrelatorEngine.GetOpenIncidents()
	if len(incidents) == 0 {
		log.Info("No open incidents found — nothing to remediate")
		return 0
	}

	log.Info("Found open incidents", "count", len(incidents))

	// Determine severity threshold.
	severityFilter := policy.Spec.SeverityFilter
	if severityFilter == "" {
		severityFilter = "high"
	}
	minSev := severityOrder[severityFilter]

	// Respect MaxConcurrentPRs limit.
	maxPRs := policy.Spec.MaxConcurrentPRs
	if maxPRs == 0 {
		maxPRs = 5
	}

	// Parse repo owner/name from URL for PR submission.
	repoOwner, repoName := parseRepoURL(repo.Spec.URL)

	var prsCreated int32
	for _, incident := range incidents {
		if prsCreated >= maxPRs {
			log.Info("MaxConcurrentPRs limit reached", "limit", maxPRs)
			break
		}

		// Filter by severity.
		incSev, ok := severityOrder[incident.Severity]
		if !ok {
			continue
		}
		if incSev > minSev {
			continue // Incident severity is below threshold.
		}

		// Convert incident to a scanner.Finding for the remediation engine.
		finding := incidentToFinding(incident)

		// Generate remediation plan.
		plan, err := r.RemediationEngine.GeneratePlan(ctx, finding)
		if err != nil {
			log.Error(err, "Failed to generate remediation plan",
				"incident", incident.ID,
				"resource", fmt.Sprintf("%s/%s", incident.Namespace, incident.Resource))
			r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
				fmt.Sprintf("LLM plan generation failed for incident %s: %v", incident.ID, err))
			continue
		}

		log.Info("Generated remediation plan",
			"incident", incident.ID,
			"fixes", len(plan.Fixes),
			"riskScore", plan.RiskScore,
			"dryRun", policy.Spec.DryRun)

		// Apply the plan (strategy is configured on the remediation engine).
		result, err := r.RemediationEngine.ApplyPlan(ctx, plan, repoOwner, repoName)
		if err != nil {
			log.Error(err, "Failed to apply remediation plan",
				"incident", incident.ID)
			r.Recorder.Event(policy, corev1.EventTypeWarning, aotanamiv1alpha1.EventReasonReconcileError,
				fmt.Sprintf("Failed to apply fix for incident %s: %v", incident.ID, err))
			continue
		}

		if result != nil {
			log.Info("Remediation PR created",
				"incident", incident.ID,
				"prURL", result.URL)
			r.Recorder.Event(policy, corev1.EventTypeNormal, "RemediationPRCreated",
				fmt.Sprintf("Created PR %s for incident %s (risk=%d)",
					result.URL, incident.ID, plan.RiskScore))
		}

		// Resolve the incident after successful remediation.
		r.CorrelatorEngine.ResolveIncident(incident.ID)
		prsCreated++
	}

	return prsCreated
}

// incidentToFinding converts a correlator incident to a scanner finding for the
// remediation engine. Uses the most recent event's details.
func incidentToFinding(incident *correlator.Incident) *scanner.Finding {
	f := &scanner.Finding{
		Title:             incident.Title,
		Severity:          incident.Severity,
		ResourceNamespace: incident.Namespace,
		ResourceName:      incident.Resource,
		Description:       fmt.Sprintf("Correlated incident %s with %d events", incident.ID, len(incident.Events)),
	}

	// Enrich from events if available.
	if len(incident.Events) > 0 {
		latest := incident.Events[len(incident.Events)-1]
		f.ResourceKind = latest.ResourceKind
		f.RuleType = string(latest.Type)
		if latest.Message != "" {
			f.Title = latest.Message
		}
	}

	return f
}

// parseRepoURL extracts owner and repo name from a Git URL.
// Handles both HTTPS and SSH URL formats.
func parseRepoURL(url string) (string, string) {
	// Simple heuristic: extract from "github.com/owner/repo" pattern.
	// Works for: https://github.com/owner/repo.git, git@github.com:owner/repo.git
	parts := []string{"", ""}
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] == '/' || url[i] == ':' {
			remainder := url[i+1:]
			// Strip .git suffix.
			if len(remainder) > 4 && remainder[len(remainder)-4:] == ".git" {
				remainder = remainder[:len(remainder)-4]
			}
			parts[1] = remainder
			// Find owner.
			for j := i - 1; j >= 0; j-- {
				if url[j] == '/' || url[j] == ':' || url[j] == '@' {
					parts[0] = url[j+1 : i]
					return parts[0], parts[1]
				}
			}
			break
		}
	}
	return parts[0], parts[1]
}

// SetupWithManager sets up the controller with the Manager.
func (r *RemediationPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&aotanamiv1alpha1.RemediationPolicy{}).
		Named("remediationpolicy").
		Complete(r)
}
