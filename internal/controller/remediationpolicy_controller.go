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

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/conditions"
	"github.com/zelyo-ai/zelyo-operator/internal/correlator"
	"github.com/zelyo-ai/zelyo-operator/internal/github"
	zelyometrics "github.com/zelyo-ai/zelyo-operator/internal/metrics"
	"github.com/zelyo-ai/zelyo-operator/internal/remediation"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
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

// +kubebuilder:rbac:groups=zelyo.ai,resources=remediationpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=remediationpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=remediationpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=zelyo.ai,resources=gitopsrepositories,verbs=get;list;watch
// +kubebuilder:rbac:groups=zelyo.ai,resources=securitypolicies,verbs=get;list;watch

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
		zelyometrics.ReconcileDuration.WithLabelValues("remediationpolicy").Observe(time.Since(start).Seconds())
	}()

	policy := &zelyov1alpha1.RemediationPolicy{}
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
	repo := &zelyov1alpha1.GitOpsRepository{}
	repoKey := types.NamespacedName{Name: policy.Spec.GitOpsRepository, Namespace: policy.Namespace}
	if err := r.Get(ctx, repoKey, repo); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
				fmt.Sprintf("GitOpsRepository %q not found", policy.Spec.GitOpsRepository))
			conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionGitOpsConnected,
				zelyov1alpha1.ReasonTargetNotFound,
				fmt.Sprintf("GitOpsRepository %q not found", policy.Spec.GitOpsRepository), policy.Generation)
			conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
				zelyov1alpha1.ReasonTargetNotFound, "Referenced GitOpsRepository not found", policy.Generation)
			policy.Status.Phase = zelyov1alpha1.PhaseError
			policy.Status.ObservedGeneration = policy.Generation
			if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
				return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
			}
			return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching GitOpsRepository: %w", err)
	}

	conditions.MarkTrue(&policy.Status.Conditions, zelyov1alpha1.ConditionGitOpsConnected,
		zelyov1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("GitOpsRepository %q is available (phase: %s)", repo.Name, repo.Status.Phase), policy.Generation)

	// ── Step 2: Validate targeted SecurityPolicies ──
	// Non-NotFound errors previously fell through silently; track missing
	// and errored targets explicitly so we can mark a degraded condition
	// and requeue with backoff.
	var missingTargets []string
	if len(policy.Spec.TargetPolicies) > 0 {
		for _, policyName := range policy.Spec.TargetPolicies {
			sp := &zelyov1alpha1.SecurityPolicy{}
			spKey := types.NamespacedName{Name: policyName, Namespace: policy.Namespace}
			if err := r.Get(ctx, spKey, sp); err != nil {
				if errors.IsNotFound(err) {
					missingTargets = append(missingTargets, policyName)
					r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
						fmt.Sprintf("Target SecurityPolicy %q not found", policyName))
					continue
				}
				return ctrl.Result{}, fmt.Errorf("fetching target SecurityPolicy %q: %w", policyName, err)
			}
		}
	}
	if len(missingTargets) > 0 {
		conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileFailed,
			fmt.Sprintf("target SecurityPolicies not found: %s", strings.Join(missingTargets, ", ")),
			policy.Generation)
		policy.Status.Phase = zelyov1alpha1.PhaseError
		policy.Status.ObservedGeneration = policy.Generation
		if err := r.Status().Update(ctx, policy); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
		return ctrl.Result{RequeueAfter: 2 * time.Minute}, nil
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
	policy.Status.Phase = zelyov1alpha1.PhaseActive
	policy.Status.LastRun = &now
	policy.Status.RemediationsApplied += prsCreated
	policy.Status.ObservedGeneration = policy.Generation
	conditions.MarkTrue(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess,
		fmt.Sprintf("RemediationPolicy is active (PRs created this cycle: %d, total: %d)",
			prsCreated, policy.Status.RemediationsApplied), policy.Generation)

	if err := r.Status().Update(ctx, policy); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(policy, corev1.EventTypeNormal, zelyov1alpha1.EventReasonReconciled,
		fmt.Sprintf("RemediationPolicy reconciled (repo=%s, dryRun=%v, prsCreated=%d, severity>=%s)",
			policy.Spec.GitOpsRepository, policy.Spec.DryRun, prsCreated, policy.Spec.SeverityFilter))

	zelyometrics.ReconcileTotal.WithLabelValues("remediationpolicy", "success").Inc()
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// processIncidents queries the correlator for open incidents, filters by severity,
// generates remediation plans, and optionally submits PRs.
func (r *RemediationPolicyReconciler) processIncidents(
	ctx context.Context,
	policy *zelyov1alpha1.RemediationPolicy,
	repo *zelyov1alpha1.GitOpsRepository,
) int32 {
	log := logf.FromContext(ctx)

	incidents := r.CorrelatorEngine.GetOpenIncidents()
	if len(incidents) == 0 {
		log.Info("No open incidents found — nothing to remediate")
		return 0
	}

	log.Info("Found open incidents", "count", len(incidents))

	// Build target-policy allowlist. Empty spec.targetPolicies means "all
	// SecurityPolicies apply" — skip the scope filter entirely.
	var targetSet map[string]struct{}
	if len(policy.Spec.TargetPolicies) > 0 {
		targetSet = make(map[string]struct{}, len(policy.Spec.TargetPolicies))
		for _, name := range policy.Spec.TargetPolicies {
			targetSet[name] = struct{}{}
		}
	}

	// Determine severity threshold.
	severityFilter := policy.Spec.SeverityFilter
	if severityFilter == "" {
		severityFilter = "high"
	}
	minSev := severityOrder[severityFilter]

	// ── Step 3: Initialize GitOps Engine from Secret ──
	if repo.Spec.AuthSecret != "" {
		secret := &corev1.Secret{}
		secretKey := types.NamespacedName{Name: repo.Spec.AuthSecret, Namespace: repo.Namespace}
		if err := r.Get(ctx, secretKey, secret); err == nil {
			token := string(secret.Data["token"])
			if token == "" {
				token = string(secret.Data["api-key"])
			}
			if token != "" {
				ghClient := github.NewPATClient(token, "")
				ghEngine := github.NewEngine(ghClient, log.WithName("github-engine"))
				r.RemediationEngine.SetGitOpsEngine(ghEngine)
				log.Info("Successfully initialized GitOps engine for remediation", "repo", repo.Name)
			}
		}
	}

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
		if !r.incidentInScope(incident, targetSet, minSev) {
			continue
		}
		if r.remediateIncident(ctx, policy, incident, repoOwner, repoName) {
			prsCreated++
		}
	}

	return prsCreated
}

// incidentInScope applies the RemediationPolicy's scope gates (target
// SecurityPolicies and severity threshold) to a single incident. Both
// gates MUST pass for the incident to be remediated. Extracted from
// processIncidents to keep that function within the gocyclo budget.
func (r *RemediationPolicyReconciler) incidentInScope(
	incident *correlator.Incident,
	targetSet map[string]struct{},
	minSev int,
) bool {
	if targetSet != nil && !incidentMatchesTargets(incident, targetSet) {
		return false
	}
	incSev, ok := severityOrder[incident.Severity]
	if !ok {
		return false
	}
	return incSev <= minSev
}

// remediateIncident runs the plan/apply pipeline for a single in-scope
// incident and returns whether a PR-producing cycle completed (so the
// caller can count it against MaxConcurrentPRs). Extracted from
// processIncidents both for readability and to keep the outer loop within
// the gocyclo budget.
func (r *RemediationPolicyReconciler) remediateIncident(
	ctx context.Context,
	policy *zelyov1alpha1.RemediationPolicy,
	incident *correlator.Incident,
	repoOwner, repoName string,
) bool {
	log := logf.FromContext(ctx)

	finding := incidentToFinding(incident)

	plan, err := r.RemediationEngine.GeneratePlan(ctx, finding)
	if err != nil {
		log.Error(err, "Failed to generate remediation plan",
			"incident", incident.ID,
			"resource", fmt.Sprintf("%s/%s", incident.Namespace, incident.Resource))
		r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
			fmt.Sprintf("LLM plan generation failed for incident %s: %v", incident.ID, err))
		return false
	}

	log.Info("Generated remediation plan",
		"incident", incident.ID,
		"fixes", len(plan.Fixes),
		"riskScore", plan.RiskScore,
		"dryRun", policy.Spec.DryRun)

	result, err := r.RemediationEngine.ApplyPlan(ctx, plan, repoOwner, repoName)
	if err != nil {
		log.Error(err, "Failed to apply remediation plan", "incident", incident.ID)
		r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
			fmt.Sprintf("Failed to apply fix for incident %s: %v", incident.ID, err))
		return false
	}

	if result != nil {
		log.Info("Remediation PR created",
			"incident", incident.ID,
			"prURL", result.URL)
		r.Recorder.Event(policy, corev1.EventTypeNormal, "RemediationPRCreated",
			fmt.Sprintf("Created PR %s for incident %s (risk=%d)",
				result.URL, incident.ID, plan.RiskScore))
	}

	// Resolve the incident after the remediation cycle completes without
	// error — whether or not a PR was actually produced (dry-run and
	// report strategies return result=nil with err=nil).
	r.CorrelatorEngine.ResolveIncident(incident.ID)
	return true
}

// incidentMatchesTargets reports whether the incident carries at least one
// event from a SecurityPolicy in the given allowlist. An incident may be a
// correlation of events from multiple SecurityPolicies on the same
// resource; if any one of them is targeted, the RemediationPolicy applies.
// Events without a SecurityPolicy (e.g. anomalies, deployments) never
// satisfy the scope gate on their own — only SecurityPolicy-originated
// events do.
func incidentMatchesTargets(incident *correlator.Incident, targets map[string]struct{}) bool {
	if incident == nil || len(targets) == 0 {
		return false
	}
	for _, ev := range incident.Events {
		if ev == nil || ev.SecurityPolicy == "" {
			continue
		}
		if _, ok := targets[ev.SecurityPolicy]; ok {
			return true
		}
	}
	return false
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
func parseRepoURL(url string) (owner, repo string) {
	// Simple heuristic: extract from "github.com/owner/repo" pattern.
	// Works for: https://github.com/owner/repo.git, git@github.com:owner/repo.git
	for i := len(url) - 1; i >= 0; i-- {
		if url[i] != '/' && url[i] != ':' {
			continue
		}

		remainder := url[i+1:]
		// Strip .git suffix.
		if len(remainder) > 4 && remainder[len(remainder)-4:] == ".git" {
			remainder = remainder[:len(remainder)-4]
		}
		repo = remainder

		// Find owner.
		for j := i - 1; j >= 0; j-- {
			if url[j] == '/' || url[j] == ':' || url[j] == '@' {
				owner = url[j+1 : i]
				return owner, repo
			}
		}
		break
	}
	return "", ""
}

// SetupWithManager sets up the controller with the Manager.
func (r *RemediationPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.RemediationPolicy{}).
		Named("remediationpolicy").
		Complete(r)
}
