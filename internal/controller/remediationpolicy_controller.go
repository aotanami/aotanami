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
	"github.com/zelyo-ai/zelyo-operator/internal/gitops"
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
	//
	// Keyed by NamespacedName because SecurityPolicy is a namespaced CRD:
	// two tenants can legally register policies with the same name, and
	// matching on name alone would let an incident from team-b/baseline
	// satisfy team-a's target "baseline". The upstream validation loop
	// already resolves targetPolicies against policy.Namespace, so using
	// that namespace here keeps the runtime gate consistent with what
	// was actually validated.
	var targetSet map[types.NamespacedName]struct{}
	if len(policy.Spec.TargetPolicies) > 0 {
		targetSet = make(map[types.NamespacedName]struct{}, len(policy.Spec.TargetPolicies))
		for _, name := range policy.Spec.TargetPolicies {
			targetSet[types.NamespacedName{Name: name, Namespace: policy.Namespace}] = struct{}{}
		}
	}

	// Determine severity threshold.
	severityFilter := policy.Spec.SeverityFilter
	if severityFilter == "" {
		severityFilter = "high"
	}
	minSev := severityOrder[severityFilter]

	// ── Step 3: Initialize GitOps Engine from Secret ──
	r.initRemediationGitOps(ctx, repo)

	// Respect MaxConcurrentPRs limit.
	maxPRs := policy.Spec.MaxConcurrentPRs
	if maxPRs == 0 {
		maxPRs = 5
	}

	// Parse repo owner/name from URL for PR submission.
	repoOwner, repoName := parseRepoURL(repo.Spec.URL)

	// One-shot dedup: snapshot the set of branches already backing an open
	// Zelyo-authored PR, so we don't open a second PR for a finding whose
	// last reconcile already produced one. This is the fix for "excessive
	// PRs" — without it, every reconcile tick regenerated incidents for the
	// same unfixed resource and opened another PR.
	existingBranches := r.snapshotOpenPRBranches(ctx, repoOwner, repoName)

	var prsCreated int32
	for _, incident := range incidents {
		if prsCreated >= maxPRs {
			log.Info("MaxConcurrentPRs limit reached", "limit", maxPRs)
			break
		}
		// Scope gate: when spec.targetPolicies is set, only remediate
		// incidents carrying at least one event from a listed
		// SecurityPolicy. Checked in the loop (not inside
		// remediateIncident) so filtered incidents are skipped without
		// paying the dedup/ListOpenPRs cost and without ever calling
		// ResolveIncident on them — another RemediationPolicy may own
		// that scope.
		if targetSet != nil && !incidentMatchesTargets(incident, targetSet) {
			continue
		}
		if r.remediateIncident(ctx, policy, repo, incident,
			minSev, repoOwner, repoName, existingBranches) {
			prsCreated++
		}
	}

	return prsCreated
}

// initRemediationGitOps resolves the GitOpsRepository's auth Secret and
// wires a PAT-backed GitHub engine into the remediation engine. A missing
// Secret, missing token, or missing AuthSecret field is silently skipped
// — the remediation engine then has no way to open PRs but the controller
// is still useful for dry-run/report strategies. Any hard failure is
// non-fatal for reconcile, so this returns nothing. Extracted from
// processIncidents to keep that function within the gocyclo budget.
func (r *RemediationPolicyReconciler) initRemediationGitOps(
	ctx context.Context,
	repo *zelyov1alpha1.GitOpsRepository,
) {
	log := logf.FromContext(ctx)
	if repo.Spec.AuthSecret == "" {
		return
	}
	secret := &corev1.Secret{}
	secretKey := types.NamespacedName{Name: repo.Spec.AuthSecret, Namespace: repo.Namespace}
	if err := r.Get(ctx, secretKey, secret); err != nil {
		return
	}
	token := string(secret.Data["token"])
	if token == "" {
		token = string(secret.Data["api-key"])
	}
	if token == "" {
		return
	}
	ghClient := github.NewPATClient(token, "")
	ghEngine := github.NewEngine(ghClient, log.WithName("github-engine"))
	r.RemediationEngine.SetGitOpsEngine(ghEngine)
	log.Info("Successfully initialized GitOps engine for remediation", "repo", repo.Name)
}

// snapshotOpenPRBranches returns a branch → PR-URL map for the currently
// open, Zelyo-authored PRs against the given repo. A nil gitops engine,
// or a ListOpenPRs failure, yields an empty map (dedup degrades to
// no-dedup — the caller will open PRs even if duplicates already exist).
// Extracted from processIncidents to keep that function within the
// gocyclo budget.
func (r *RemediationPolicyReconciler) snapshotOpenPRBranches(
	ctx context.Context,
	repoOwner, repoName string,
) map[string]string {
	log := logf.FromContext(ctx)
	existing := map[string]string{}
	ge := r.RemediationEngine.GitOpsEngineForRepo(repoOwner, repoName)
	if ge == nil {
		return existing
	}
	open, err := ge.ListOpenPRs(ctx, repoOwner, repoName)
	if err != nil {
		log.Info("PR dedup skipped: ListOpenPRs failed", "error", err.Error())
		return existing
	}
	for _, pr := range open {
		existing[pr.Branch] = pr.URL
	}
	return existing
}

// remediateIncident handles the full severity-check → dedup →
// GeneratePlan → ApplyPlan → resolve flow for a single incident. Returns
// true if a new PR was opened (so the caller can tally against
// MaxConcurrentPRs). Factored out of processIncidents to keep each unit
// under the gocyclo threshold. The targetPolicies scope gate is applied
// by the caller, not here — see processIncidents.
func (r *RemediationPolicyReconciler) remediateIncident(
	ctx context.Context,
	policy *zelyov1alpha1.RemediationPolicy,
	repo *zelyov1alpha1.GitOpsRepository,
	incident *correlator.Incident,
	minSev int,
	repoOwner, repoName string,
	existingBranches map[string]string,
) bool {
	log := logf.FromContext(ctx)

	// Severity filter.
	incSev, ok := severityOrder[incident.Severity]
	if !ok || incSev > minSev {
		return false
	}

	finding := incidentToFinding(incident)

	// Dedup: compute the branch name the PR would land on and skip if a
	// PR is already open for it. The remediation engine uses the same
	// BranchName helper so the keys line up.
	branch := gitops.BranchName(finding.ResourceName, finding.ResourceNamespace, finding.Title)
	if existingURL, exists := existingBranches[branch]; exists {
		log.Info("Skipping remediation — open PR already exists",
			"incident", incident.ID, "branch", branch, "prURL", existingURL)
		// Still mark the incident resolved so we don't loop on it; a
		// future scan will regenerate the incident if the PR is closed
		// without merging and the finding remains.
		r.CorrelatorEngine.ResolveIncident(incident.ID)
		return false
	}

	plan, err := r.RemediationEngine.GeneratePlan(ctx, finding, repo.Spec.Paths)
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
		log.Error(err, "Failed to apply remediation plan",
			"incident", incident.ID)
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
		existingBranches[branch] = result.URL
	}

	r.CorrelatorEngine.ResolveIncident(incident.ID)
	return true
}

// incidentMatchesTargets reports whether the incident carries at least one
// event from a SecurityPolicy in the given allowlist. An incident may be a
// correlation of events from multiple SecurityPolicies on the same
// resource; if any one of them is targeted, the RemediationPolicy applies.
//
// Matching is on the (name, namespace) pair because SecurityPolicy is a
// namespaced CRD. An event missing either half is treated as unmatched —
// anomaly/deployment events legitimately have both blank, and a
// SecurityPolicy-originated event with an empty namespace is malformed
// (see securitypolicy_controller.ingestFindingsToCorrelator) and must
// not be allowed to satisfy the gate by coincidence.
func incidentMatchesTargets(incident *correlator.Incident, targets map[types.NamespacedName]struct{}) bool {
	if incident == nil || len(targets) == 0 {
		return false
	}
	for _, ev := range incident.Events {
		if ev == nil || ev.SecurityPolicy == "" || ev.SecurityPolicyNamespace == "" {
			continue
		}
		key := types.NamespacedName{Name: ev.SecurityPolicy, Namespace: ev.SecurityPolicyNamespace}
		if _, ok := targets[key]; ok {
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
