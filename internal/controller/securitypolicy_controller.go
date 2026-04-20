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
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/conditions"
	"github.com/zelyo-ai/zelyo-operator/internal/correlator"
	zelyometrics "github.com/zelyo-ai/zelyo-operator/internal/metrics"
	"github.com/zelyo-ai/zelyo-operator/internal/notifier"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

const (
	// requeueIntervalScan is the default continuous scan interval.
	requeueIntervalScan = 5 * time.Minute
)

// severityOrder defines the ordering of severity levels (lower index = higher severity).
var severityOrder = map[string]int{
	zelyov1alpha1.SeverityCritical: 0,
	zelyov1alpha1.SeverityHigh:     1,
	zelyov1alpha1.SeverityMedium:   2,
	zelyov1alpha1.SeverityLow:      3,
	zelyov1alpha1.SeverityInfo:     4,
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

// +kubebuilder:rbac:groups=zelyo.ai,resources=securitypolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=securitypolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=securitypolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=zelyo.ai,resources=notificationchannels,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements the main reconciliation loop for SecurityPolicy.
func (r *SecurityPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		zelyometrics.ReconcileDuration.WithLabelValues("securitypolicy").Observe(time.Since(start).Seconds())
	}()

	policy := &zelyov1alpha1.SecurityPolicy{}
	if err := r.Get(ctx, req.NamespacedName, policy); err != nil {
		if errors.IsNotFound(err) {
			log.Info("SecurityPolicy resource not found — likely deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching SecurityPolicy: %w", err)
	}

	log.Info("Reconciling SecurityPolicy", "name", policy.Name, "namespace", policy.Namespace,
		"generation", policy.Generation, "rulesCount", len(policy.Spec.Rules))

	// Step 1: Resolve target pods.
	pods, err := r.resolveTargetPods(ctx, policy)
	if err != nil {
		return r.handlePodResolutionError(ctx, policy, err)
	}

	log.Info("Resolved target pods", "count", len(pods))
	r.Recorder.Event(policy, corev1.EventTypeNormal, zelyov1alpha1.EventReasonScanStarted,
		fmt.Sprintf("Starting scan: %d rules against %d pods", len(policy.Spec.Rules), len(pods)))

	// Step 2: Run scanners, correlate, notify.
	eval := r.runPolicyScanners(ctx, policy, pods)
	r.ingestFindingsToCorrelator(ctx, policy, eval.findings)

	if len(eval.findings) > 0 {
		r.sendNotifications(ctx, policy, eval.findings)
	}

	// Step 3: Update status and metrics.
	if err := r.updatePolicyStatus(ctx, policy, eval, len(pods)); err != nil {
		return ctrl.Result{}, err
	}

	zelyometrics.ReconcileTotal.WithLabelValues("securitypolicy", "success").Inc()
	return ctrl.Result{RequeueAfter: requeueIntervalScan}, nil
}

// handlePodResolutionError records a failure event and updates status when target pods cannot be resolved.
func (r *SecurityPolicyReconciler) handlePodResolutionError(ctx context.Context, policy *zelyov1alpha1.SecurityPolicy, err error) (ctrl.Result, error) {
	r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
		fmt.Sprintf("Failed to resolve target pods: %v", err))
	conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileFailed, fmt.Sprintf("Failed to resolve targets: %v", err), policy.Generation)
	policy.Status.Phase = zelyov1alpha1.PhaseError
	policy.Status.ObservedGeneration = policy.Generation
	if statusErr := r.Status().Update(ctx, policy); statusErr != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
	}
	zelyometrics.ReconcileTotal.WithLabelValues("securitypolicy", "error").Inc()
	return ctrl.Result{RequeueAfter: requeueIntervalScan}, nil
}

// policyEvalResult holds the output of running policy scanners against target pods.
type policyEvalResult struct {
	findings   []scanner.Finding
	scanErrors []string
}

// runPolicyScanners executes scanners for each policy rule and filters findings by severity threshold.
func (r *SecurityPolicyReconciler) runPolicyScanners(ctx context.Context, policy *zelyov1alpha1.SecurityPolicy, pods []corev1.Pod) *policyEvalResult {
	log := logf.FromContext(ctx)
	eval := &policyEvalResult{}
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
			r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
				fmt.Sprintf("Scanner %q failed: %v", s.Name(), scanErr))
			eval.scanErrors = append(eval.scanErrors, fmt.Sprintf("%s: %v", s.Name(), scanErr))
			continue
		}

		for i := range findings {
			f := &findings[i]
			if severityOrder[f.Severity] <= minSeverity {
				eval.findings = append(eval.findings, *f)
			}
		}
	}

	sort.Slice(eval.findings, func(i, j int) bool {
		return severityOrder[eval.findings[i].Severity] < severityOrder[eval.findings[j].Severity]
	})
	return eval
}

// ingestFindingsToCorrelator feeds scan findings into the agentic correlator engine.
func (r *SecurityPolicyReconciler) ingestFindingsToCorrelator(ctx context.Context, policy *zelyov1alpha1.SecurityPolicy, findings []scanner.Finding) {
	if r.CorrelatorEngine == nil || len(findings) == 0 {
		return
	}
	log := logf.FromContext(ctx)
	for i := range findings {
		f := &findings[i]
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
	log.Info("Ingested findings into correlator", "count", len(findings))
}

// updatePolicyStatus writes the reconciliation result into the SecurityPolicy status.
func (r *SecurityPolicyReconciler) updatePolicyStatus(ctx context.Context, policy *zelyov1alpha1.SecurityPolicy, eval *policyEvalResult, podsScanned int) error {
	log := logf.FromContext(ctx)
	now := metav1.Now()
	policy.Status.ViolationCount = int32(len(eval.findings)) //nolint:gosec // Count is bounded
	policy.Status.LastEvaluated = &now
	policy.Status.ObservedGeneration = policy.Generation

	if len(eval.findings) > 0 {
		conditions.MarkTrue(&policy.Status.Conditions, zelyov1alpha1.ConditionScanCompleted,
			zelyov1alpha1.ReasonViolationsFound,
			fmt.Sprintf("Scan completed: %d violations found", len(eval.findings)), policy.Generation)
		r.Recorder.Event(policy, corev1.EventTypeWarning, zelyov1alpha1.EventReasonViolationsDetected,
			fmt.Sprintf("Found %d violations across %d pods (severity >= %s)",
				len(eval.findings), podsScanned, policy.Spec.Severity))
		limit := min(5, len(eval.findings))
		for i := range eval.findings[:limit] {
			f := &eval.findings[i]
			log.Info("Violation detected",
				"severity", f.Severity, "title", f.Title,
				"resource", fmt.Sprintf("%s/%s", f.ResourceNamespace, f.ResourceName))
		}
	} else {
		conditions.MarkTrue(&policy.Status.Conditions, zelyov1alpha1.ConditionScanCompleted,
			zelyov1alpha1.ReasonNoViolations, "Scan completed with no violations", policy.Generation)
		r.Recorder.Event(policy, corev1.EventTypeNormal, zelyov1alpha1.EventReasonScanCompleted,
			fmt.Sprintf("Scan completed with 0 violations across %d pods", podsScanned))
	}

	if len(eval.scanErrors) > 0 {
		conditions.MarkFalse(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileFailed,
			fmt.Sprintf("Scans completed with %d error(s): %s", len(eval.scanErrors), strings.Join(eval.scanErrors, "; ")),
			policy.Generation)
		policy.Status.Phase = zelyov1alpha1.PhaseDegraded
	} else {
		conditions.MarkTrue(&policy.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileSuccess, "Policy is active and scanning", policy.Generation)
		policy.Status.Phase = zelyov1alpha1.PhaseActive
	}

	zelyometrics.PolicyViolationsGauge.WithLabelValues(policy.Name, policy.Namespace, policy.Spec.Severity).Set(float64(len(eval.findings)))
	for i := range eval.findings {
		f := &eval.findings[i]
		zelyometrics.ScanFindingsTotal.WithLabelValues("securitypolicy", f.Severity).Inc()
	}
	zelyometrics.ResourcesScannedTotal.WithLabelValues("securitypolicy").Add(float64(podsScanned))

	if err := r.Status().Update(ctx, policy); err != nil {
		return fmt.Errorf("updating status: %w", err)
	}

	log.Info("SecurityPolicy reconciled",
		"phase", policy.Status.Phase,
		"violations", policy.Status.ViolationCount,
		"podsScanned", podsScanned)
	return nil
}

// resolveTargetPods lists pods matching the policy's scope (namespaces, labels, resource kinds).
func (r *SecurityPolicyReconciler) resolveTargetPods(ctx context.Context, policy *zelyov1alpha1.SecurityPolicy) ([]corev1.Pod, error) {
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

// sendNotifications fetches applicable NotificationChannels and delivers alerts.
func (r *SecurityPolicyReconciler) sendNotifications(ctx context.Context, policy *zelyov1alpha1.SecurityPolicy, findings []scanner.Finding) {
	log := logf.FromContext(ctx)
	log.Info("Checking for notification channels", "policy", policy.Name, "findings", len(findings))

	// List all notification channels in the cluster.
	channels := &zelyov1alpha1.NotificationChannelList{}
	if err := r.List(ctx, channels); err != nil {
		log.Error(err, "Failed to list notification channels")
		return
	}

	log.Info("Found notification channels", "count", len(channels.Items))
	if len(channels.Items) == 0 {
		return
	}

	// Build notifier configurations.
	var notifierConfigs []notifier.ChannelConfig
	for i := range channels.Items {
		ch := &channels.Items[i]
		log.Info("Evaluating channel", "name", ch.Name, "type", ch.Spec.Type, "severityFilter", ch.Spec.SeverityFilter)

		config := notifier.ChannelConfig{
			Type:        notifier.ChannelType(ch.Spec.Type),
			Name:        ch.Name,
			MinSeverity: notifier.Severity(ch.Spec.SeverityFilter),
		}

		// Handle Slack-specific config (using CredentialSecret for webhook URL).
		if ch.Spec.Type == "slack" {
			secret := &corev1.Secret{}
			secretKey := types.NamespacedName{Name: ch.Spec.CredentialSecret, Namespace: ch.Namespace}
			log.Info("Fetching Slack secret", "name", ch.Spec.CredentialSecret, "namespace", ch.Namespace)
			if err := r.Get(ctx, secretKey, secret); err != nil {
				log.Error(err, "Failed to fetch Slack webhook secret", "secret", ch.Spec.CredentialSecret)
				continue
			}
			url := string(secret.Data["url"])
			if url == "" {
				url = string(secret.Data["webhook-url"])
			}
			if url != "" {
				log.Info("Slack webhook URL found", "channel", ch.Name)
				config.WebhookURL = url
				notifierConfigs = append(notifierConfigs, config)
			} else {
				log.Info("Slack webhook URL EMPTY in secret", "channel", ch.Name, "secret", ch.Spec.CredentialSecret)
			}
		}
	}

	log.Info("Notifier configurations ready", "count", len(notifierConfigs))
	if len(notifierConfigs) == 0 {
		return
	}

	n := notifier.New(notifierConfigs, log.WithName("notifier"))

	// Bundle findings into one notification for efficiency.
	var msg strings.Builder
	msg.WriteString("Found security violations in your cluster:\n\n")
	for i := range findings {
		f := &findings[i]
		if i >= 10 {
			msg.WriteString(fmt.Sprintf("\n... and %d more", len(findings)-10))
			break
		}
		msg.WriteString(fmt.Sprintf("• *[%s]* %s (%s/%s)\n", f.Severity, f.Title, f.ResourceNamespace, f.ResourceName))
	}

	notif := &notifier.Notification{
		Title:        fmt.Sprintf("🛡️ Zelyo Alert: %d Violations Detected", len(findings)),
		Message:      msg.String(),
		Severity:     notifier.Severity(findings[0].Severity), // Use highest severity.
		Source:       fmt.Sprintf("securitypolicy/%s", policy.Name),
		Namespace:    policy.Namespace,
		ResourceKind: "SecurityPolicy",
		ResourceName: policy.Name,
		Timestamp:    time.Now(),
	}

	log.Info("Dispatching notification", "source", notif.Source, "violationCount", len(findings))
	if err := n.Send(ctx, notif); err != nil {
		log.Error(err, "Failed to send notifications")
	} else {
		log.Info("Successfully sent notifications", "channels", len(notifierConfigs))
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *SecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.SecurityPolicy{}).
		Named("securitypolicy").
		Complete(r)
}
