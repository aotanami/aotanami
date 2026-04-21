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

	"github.com/robfig/cron/v3"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/compliance"
	"github.com/zelyo-ai/zelyo-operator/internal/conditions"
	"github.com/zelyo-ai/zelyo-operator/internal/events"
	zelyometrics "github.com/zelyo-ai/zelyo-operator/internal/metrics"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

const (
	// clusterScanFinalizer is the finalizer for cleaning up child ScanReports.
	clusterScanFinalizer = "zelyo.ai/clusterscan-cleanup"

	// defaultScanInterval is the default requeue interval for scans without a schedule.
	defaultScanInterval = 30 * time.Minute
)

// ClusterScanReconciler reconciles a ClusterScan object.
// It runs security and compliance scans, creates ScanReport child resources
// to store results, and manages scan history cleanup.
type ClusterScanReconciler struct {
	client.Client
	Scheme          *runtime.Scheme
	Recorder        record.EventRecorder
	ScannerRegistry *scanner.Registry
}

// +kubebuilder:rbac:groups=zelyo.ai,resources=clusterscans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=clusterscans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=clusterscans/finalizers,verbs=update
// +kubebuilder:rbac:groups=zelyo.ai,resources=scanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// scanResult holds aggregated output from running all scanners.
type scanResult struct {
	findings   []zelyov1alpha1.Finding
	summary    zelyov1alpha1.ScanSummary
	scanErrors []string
}

// Reconcile runs the scan lifecycle for a ClusterScan resource.
func (r *ClusterScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// Fetch the ClusterScan.
	scan := &zelyov1alpha1.ClusterScan{}
	if err := r.Get(ctx, req.NamespacedName, scan); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching ClusterScan: %w", err)
	}

	log.Info("Reconciling ClusterScan", "name", scan.Name, "namespace", scan.Namespace,
		"generation", scan.Generation, "scanners", scan.Spec.Scanners)

	// ── Handle deletion / finalizer ──
	if !scan.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(scan, clusterScanFinalizer) {
			if err := r.cleanupScanReports(ctx, scan); err != nil {
				return ctrl.Result{}, fmt.Errorf("cleaning up ScanReports: %w", err)
			}
			controllerutil.RemoveFinalizer(scan, clusterScanFinalizer)
			if err := r.Update(ctx, scan); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer is set.
	if !controllerutil.ContainsFinalizer(scan, clusterScanFinalizer) {
		controllerutil.AddFinalizer(scan, clusterScanFinalizer)
		if err := r.Update(ctx, scan); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// ── Check if suspended ──
	if scan.Spec.Suspend {
		log.Info("ClusterScan is suspended — skipping")
		conditions.MarkFalse(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
			"Suspended", "Scan is suspended", scan.Generation)
		scan.Status.Phase = zelyov1alpha1.PhasePending
		if err := r.Status().Update(ctx, scan); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
		}
		return ctrl.Result{RequeueAfter: scanRequeueInterval(scan)}, nil
	}

	// ── Run the scan ──
	r.Recorder.Event(scan, corev1.EventTypeNormal, zelyov1alpha1.EventReasonScanStarted,
		fmt.Sprintf("Starting cluster scan with %d scanners", len(scan.Spec.Scanners)))
	events.EmitScanStarted(scan.Name, scan.Namespace, scan.Spec.Scanners)
	scanStartedAt := time.Now()

	scan.Status.Phase = zelyov1alpha1.PhaseRunning
	conditions.MarkUnknown(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonProgressingMessage, "Scan in progress", scan.Generation)
	if err := r.Status().Update(ctx, scan); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status to Running: %w", err)
	}

	// Resolve target pods.
	pods, err := r.resolveTargetPods(ctx, scan)
	if err != nil {
		return r.handleTargetResolutionError(ctx, scan, err)
	}

	// Execute scanners, evaluate compliance, create report.
	sr := r.executeScan(ctx, scan, pods)
	complianceResults := r.evaluateCompliance(ctx, scan, sr.findings)
	reportName, err := r.createScanReport(ctx, scan, sr.findings, &sr.summary, complianceResults)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("creating scan report: %w", err)
	}

	if err := r.enforceHistoryLimit(ctx, scan); err != nil {
		log.Error(err, "Failed to enforce history limit")
	}

	events.EmitScanCompleted(&events.ScanCompletion{
		Name:       scan.Name,
		Namespace:  scan.Namespace,
		ReportName: reportName,
		Total:      sr.summary.TotalFindings,
		Critical:   sr.summary.Critical,
		High:       sr.summary.High,
		Medium:     sr.summary.Medium,
		Low:        sr.summary.Low,
		Info:       sr.summary.Info,
		DurationMs: time.Since(scanStartedAt).Milliseconds(),
		HasErrors:  len(sr.scanErrors) > 0,
	})

	return r.updateFinalStatus(ctx, scan, sr, reportName)
}

// handleTargetResolutionError records a failure event and updates status when targets cannot be resolved.
func (r *ClusterScanReconciler) handleTargetResolutionError(ctx context.Context, scan *zelyov1alpha1.ClusterScan, err error) (ctrl.Result, error) {
	r.Recorder.Event(scan, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
		fmt.Sprintf("Failed to resolve target pods: %v", err))
	scan.Status.Phase = zelyov1alpha1.PhaseFailed
	conditions.MarkFalse(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileFailed, fmt.Sprintf("Target resolution failed: %v", err), scan.Generation)
	if statusErr := r.Status().Update(ctx, scan); statusErr != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
	}
	return ctrl.Result{RequeueAfter: scanRequeueInterval(scan)}, nil
}

// updateFinalStatus writes the scan result into the ClusterScan status and records metrics.
func (r *ClusterScanReconciler) updateFinalStatus(ctx context.Context, scan *zelyov1alpha1.ClusterScan, sr *scanResult, reportName string) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	now := metav1.Now()
	scan.Status.LastScheduleTime = &now
	scan.Status.CompletedAt = &now
	scan.Status.FindingsCount = sr.summary.TotalFindings
	scan.Status.LastReportName = reportName

	conditions.MarkTrue(&scan.Status.Conditions, zelyov1alpha1.ConditionScanCompleted,
		zelyov1alpha1.ReasonScanSuccess,
		fmt.Sprintf("Scan completed: %d findings across %d resources", sr.summary.TotalFindings, sr.summary.ResourcesScanned),
		scan.Generation)

	if len(sr.scanErrors) > 0 {
		conditions.MarkFalse(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileFailed,
			fmt.Sprintf("Scans completed with %d error(s): %s", len(sr.scanErrors), strings.Join(sr.scanErrors, "; ")),
			scan.Generation)
		scan.Status.Phase = zelyov1alpha1.PhaseDegraded
	} else {
		conditions.MarkTrue(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileSuccess, "Scan completed successfully", scan.Generation)
		scan.Status.Phase = zelyov1alpha1.PhaseCompleted
	}

	if err := r.Status().Update(ctx, scan); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", err)
	}

	r.Recorder.Event(scan, corev1.EventTypeNormal, zelyov1alpha1.EventReasonScanCompleted,
		fmt.Sprintf("Scan completed: %d findings (C:%d H:%d M:%d L:%d I:%d) — report: %s",
			sr.summary.TotalFindings, sr.summary.Critical, sr.summary.High, sr.summary.Medium, sr.summary.Low, sr.summary.Info, reportName))

	log.Info("ClusterScan completed",
		"findings", sr.summary.TotalFindings, "report", reportName, "resourcesScanned", sr.summary.ResourcesScanned)

	zelyometrics.ClusterScanCompletedTotal.WithLabelValues(scan.Name, scan.Namespace).Inc()
	zelyometrics.ClusterScanFindingsGauge.WithLabelValues(scan.Name, scan.Namespace).Set(float64(sr.summary.TotalFindings))
	zelyometrics.ResourcesScannedTotal.WithLabelValues("clusterscan").Add(float64(sr.summary.ResourcesScanned))
	zelyometrics.ReconcileTotal.WithLabelValues("clusterscan", "success").Inc()

	return ctrl.Result{RequeueAfter: scanRequeueInterval(scan)}, nil
}

// executeScan runs all requested scanners against the target pods and returns
// aggregated findings, a summary, and any scanner errors.
func (r *ClusterScanReconciler) executeScan(ctx context.Context, scan *zelyov1alpha1.ClusterScan, pods []corev1.Pod) *scanResult {
	log := logf.FromContext(ctx)

	sr := &scanResult{}
	sr.summary.ResourcesScanned = int32(len(pods)) //nolint:gosec // Pod count is bounded

	for _, scannerName := range scan.Spec.Scanners {
		s := r.ScannerRegistry.Get(scannerName)
		if s == nil {
			log.Info("No scanner registered — skipping", "scanner", scannerName)
			continue
		}

		results, scanErr := s.Scan(ctx, pods, nil)
		if scanErr != nil {
			log.Error(scanErr, "Scanner failed", "scanner", s.Name())
			r.Recorder.Event(scan, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
				fmt.Sprintf("Scanner %q failed: %v", s.Name(), scanErr))
			sr.scanErrors = append(sr.scanErrors, fmt.Sprintf("%s: %v", s.Name(), scanErr))
			continue
		}

		for i := range results {
			f := &results[i]
			finding := zelyov1alpha1.Finding{
				ID:          fmt.Sprintf("%s-%s-%s-%s", f.RuleType, f.ResourceNamespace, f.ResourceName, truncateRunes(f.Title, 20)),
				Severity:    f.Severity,
				Category:    f.RuleType,
				Title:       f.Title,
				Description: f.Description,
				Resource: zelyov1alpha1.AffectedResource{
					Kind:      f.ResourceKind,
					Namespace: f.ResourceNamespace,
					Name:      f.ResourceName,
				},
				Recommendation: f.Recommendation,
			}
			sr.findings = append(sr.findings, finding)

			// Update summary counts.
			switch f.Severity {
			case zelyov1alpha1.SeverityCritical:
				sr.summary.Critical++
			case zelyov1alpha1.SeverityHigh:
				sr.summary.High++
			case zelyov1alpha1.SeverityMedium:
				sr.summary.Medium++
			case zelyov1alpha1.SeverityLow:
				sr.summary.Low++
			case zelyov1alpha1.SeverityInfo:
				sr.summary.Info++
			}

			// Surface high-signal findings to the live pipeline feed.
			if f.Severity == zelyov1alpha1.SeverityCritical || f.Severity == zelyov1alpha1.SeverityHigh {
				events.EmitFindingDetected(
					scan.Name,
					f.RuleType,
					f.Severity,
					fmt.Sprintf("%s/%s/%s", f.ResourceKind, f.ResourceNamespace, f.ResourceName),
					f.Title,
				)
			}
		}
	}

	sr.summary.TotalFindings = int32(len(sr.findings)) //nolint:gosec // Findings count is bounded
	return sr
}

// evaluateCompliance converts findings to compliance format, evaluates them
// against each configured framework, records events, and returns the results.
func (r *ClusterScanReconciler) evaluateCompliance(ctx context.Context, scan *zelyov1alpha1.ClusterScan, findings []zelyov1alpha1.Finding) []zelyov1alpha1.ComplianceResult {
	log := logf.FromContext(ctx)

	complianceFindings := make([]compliance.Finding, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		complianceFindings = append(complianceFindings, compliance.Finding{
			RuleType:          f.Category,
			Severity:          f.Severity,
			Title:             f.Title,
			ResourceKind:      f.Resource.Kind,
			ResourceNamespace: f.Resource.Namespace,
			ResourceName:      f.Resource.Name,
		})
	}

	compReport := compliance.EvaluateFindings(compliance.FrameworkCISK8s, complianceFindings)
	log.Info("Compliance evaluation complete",
		"framework", compReport.Framework,
		"passed", compReport.Summary.Passed,
		"failed", compReport.Summary.Failed,
		"compliancePct", fmt.Sprintf("%.1f%%", compReport.Summary.CompliancePct))

	if compReport.Summary.Failed > 0 {
		r.Recorder.Event(scan, corev1.EventTypeWarning, "ComplianceViolation",
			fmt.Sprintf("CIS Kubernetes Benchmark: %.1f%% compliant (%d/%d controls passed, %d failed)",
				compReport.Summary.CompliancePct,
				compReport.Summary.Passed,
				compReport.Summary.TotalControls,
				compReport.Summary.Failed))
	}

	zelyometrics.CompliancePctGauge.WithLabelValues(string(compReport.Framework)).Set(compReport.Summary.CompliancePct)

	return []zelyov1alpha1.ComplianceResult{
		{
			Framework:      string(compReport.Framework),
			PassRate:       int32(compReport.Summary.CompliancePct),
			TotalControls:  int32(compReport.Summary.TotalControls), //nolint:gosec // Control count is bounded
			FailedControls: int32(compReport.Summary.Failed),        //nolint:gosec // Failed count is bounded
		},
	}
}

// createScanReport builds a ScanReport CR, sets the owner reference, creates
// it in the cluster, updates its status, and returns the report name.
func (r *ClusterScanReconciler) createScanReport(ctx context.Context, scan *zelyov1alpha1.ClusterScan, findings []zelyov1alpha1.Finding, summary *zelyov1alpha1.ScanSummary, complianceResults []zelyov1alpha1.ComplianceResult) (string, error) {
	log := logf.FromContext(ctx)

	// Use GenerateName (not Name) so the API server appends a 5-char random
	// suffix: this guarantees the result never exceeds the DNS-1123 label
	// limit of 63 chars regardless of scan.Name length, and stays unique
	// even when two scans complete in the same second (the unix-timestamp
	// approach previously collided under parallel execution).
	report := &zelyov1alpha1.ScanReport{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: scanReportBasename(scan.Name),
			Namespace:    scan.Namespace,
			Labels: map[string]string{
				"zelyo.ai/scan": scan.Name,
			},
		},
		Spec: zelyov1alpha1.ScanReportSpec{
			ScanRef:    scan.Name,
			Findings:   findings,
			Summary:    *summary,
			Compliance: complianceResults,
		},
	}

	// Set owner reference so reports are GC'd with the scan.
	if err := controllerutil.SetControllerReference(scan, report, r.Scheme); err != nil {
		return "", fmt.Errorf("setting owner reference on ScanReport: %w", err)
	}

	if err := r.Create(ctx, report); err != nil {
		return "", fmt.Errorf("creating ScanReport: %w", err)
	}

	// Mark the report as complete.
	report.Status.Phase = zelyov1alpha1.PhaseComplete
	conditions.MarkTrue(&report.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess, "Report is complete", report.Generation)
	if err := r.Status().Update(ctx, report); err != nil {
		log.Error(err, "Failed to update ScanReport status")
	}

	return report.Name, nil
}

// scanReportBasename returns a GenerateName prefix that leaves at least
// 6 chars for the API server's random suffix while respecting the 63-char
// DNS-1123 label limit. ScanReports use the scan name as a prefix so
// human operators can still correlate reports to their scan in `kubectl
// get scanreports`.
func scanReportBasename(scanName string) string {
	const maxPrefix = 56 // 63 - 5 suffix - 1 dash - 1 safety = plenty.
	base := scanName
	if len(base) > maxPrefix {
		base = base[:maxPrefix]
	}
	return base + "-"
}

// resolveTargetPods lists running pods matching the scan's scope.
func (r *ClusterScanReconciler) resolveTargetPods(ctx context.Context, scan *zelyov1alpha1.ClusterScan) ([]corev1.Pod, error) {
	var targetNamespaces []string

	if len(scan.Spec.Scope.Namespaces) > 0 {
		targetNamespaces = scan.Spec.Scope.Namespaces
	} else {
		nsList := &corev1.NamespaceList{}
		if err := r.List(ctx, nsList); err != nil {
			return nil, fmt.Errorf("listing namespaces: %w", err)
		}
		excludeSet := make(map[string]bool, len(scan.Spec.Scope.ExcludeNamespaces))
		for _, ns := range scan.Spec.Scope.ExcludeNamespaces {
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

	var allPods []corev1.Pod
	for _, ns := range targetNamespaces {
		podList := &corev1.PodList{}
		if err := r.List(ctx, podList, client.InNamespace(ns)); err != nil {
			return nil, fmt.Errorf("listing pods in namespace %q: %w", ns, err)
		}
		for i := range podList.Items {
			if podList.Items[i].Status.Phase == corev1.PodRunning {
				allPods = append(allPods, podList.Items[i])
			}
		}
	}

	return allPods, nil
}

// cleanupScanReports removes all ScanReport resources owned by this ClusterScan.
func (r *ClusterScanReconciler) cleanupScanReports(ctx context.Context, scan *zelyov1alpha1.ClusterScan) error {
	log := logf.FromContext(ctx)

	reportList := &zelyov1alpha1.ScanReportList{}
	if err := r.List(ctx, reportList,
		client.InNamespace(scan.Namespace),
		client.MatchingLabels{"zelyo.ai/scan": scan.Name}); err != nil {
		return fmt.Errorf("listing ScanReports: %w", err)
	}

	for i := range reportList.Items {
		if err := r.Delete(ctx, &reportList.Items[i]); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting ScanReport %q: %w", reportList.Items[i].Name, err)
		}
		log.Info("Deleted ScanReport", "name", reportList.Items[i].Name)
	}

	return nil
}

// enforceHistoryLimit removes old ScanReports exceeding the history limit.
func (r *ClusterScanReconciler) enforceHistoryLimit(ctx context.Context, scan *zelyov1alpha1.ClusterScan) error {
	log := logf.FromContext(ctx)

	historyLimit := scan.Spec.HistoryLimit
	if historyLimit <= 0 {
		historyLimit = 10
	}

	reportList := &zelyov1alpha1.ScanReportList{}
	if err := r.List(ctx, reportList,
		client.InNamespace(scan.Namespace),
		client.MatchingLabels{"zelyo.ai/scan": scan.Name}); err != nil {
		return fmt.Errorf("listing ScanReports: %w", err)
	}

	//nolint:gosec // list length is bounded
	if int32(len(reportList.Items)) <= historyLimit {
		return nil
	}

	// Sort by creation time (oldest first).
	sort.Slice(reportList.Items, func(i, j int) bool {
		return reportList.Items[i].CreationTimestamp.Before(&reportList.Items[j].CreationTimestamp)
	})

	// Delete oldest reports exceeding the limit.
	//nolint:gosec // list length is bounded
	toDelete := int32(len(reportList.Items)) - historyLimit
	for i := int32(0); i < toDelete; i++ {
		if err := r.Delete(ctx, &reportList.Items[i]); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting old ScanReport %q: %w", reportList.Items[i].Name, err)
		}
		log.Info("Pruned old ScanReport", "name", reportList.Items[i].Name)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
//
// GenerationChangedPredicate is critical: the Reconcile loop writes the
// ClusterScan status on every run (Phase=Running, Phase=Complete,
// LastScheduleTime), which otherwise retriggers Reconcile immediately in
// a tight loop — the scanner runs again → status writes again → Reconcile
// again. With the predicate the controller only re-runs on spec changes,
// owned-resource events, and the explicit RequeueAfter interval.
func (r *ClusterScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.ClusterScan{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&zelyov1alpha1.ScanReport{}).
		Named("clusterscan").
		Complete(r)
}

// scanRequeueInterval returns the next-tick interval derived from the
// scan's schedule. Uses robfig/cron/v3's standard parser so any valid
// 5-field cron expression works ("*/10 * * * *", "0 * * * *",
// "0 0 * * *", "30 2 * * 1-5", ...). We compute the interval from now
// to the parser's next-trigger, clamp to [1m, 24h] to stop misconfig
// from collapsing into a scan-per-second hot-loop (the
// GenerationChangedPredicate also guards this), and fall back to
// defaultScanInterval if the expression is empty or doesn't parse.
// Unparseable expressions are logged at the caller's discretion.
func scanRequeueInterval(scan *zelyov1alpha1.ClusterScan) time.Duration {
	if scan == nil {
		return defaultScanInterval
	}
	sch := strings.TrimSpace(scan.Spec.Schedule)
	if sch == "" {
		return defaultScanInterval
	}
	expr, err := cron.ParseStandard(sch)
	if err != nil {
		return defaultScanInterval
	}
	now := time.Now()
	next := expr.Next(now)
	interval := next.Sub(now)
	if interval < time.Minute {
		interval = time.Minute
	}
	if interval > 24*time.Hour {
		interval = 24 * time.Hour
	}
	return interval
}

// truncateRunes returns s truncated to at most maxRunes runes. Slicing a
// string by byte index (s[:n]) chops mid-codepoint on multi-byte UTF-8
// input, producing invalid sequences in downstream Finding IDs.
func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes])
}
