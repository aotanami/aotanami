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

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo/api/v1alpha1"
	"github.com/zelyo-ai/zelyo/internal/compliance"
	"github.com/zelyo-ai/zelyo/internal/conditions"
	aotmetrics "github.com/zelyo-ai/zelyo/internal/metrics"
	"github.com/zelyo-ai/zelyo/internal/scanner"
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
	if result, done, err := r.handleFinalizer(ctx, scan); done {
		return result, err
	}

	// ── Check if suspended ──
	if result, done, err := r.handleSuspend(ctx, scan); done {
		return result, err
	}

	// ── Run the scan ──
	return r.executeScan(ctx, scan, log)
}

// handleFinalizer manages the deletion lifecycle and finalizer.
// Returns (result, true, err) if the reconcile should stop, or (_, false, nil) to continue.
func (r *ClusterScanReconciler) handleFinalizer(ctx context.Context, scan *zelyov1alpha1.ClusterScan) (ctrl.Result, bool, error) {
	if !scan.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(scan, clusterScanFinalizer) {
			if err := r.cleanupScanReports(ctx, scan); err != nil {
				return ctrl.Result{}, true, fmt.Errorf("cleaning up ScanReports: %w", err)
			}
			controllerutil.RemoveFinalizer(scan, clusterScanFinalizer)
			if err := r.Update(ctx, scan); err != nil {
				return ctrl.Result{}, true, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, true, nil
	}

	// Ensure finalizer is set.
	if !controllerutil.ContainsFinalizer(scan, clusterScanFinalizer) {
		controllerutil.AddFinalizer(scan, clusterScanFinalizer)
		if err := r.Update(ctx, scan); err != nil {
			return ctrl.Result{}, true, fmt.Errorf("adding finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, true, nil
	}

	return ctrl.Result{}, false, nil
}

// handleSuspend checks if the scan is suspended and updates status accordingly.
func (r *ClusterScanReconciler) handleSuspend(ctx context.Context, scan *zelyov1alpha1.ClusterScan) (ctrl.Result, bool, error) {
	if !scan.Spec.Suspend {
		return ctrl.Result{}, false, nil
	}

	logf.FromContext(ctx).Info("ClusterScan is suspended — skipping")
	conditions.MarkFalse(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
		"Suspended", "Scan is suspended", scan.Generation)
	scan.Status.Phase = zelyov1alpha1.PhasePending
	if err := r.Status().Update(ctx, scan); err != nil {
		return ctrl.Result{}, true, fmt.Errorf("updating status: %w", err)
	}
	return ctrl.Result{RequeueAfter: defaultScanInterval}, true, nil
}

// executeScan performs the actual scanning, compliance evaluation, and report creation.
func (r *ClusterScanReconciler) executeScan(ctx context.Context, scan *zelyov1alpha1.ClusterScan, log logr.Logger) (ctrl.Result, error) {
	r.Recorder.Event(scan, corev1.EventTypeNormal, zelyov1alpha1.EventReasonScanStarted,
		fmt.Sprintf("Starting cluster scan with %d scanners", len(scan.Spec.Scanners)))

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

	// Run scanners and collect results.
	allFindings, summary, scanErrors := r.runScanners(ctx, scan, pods, log)

	// Evaluate compliance.
	r.evaluateCompliance(ctx, scan, allFindings, log)

	// Create ScanReport.
	reportName, err := r.createScanReport(ctx, scan, allFindings, summary)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Enforce history limit.
	if err := r.enforceHistoryLimit(ctx, scan); err != nil {
		log.Error(err, "Failed to enforce history limit")
	}

	// Update final status.
	r.updateFinalStatus(ctx, scan, summary, reportName, scanErrors, log)

	return ctrl.Result{RequeueAfter: defaultScanInterval}, nil
}

// handleTargetResolutionError marks the scan as failed when pod resolution fails.
func (r *ClusterScanReconciler) handleTargetResolutionError(ctx context.Context, scan *zelyov1alpha1.ClusterScan, err error) (ctrl.Result, error) {
	r.Recorder.Event(scan, corev1.EventTypeWarning, zelyov1alpha1.EventReasonReconcileError,
		fmt.Sprintf("Failed to resolve target pods: %v", err))
	scan.Status.Phase = zelyov1alpha1.PhaseFailed
	conditions.MarkFalse(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileFailed, fmt.Sprintf("Target resolution failed: %v", err), scan.Generation)
	if statusErr := r.Status().Update(ctx, scan); statusErr != nil {
		return ctrl.Result{}, fmt.Errorf("updating status: %w", statusErr)
	}
	return ctrl.Result{RequeueAfter: defaultScanInterval}, nil
}

// runScanners executes each registered scanner and aggregates findings.
func (r *ClusterScanReconciler) runScanners(ctx context.Context, scan *zelyov1alpha1.ClusterScan, pods []corev1.Pod, log logr.Logger) ([]zelyov1alpha1.Finding, zelyov1alpha1.ScanSummary, []string) {
	var allFindings []zelyov1alpha1.Finding
	var scanErrors []string
	var summary zelyov1alpha1.ScanSummary
	summary.ResourcesScanned = int32(len(pods)) //nolint:gosec // Pod count is bounded

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
			scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", s.Name(), scanErr))
			continue
		}

		for i := range results {
			f := &results[i]
			finding := zelyov1alpha1.Finding{
				ID:          fmt.Sprintf("%s-%s-%s-%s", f.RuleType, f.ResourceNamespace, f.ResourceName, f.Title[:min(len(f.Title), 20)]),
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
			allFindings = append(allFindings, finding)
			incrementSeverityCount(&summary, f.Severity)
		}
	}

	summary.TotalFindings = int32(len(allFindings)) //nolint:gosec // Findings count is bounded
	return allFindings, summary, scanErrors
}

// incrementSeverityCount updates the summary severity counter for a finding.
func incrementSeverityCount(summary *zelyov1alpha1.ScanSummary, severity string) {
	switch severity {
	case zelyov1alpha1.SeverityCritical:
		summary.Critical++
	case zelyov1alpha1.SeverityHigh:
		summary.High++
	case zelyov1alpha1.SeverityMedium:
		summary.Medium++
	case zelyov1alpha1.SeverityLow:
		summary.Low++
	case zelyov1alpha1.SeverityInfo:
		summary.Info++
	}
}

// evaluateCompliance runs CIS Kubernetes Benchmark evaluation on the findings.
func (r *ClusterScanReconciler) evaluateCompliance(ctx context.Context, scan *zelyov1alpha1.ClusterScan, allFindings []zelyov1alpha1.Finding, log logr.Logger) {
	var complianceFindings []compliance.Finding
	for i := range allFindings {
		f := &allFindings[i]
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

	aotmetrics.CompliancePctGauge.WithLabelValues(string(compReport.Framework)).Set(compReport.Summary.CompliancePct)
}

// createScanReport creates a ScanReport child resource with the scan results.
func (r *ClusterScanReconciler) createScanReport(ctx context.Context, scan *zelyov1alpha1.ClusterScan, allFindings []zelyov1alpha1.Finding, summary zelyov1alpha1.ScanSummary) (string, error) {
	log := logf.FromContext(ctx)

	reportName := fmt.Sprintf("%s-%d", scan.Name, time.Now().Unix())
	report := &zelyov1alpha1.ScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      reportName,
			Namespace: scan.Namespace,
			Labels: map[string]string{
				"zelyo.ai/scan": scan.Name,
			},
		},
		Spec: zelyov1alpha1.ScanReportSpec{
			ScanRef:  scan.Name,
			Findings: allFindings,
			Summary:  summary,
		},
	}

	if err := controllerutil.SetControllerReference(scan, report, r.Scheme); err != nil {
		return "", fmt.Errorf("setting owner reference on ScanReport: %w", err)
	}

	if err := r.Create(ctx, report); err != nil {
		return "", fmt.Errorf("creating ScanReport: %w", err)
	}

	report.Status.Phase = zelyov1alpha1.PhaseComplete
	conditions.MarkTrue(&report.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess, "Report is complete", report.Generation)
	if err := r.Status().Update(ctx, report); err != nil {
		log.Error(err, "Failed to update ScanReport status")
	}

	return reportName, nil
}

// updateFinalStatus sets the final status, records events, and emits metrics.
func (r *ClusterScanReconciler) updateFinalStatus(ctx context.Context, scan *zelyov1alpha1.ClusterScan, summary zelyov1alpha1.ScanSummary, reportName string, scanErrors []string, log logr.Logger) {
	now := metav1.Now()
	scan.Status.LastScheduleTime = &now
	scan.Status.CompletedAt = &now
	scan.Status.FindingsCount = summary.TotalFindings
	scan.Status.LastReportName = reportName

	conditions.MarkTrue(&scan.Status.Conditions, zelyov1alpha1.ConditionScanCompleted,
		zelyov1alpha1.ReasonScanSuccess,
		fmt.Sprintf("Scan completed: %d findings across %d resources", summary.TotalFindings, summary.ResourcesScanned),
		scan.Generation)

	if len(scanErrors) > 0 {
		conditions.MarkFalse(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileFailed,
			fmt.Sprintf("Scans completed with %d error(s): %s", len(scanErrors), strings.Join(scanErrors, "; ")),
			scan.Generation)
		scan.Status.Phase = zelyov1alpha1.PhaseDegraded
	} else {
		conditions.MarkTrue(&scan.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileSuccess, "Scan completed successfully", scan.Generation)
		scan.Status.Phase = zelyov1alpha1.PhaseCompleted
	}

	if err := r.Status().Update(ctx, scan); err != nil {
		log.Error(err, "Failed to update ClusterScan status")
	}

	r.Recorder.Event(scan, corev1.EventTypeNormal, zelyov1alpha1.EventReasonScanCompleted,
		fmt.Sprintf("Scan completed: %d findings (C:%d H:%d M:%d L:%d I:%d) — report: %s",
			summary.TotalFindings, summary.Critical, summary.High, summary.Medium, summary.Low, summary.Info, reportName))

	log.Info("ClusterScan completed",
		"findings", summary.TotalFindings,
		"report", reportName,
		"resourcesScanned", summary.ResourcesScanned)

	// Record metrics.
	aotmetrics.ClusterScanCompletedTotal.WithLabelValues(scan.Name, scan.Namespace).Inc()
	aotmetrics.ClusterScanFindingsGauge.WithLabelValues(scan.Name, scan.Namespace).Set(float64(summary.TotalFindings))
	aotmetrics.ResourcesScannedTotal.WithLabelValues("clusterscan").Add(float64(summary.ResourcesScanned))
	aotmetrics.ReconcileTotal.WithLabelValues("clusterscan", "success").Inc()
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
func (r *ClusterScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.ClusterScan{}).
		Owns(&zelyov1alpha1.ScanReport{}).
		Named("clusterscan").
		Complete(r)
}

// Ensure the ClusterScanReconciler uses the NamespacedName for singleton lookups.
var _ = types.NamespacedName{}
