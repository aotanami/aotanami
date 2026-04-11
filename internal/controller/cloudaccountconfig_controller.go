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
	"time"

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

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/cloudscanner"
	awsclients "github.com/zelyo-ai/zelyo-operator/internal/cloudscanner/aws"
	"github.com/zelyo-ai/zelyo-operator/internal/compliance"
	"github.com/zelyo-ai/zelyo-operator/internal/conditions"
	zelyometrics "github.com/zelyo-ai/zelyo-operator/internal/metrics"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

const (
	cloudAccountFinalizer    = "zelyo.ai/cloudaccountconfig-cleanup"
	defaultCloudScanInterval = 30 * time.Minute
)

// CloudAccountConfigReconciler reconciles a CloudAccountConfig object.
// It authenticates to cloud providers, runs cloud security scanners,
// creates ScanReport child resources, and evaluates compliance frameworks.
type CloudAccountConfigReconciler struct {
	client.Client
	Scheme               *runtime.Scheme
	Recorder             record.EventRecorder
	CloudScannerRegistry *cloudscanner.Registry
}

// +kubebuilder:rbac:groups=zelyo.ai,resources=cloudaccountconfigs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=zelyo.ai,resources=cloudaccountconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=zelyo.ai,resources=cloudaccountconfigs/finalizers,verbs=update
// +kubebuilder:rbac:groups=zelyo.ai,resources=scanreports,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile runs the cloud scan lifecycle for a CloudAccountConfig resource.
//
//nolint:gocyclo // Controller logic is inherently complex
func (r *CloudAccountConfigReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	start := time.Now()
	defer func() {
		zelyometrics.ReconcileDuration.WithLabelValues("cloudaccountconfig").Observe(time.Since(start).Seconds())
	}()

	// ── Fetch the CloudAccountConfig ──
	account := &zelyov1alpha1.CloudAccountConfig{}
	if err := r.Get(ctx, req.NamespacedName, account); err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching CloudAccountConfig: %w", err)
	}

	// ── Handle deletion / finalizer ──
	if !account.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(account, cloudAccountFinalizer) {
			if err := r.cleanupScanReports(ctx, account); err != nil {
				return ctrl.Result{}, fmt.Errorf("cleaning up ScanReports: %w", err)
			}
			controllerutil.RemoveFinalizer(account, cloudAccountFinalizer)
			if err := r.Update(ctx, account); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(account, cloudAccountFinalizer) {
		controllerutil.AddFinalizer(account, cloudAccountFinalizer)
		if err := r.Update(ctx, account); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// ── Mark reconciling ──
	conditions.MarkReconciling(&account.Status.Conditions, "Starting cloud scan", account.Generation)
	if err := r.Status().Update(ctx, account); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating reconciling status: %w", err)
	}

	// ── Check if suspended ──
	if account.Spec.Suspend {
		log.Info("CloudAccountConfig is suspended, skipping scan")
		account.Status.Phase = zelyov1alpha1.PhaseActive
		conditions.MarkTrue(&account.Status.Conditions, zelyov1alpha1.ConditionReady,
			zelyov1alpha1.ReasonReconcileSuccess, "Suspended — no scan executed", account.Generation)
		if err := r.Status().Update(ctx, account); err != nil {
			return ctrl.Result{}, fmt.Errorf("updating suspended status: %w", err)
		}
		return ctrl.Result{RequeueAfter: defaultCloudScanInterval}, nil
	}

	// ── Validate and build cloud credentials ──
	credConfig, err := r.buildCredentialConfig(ctx, account)
	if err != nil {
		log.Error(err, "Failed to build cloud credentials")
		r.Recorder.Event(account, corev1.EventTypeWarning, zelyov1alpha1.EventReasonCloudAuthError, err.Error())
		account.Status.Phase = zelyov1alpha1.PhaseDegraded
		conditions.MarkFalse(&account.Status.Conditions, zelyov1alpha1.ConditionCloudConnected,
			zelyov1alpha1.ReasonCloudAuthFailed, err.Error(), account.Generation)
		if statusErr := r.Status().Update(ctx, account); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("updating auth error status: %w", statusErr)
		}
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	// Verify identity with the default region before scanning.
	defaultClients, err := awsclients.NewClients(ctx, credConfig)
	if err != nil {
		log.Error(err, "Failed to create AWS clients")
		account.Status.Phase = zelyov1alpha1.PhaseDegraded
		conditions.MarkFalse(&account.Status.Conditions, zelyov1alpha1.ConditionCloudConnected,
			zelyov1alpha1.ReasonCloudAuthFailed, err.Error(), account.Generation)
		if statusErr := r.Status().Update(ctx, account); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("updating auth error status: %w", statusErr)
		}
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}

	verifiedAccount, arn, err := defaultClients.VerifyIdentity(ctx)
	if err != nil {
		log.Error(err, "Failed to verify AWS identity")
		account.Status.Phase = zelyov1alpha1.PhaseDegraded
		conditions.MarkFalse(&account.Status.Conditions, zelyov1alpha1.ConditionCloudConnected,
			zelyov1alpha1.ReasonCloudAuthFailed, err.Error(), account.Generation)
		if statusErr := r.Status().Update(ctx, account); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("updating auth error status: %w", statusErr)
		}
		return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
	}
	log.Info("AWS identity verified", "account", verifiedAccount, "arn", arn)

	// Mark cloud connected.
	conditions.MarkTrue(&account.Status.Conditions, zelyov1alpha1.ConditionCloudConnected,
		zelyov1alpha1.ReasonCloudAuthSuccess, "Cloud provider authenticated", account.Generation)

	// ── Run cloud scans ──
	r.Recorder.Event(account, corev1.EventTypeNormal, zelyov1alpha1.EventReasonCloudScanStarted,
		fmt.Sprintf("Starting cloud scan for %s account %s", account.Spec.Provider, account.Spec.AccountID))

	now := metav1.Now()
	account.Status.LastScanTime = &now
	account.Status.Phase = zelyov1alpha1.PhaseRunning
	if err := r.Status().Update(ctx, account); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating running status: %w", err)
	}

	allFindings, summary, scannedRegions := r.runCloudScans(ctx, account, credConfig)

	// ── Evaluate compliance ──
	var complianceResults []zelyov1alpha1.ComplianceResult
	for _, fw := range account.Spec.ComplianceFrameworks {
		framework := mapComplianceFramework(fw)
		compFindings := toComplianceFindings(allFindings)
		report := compliance.EvaluateFindings(framework, compFindings)
		complianceResults = append(complianceResults, zelyov1alpha1.ComplianceResult{
			Framework:      string(report.Framework),
			PassRate:       int32(report.Summary.CompliancePct),
			TotalControls:  int32(report.Summary.TotalControls), //nolint:gosec // G115: small control count, no overflow risk
			FailedControls: int32(report.Summary.Failed),        //nolint:gosec // G115: small failure count, no overflow risk
		})
		zelyometrics.CompliancePctGauge.WithLabelValues(string(report.Framework)).Set(report.Summary.CompliancePct)
	}

	// ── Create ScanReport ──
	reportFindings := toReportFindings(allFindings)
	report := &zelyov1alpha1.ScanReport{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", account.Name),
			Namespace:    account.Namespace,
			Labels: map[string]string{
				"zelyo.ai/scan":      account.Name,
				"zelyo.ai/scan-type": "cloud",
				"zelyo.ai/provider":  account.Spec.Provider,
			},
		},
		Spec: zelyov1alpha1.ScanReportSpec{
			ScanRef:    account.Name,
			Findings:   reportFindings,
			Summary:    summary,
			Compliance: complianceResults,
		},
	}

	if err := controllerutil.SetControllerReference(account, report, r.Scheme); err != nil {
		return ctrl.Result{}, fmt.Errorf("setting owner reference on ScanReport: %w", err)
	}
	if err := r.Create(ctx, report); err != nil {
		return ctrl.Result{}, fmt.Errorf("creating ScanReport: %w", err)
	}

	// Mark report complete.
	report.Status.Phase = zelyov1alpha1.PhaseComplete
	if err := r.Status().Update(ctx, report); err != nil {
		log.Error(err, "Failed to update ScanReport status")
	}

	// ── Enforce history limit ──
	if err := r.enforceHistoryLimit(ctx, account); err != nil {
		log.Error(err, "Failed to enforce history limit")
	}

	// ── Update status ──
	completedAt := metav1.Now()
	account.Status.Phase = zelyov1alpha1.PhaseCompleted
	account.Status.CompletedAt = &completedAt
	account.Status.FindingsCount = summary.TotalFindings
	account.Status.FindingsSummary = zelyov1alpha1.FindingsSummary{
		Critical: summary.Critical,
		High:     summary.High,
		Medium:   summary.Medium,
		Low:      summary.Low,
		Info:     summary.Info,
	}
	account.Status.LastReportName = report.Name
	account.Status.ScannedRegions = scannedRegions
	account.Status.ResourcesScanned = summary.ResourcesScanned
	account.Status.ObservedGeneration = account.Generation

	conditions.MarkTrue(&account.Status.Conditions, zelyov1alpha1.ConditionCloudScanCompleted,
		zelyov1alpha1.ReasonCloudScanSuccess,
		fmt.Sprintf("Scan completed: %d findings across %d resources", summary.TotalFindings, summary.ResourcesScanned),
		account.Generation)
	conditions.MarkTrue(&account.Status.Conditions, zelyov1alpha1.ConditionReady,
		zelyov1alpha1.ReasonReconcileSuccess, "Cloud account scan completed", account.Generation)

	if err := r.Status().Update(ctx, account); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating completed status: %w", err)
	}

	// ── Record metrics ──
	zelyometrics.CloudScanCompletedTotal.WithLabelValues(
		account.Spec.AccountID, account.Spec.Provider, account.Namespace).Inc()
	zelyometrics.ReconcileTotal.WithLabelValues("cloudaccountconfig", "success").Inc()

	r.Recorder.Event(account, corev1.EventTypeNormal, zelyov1alpha1.EventReasonCloudScanCompleted,
		fmt.Sprintf("Cloud scan completed: %d findings", summary.TotalFindings))

	log.Info("Cloud scan completed",
		"account", account.Spec.AccountID,
		"findings", summary.TotalFindings,
		"regions", len(scannedRegions))

	return ctrl.Result{RequeueAfter: defaultCloudScanInterval}, nil
}

// buildCredentialConfig prepares the AWS credential configuration from the CloudAccountConfig spec.
// It resolves secrets but does not create clients — callers create per-region clients as needed.
func (r *CloudAccountConfigReconciler) buildCredentialConfig(ctx context.Context, account *zelyov1alpha1.CloudAccountConfig) (*awsclients.CredentialConfig, error) {
	creds := account.Spec.Credentials

	cc := &awsclients.CredentialConfig{
		Method:  awsclients.CredentialMethod(creds.Method),
		RoleARN: creds.RoleARN,
	}

	// For secret-based credentials, load the secret.
	if creds.Method == "secret" {
		if creds.SecretRef == "" {
			return nil, fmt.Errorf("secretRef is required when credential method is 'secret'")
		}

		secret := &corev1.Secret{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      creds.SecretRef,
			Namespace: account.Namespace,
		}, secret); err != nil {
			return nil, fmt.Errorf("fetching credential secret %q: %w", creds.SecretRef, err)
		}

		accessKey, ok := secret.Data["aws-access-key-id"]
		if !ok {
			return nil, fmt.Errorf("secret %q missing key 'aws-access-key-id'", creds.SecretRef)
		}
		secretKey, ok := secret.Data["aws-secret-access-key"]
		if !ok {
			return nil, fmt.Errorf("secret %q missing key 'aws-secret-access-key'", creds.SecretRef)
		}

		cc.AccessKeyID = string(accessKey)
		cc.SecretAccessKey = string(secretKey)
	}

	if creds.ExternalID != "" {
		cc.ExternalID = creds.ExternalID
	}

	// Use the first configured region, or default to us-east-1.
	region := "us-east-1"
	if len(account.Spec.Regions) > 0 {
		region = account.Spec.Regions[0]
	}
	cc.Region = region

	return cc, nil
}

// runCloudScans executes all configured cloud scanners.
// Regional scanners get per-region AWS clients; global scanners use the default region.
// Individual scanner errors are logged and skipped; the function always succeeds.
func (r *CloudAccountConfigReconciler) runCloudScans(
	ctx context.Context,
	account *zelyov1alpha1.CloudAccountConfig,
	credConfig *awsclients.CredentialConfig,
) ([]scanner.Finding, zelyov1alpha1.ScanSummary, []string) {
	log := logf.FromContext(ctx)

	// Determine which categories to scan.
	categories := account.Spec.ScanCategories
	if len(categories) == 0 {
		categories = []string{"cspm", "ciem", "network", "dspm", "supply-chain", "cicd-pipeline"}
	}

	// Determine regions to scan.
	regions := account.Spec.Regions
	if len(regions) == 0 {
		regions = []string{"us-east-1"} // Default region.
	}

	var allFindings []scanner.Finding
	var totalChecks int32
	scannedGlobal := make(map[string]bool) // Track global scanners already run.

	// Create clients for the default region (used for global scanners).
	defaultClients, err := awsclients.NewClients(ctx, credConfig)
	if err != nil {
		log.Error(err, "Failed to create default-region AWS clients")
		return nil, zelyov1alpha1.ScanSummary{}, regions
	}

	// Pre-create per-region clients.
	regionClients := make(map[string]*awsclients.Clients)
	for _, region := range regions {
		rc, err := awsclients.NewClientsForRegion(ctx, credConfig, region)
		if err != nil {
			log.Error(err, "Failed to create AWS clients for region, skipping", "region", region)
			continue
		}
		regionClients[region] = rc
	}

	for _, category := range categories {
		scanners := r.CloudScannerRegistry.GetByCategoryAndProvider(category, account.Spec.Provider)
		if len(scanners) == 0 {
			log.V(1).Info("No scanners for category/provider", "category", category, "provider", account.Spec.Provider)
			continue
		}

		scanStart := time.Now()

		for _, s := range scanners {
			findings, checks := runSingleScanner(ctx, s, account, regions, defaultClients, regionClients, scannedGlobal)
			allFindings = append(allFindings, findings...)
			totalChecks += checks
		}

		zelyometrics.CloudScanDuration.WithLabelValues(account.Spec.Provider, category).
			Observe(time.Since(scanStart).Seconds())
	}

	// Build summary.
	summary := buildFindingsSummary(allFindings, totalChecks)

	// Record per-category finding metrics.
	categoryFindings := make(map[string]int)
	for i := range allFindings {
		cat := categoryFromRuleType(allFindings[i].RuleType)
		categoryFindings[cat]++
	}
	for cat, count := range categoryFindings {
		zelyometrics.CloudScanFindingsGauge.WithLabelValues(
			account.Spec.AccountID, account.Spec.Provider, cat).Set(float64(count))
	}

	// Sort findings by severity (critical first).
	sort.Slice(allFindings, func(i, j int) bool {
		return severityOrder[allFindings[i].Severity] < severityOrder[allFindings[j].Severity]
	})

	return allFindings, summary, regions
}

// runSingleScanner executes one scanner across regions (or once for global scanners).
func runSingleScanner(
	ctx context.Context,
	s cloudscanner.CloudScanner,
	account *zelyov1alpha1.CloudAccountConfig,
	regions []string,
	defaultClients *awsclients.Clients,
	regionClients map[string]*awsclients.Clients,
	scannedGlobal map[string]bool,
) (findings []scanner.Finding, checks int32) {
	log := logf.FromContext(ctx)

	if s.IsGlobal() {
		if scannedGlobal[s.RuleType()] {
			return nil, 0
		}
		scannedGlobal[s.RuleType()] = true

		cc := &cloudscanner.CloudContext{
			Provider:   account.Spec.Provider,
			AccountID:  account.Spec.AccountID,
			AWSClients: defaultClients,
		}
		result, err := s.Scan(ctx, cc)
		if err != nil {
			log.Error(err, "Cloud scanner failed", "scanner", s.Name(), "ruleType", s.RuleType())
			return nil, 0
		}
		return result, 1
	}

	for _, region := range regions {
		rc, ok := regionClients[region]
		if !ok {
			continue
		}

		cc := &cloudscanner.CloudContext{
			Provider:   account.Spec.Provider,
			AccountID:  account.Spec.AccountID,
			Region:     region,
			AWSClients: rc,
		}
		result, err := s.Scan(ctx, cc)
		if err != nil {
			log.Error(err, "Cloud scanner failed",
				"scanner", s.Name(), "ruleType", s.RuleType(), "region", region)
			continue
		}
		findings = append(findings, result...)
		checks++
	}

	return findings, checks
}

// buildFindingsSummary aggregates finding counts by severity.
func buildFindingsSummary(findings []scanner.Finding, checksPerformed int32) zelyov1alpha1.ScanSummary {
	summary := zelyov1alpha1.ScanSummary{
		TotalFindings:    int32(len(findings)), //nolint:gosec // G115: finding count fits in int32
		ResourcesScanned: checksPerformed,
	}
	for i := range findings {
		switch findings[i].Severity {
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
	return summary
}

// toReportFindings converts scanner.Finding to CRD Finding format.
func toReportFindings(findings []scanner.Finding) []zelyov1alpha1.Finding {
	result := make([]zelyov1alpha1.Finding, 0, len(findings))
	for i := range findings {
		id := fmt.Sprintf("%s-%s-%s", findings[i].RuleType, findings[i].ResourceNamespace, findings[i].ResourceName)
		if len(id) > 63 {
			id = id[:63]
		}
		result = append(result, zelyov1alpha1.Finding{
			ID:          id,
			Severity:    findings[i].Severity,
			Category:    findings[i].RuleType,
			Title:       findings[i].Title,
			Description: findings[i].Description,
			Resource: zelyov1alpha1.AffectedResource{
				Kind:      findings[i].ResourceKind,
				Namespace: findings[i].ResourceNamespace,
				Name:      findings[i].ResourceName,
			},
			Recommendation: findings[i].Recommendation,
		})
	}
	return result
}

// toComplianceFindings converts scanner.Finding to compliance.Finding.
func toComplianceFindings(findings []scanner.Finding) []compliance.Finding {
	result := make([]compliance.Finding, 0, len(findings))
	for i := range findings {
		result = append(result, compliance.Finding{
			RuleType:          findings[i].RuleType,
			Severity:          findings[i].Severity,
			Title:             findings[i].Title,
			ResourceKind:      findings[i].ResourceKind,
			ResourceNamespace: findings[i].ResourceNamespace,
			ResourceName:      findings[i].ResourceName,
		})
	}
	return result
}

// mapComplianceFramework maps spec string to compliance.Framework.
func mapComplianceFramework(fw string) compliance.Framework {
	switch fw {
	case "soc2":
		return compliance.FrameworkSOC2
	case "pci-dss":
		return compliance.FrameworkPCIDSS
	case "hipaa":
		return compliance.FrameworkHIPAA
	case "cis-aws":
		return compliance.FrameworkCISK8s // Reuse for now, extend later.
	case "nist-800-53":
		return compliance.FrameworkNIST
	case "iso-27001":
		return compliance.FrameworkISO27001
	default:
		return compliance.FrameworkSOC2
	}
}

// categoryFromRuleType extracts the category prefix from a rule type string.
func categoryFromRuleType(ruleType string) string {
	prefixes := []string{"cspm-", "ciem-", "network-", "dspm-", "supplychain-", "cicd-"}
	for _, p := range prefixes {
		if len(ruleType) > len(p) && ruleType[:len(p)] == p {
			return p[:len(p)-1] // Remove trailing dash.
		}
	}
	return "unknown"
}

// cleanupScanReports deletes all ScanReports owned by this CloudAccountConfig.
func (r *CloudAccountConfigReconciler) cleanupScanReports(ctx context.Context, account *zelyov1alpha1.CloudAccountConfig) error {
	reports := &zelyov1alpha1.ScanReportList{}
	if err := r.List(ctx, reports,
		client.InNamespace(account.Namespace),
		client.MatchingLabels{"zelyo.ai/scan": account.Name, "zelyo.ai/scan-type": "cloud"},
	); err != nil {
		return fmt.Errorf("listing ScanReports: %w", err)
	}

	for i := range reports.Items {
		if err := r.Delete(ctx, &reports.Items[i]); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting ScanReport %s: %w", reports.Items[i].Name, err)
		}
	}
	return nil
}

// enforceHistoryLimit keeps only the most recent N ScanReports.
func (r *CloudAccountConfigReconciler) enforceHistoryLimit(ctx context.Context, account *zelyov1alpha1.CloudAccountConfig) error {
	limit := int(account.Spec.HistoryLimit)
	if limit <= 0 {
		limit = 10
	}

	reports := &zelyov1alpha1.ScanReportList{}
	if err := r.List(ctx, reports,
		client.InNamespace(account.Namespace),
		client.MatchingLabels{"zelyo.ai/scan": account.Name, "zelyo.ai/scan-type": "cloud"},
	); err != nil {
		return fmt.Errorf("listing ScanReports: %w", err)
	}

	if len(reports.Items) <= limit {
		return nil
	}

	// Sort by creation timestamp (oldest first).
	sort.Slice(reports.Items, func(i, j int) bool {
		return reports.Items[i].CreationTimestamp.Before(&reports.Items[j].CreationTimestamp)
	})

	// Delete oldest reports exceeding the limit.
	toDelete := reports.Items[:len(reports.Items)-limit]
	for i := range toDelete {
		if err := r.Delete(ctx, &toDelete[i]); err != nil && !errors.IsNotFound(err) {
			return fmt.Errorf("deleting old ScanReport %s: %w", toDelete[i].Name, err)
		}
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *CloudAccountConfigReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&zelyov1alpha1.CloudAccountConfig{}).
		Owns(&zelyov1alpha1.ScanReport{}).
		Named("cloudaccountconfig").
		Complete(r)
}
