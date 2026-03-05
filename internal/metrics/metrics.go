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

// Package metrics exposes custom Prometheus metrics for the Zelyo Operator.
// These metrics follow the conventions established by kube-state-metrics and
// the Kubernetes Instrumentation SIG.
//
// All metrics use the "zelyo_operator_" prefix and are registered automatically
// when the package is imported.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// ── Reconcile Metrics ──

	// ReconcileTotal counts the total number of reconcile operations per controller.
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "controller",
			Name:      "reconcile_total",
			Help:      "Total number of reconcile operations by controller and result.",
		},
		[]string{"controller", "result"}, // result: success, error, requeue
	)

	// ReconcileDuration tracks the duration of reconcile operations.
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "zelyo_operator",
			Subsystem: "controller",
			Name:      "reconcile_duration_seconds",
			Help:      "Duration of reconcile operations in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"controller"},
	)

	// ── Scanner Metrics ──

	// ScanFindingsTotal counts findings produced by scanners, by severity.
	ScanFindingsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "scanner",
			Name:      "findings_total",
			Help:      "Total number of security findings by scanner and severity.",
		},
		[]string{"scanner", "severity"},
	)

	// ScanDuration tracks the duration of scan operations.
	ScanDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "zelyo_operator",
			Subsystem: "scanner",
			Name:      "scan_duration_seconds",
			Help:      "Duration of scan operations in seconds.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"scanner"},
	)

	// ResourcesScannedTotal counts total resources scanned.
	ResourcesScannedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "scanner",
			Name:      "resources_scanned_total",
			Help:      "Total number of resources scanned by scanner type.",
		},
		[]string{"scanner"},
	)

	// ── Policy Metrics ──

	// PolicyViolationsGauge tracks the current number of violations per policy.
	PolicyViolationsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "policy",
			Name:      "violations",
			Help:      "Current number of violations per security policy.",
		},
		[]string{"policy", "namespace", "severity"},
	)

	// PolicyPhaseGauge tracks the current phase of each policy.
	PolicyPhaseGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "policy",
			Name:      "phase_info",
			Help:      "Current phase of each policy (1 = active).",
		},
		[]string{"policy", "namespace", "phase"},
	)

	// ── ClusterScan Metrics ──

	// ClusterScanCompletedTotal counts completed scans.
	ClusterScanCompletedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "clusterscan",
			Name:      "completed_total",
			Help:      "Total number of completed cluster scans.",
		},
		[]string{"scan", "namespace"},
	)

	// ClusterScanFindingsGauge tracks the latest findings count per scan.
	ClusterScanFindingsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "clusterscan",
			Name:      "findings",
			Help:      "Number of findings from the last cluster scan run.",
		},
		[]string{"scan", "namespace"},
	)

	// ── Cost Metrics ──

	// CostRightsizingGauge tracks the number of rightsizing recommendations.
	CostRightsizingGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "cost",
			Name:      "rightsizing_recommendations",
			Help:      "Number of pending rightsizing recommendations.",
		},
		[]string{"policy", "namespace"},
	)

	// ── GitOps Metrics ──

	// GitOpsSyncStatusGauge tracks the sync status of GitOps repositories.
	GitOpsSyncStatusGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "gitops",
			Name:      "sync_status",
			Help:      "Sync status of GitOps repositories (1 = synced, 0 = not synced).",
		},
		[]string{"repository", "namespace", "source_type", "controller_type"},
	)

	// GitOpsDiscoveredAppsGauge tracks the number of discovered applications.
	GitOpsDiscoveredAppsGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "gitops",
			Name:      "discovered_applications",
			Help:      "Number of applications discovered by the GitOps controller adapter.",
		},
		[]string{"repository", "namespace", "controller_type"},
	)

	// ── Brain Package Metrics ──

	// AnomalyDetectedTotal counts anomalies detected by the anomaly engine.
	AnomalyDetectedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "anomaly",
			Name:      "detected_total",
			Help:      "Total anomalies detected by metric key and severity.",
		},
		[]string{"metric_key", "severity"},
	)

	// CorrelatorIncidentsTotal counts incidents created by the correlator.
	CorrelatorIncidentsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "correlator",
			Name:      "incidents_total",
			Help:      "Total incidents created by the correlator engine.",
		},
		[]string{"severity"},
	)

	// CorrelatorOpenIncidents tracks the current number of open incidents.
	CorrelatorOpenIncidents = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "correlator",
			Name:      "open_incidents",
			Help:      "Current number of open (unresolved) incidents.",
		},
	)

	// RemediationPRsTotal counts pull requests created by the remediation engine.
	RemediationPRsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "remediation",
			Name:      "prs_created_total",
			Help:      "Total pull requests created by the remediation engine.",
		},
		[]string{"strategy"}, // dry-run, auto-fix
	)

	// RemediationRiskScore tracks the risk score of the latest remediation plan.
	RemediationRiskScore = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "remediation",
			Name:      "risk_score",
			Help:      "Risk score (0-100) of the last remediation plan.",
		},
		[]string{"namespace"},
	)

	// DriftDetectedTotal counts drift results detected by the drift engine.
	DriftDetectedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "drift",
			Name:      "detected_total",
			Help:      "Total drifts detected by resource kind and type.",
		},
		[]string{"kind", "drift_type"}, // drift_type: added, modified, deleted
	)

	// CompliancePctGauge tracks the compliance percentage per framework.
	CompliancePctGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "zelyo_operator",
			Subsystem: "compliance",
			Name:      "posture_pct",
			Help:      "Compliance posture percentage by framework.",
		},
		[]string{"framework"},
	)

	// NotifierDeliveredTotal counts notifications delivered by the notifier.
	NotifierDeliveredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "zelyo_operator",
			Subsystem: "notifier",
			Name:      "delivered_total",
			Help:      "Total notifications delivered by channel type and severity.",
		},
		[]string{"channel_type", "severity"},
	)
)

func init() { //nolint:gochecknoinits // standard practice for prometheus
	// Register all custom metrics with the controller-runtime metrics registry.
	metrics.Registry.MustRegister(
		ReconcileTotal,
		ReconcileDuration,
		ScanFindingsTotal,
		ScanDuration,
		ResourcesScannedTotal,
		PolicyViolationsGauge,
		PolicyPhaseGauge,
		ClusterScanCompletedTotal,
		ClusterScanFindingsGauge,
		CostRightsizingGauge,
		GitOpsSyncStatusGauge,
		GitOpsDiscoveredAppsGauge,
		// Brain package metrics.
		AnomalyDetectedTotal,
		CorrelatorIncidentsTotal,
		CorrelatorOpenIncidents,
		RemediationPRsTotal,
		RemediationRiskScore,
		DriftDetectedTotal,
		CompliancePctGauge,
		NotifierDeliveredTotal,
	)
}
