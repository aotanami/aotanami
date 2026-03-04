/*
Copyright 2026 Zelyo AI.
*/

// Package compliance provides compliance framework evaluation for Kubernetes
// clusters. It maps security findings to controls from CIS Benchmarks, NIST
// 800-53, SOC 2, and PCI-DSS, generating audit-ready compliance reports.
package compliance

import (
	"time"
)

// Framework identifies a compliance standard.
type Framework string

// Enumeration values.
const (
	FrameworkCISK8s   Framework = "CIS-Kubernetes"
	FrameworkNIST     Framework = "NIST-800-53"
	FrameworkSOC2     Framework = "SOC-2"
	FrameworkPCIDSS   Framework = "PCI-DSS"
	FrameworkHIPAA    Framework = "HIPAA"
	FrameworkISO27001 Framework = "ISO-27001"
)

// ControlStatus indicates the compliance state of a control.
type ControlStatus string

// Enumeration values.
const (
	ControlPassed     ControlStatus = "passed"
	ControlFailed     ControlStatus = "failed"
	ControlException  ControlStatus = "exception"
	ControlNotChecked ControlStatus = "not_checked"
)

// Control represents a single compliance control.
type Control struct {
	// ID is the control identifier (e.g., "5.2.1" for CIS).
	ID string `json:"id"`

	// Framework is the compliance standard.
	Framework Framework `json:"framework"`

	// Title is the control title.
	Title string `json:"title"`

	// Description is the detailed control description.
	Description string `json:"description"`

	// Severity is the importance level.
	Severity string `json:"severity"`

	// Status is the current compliance state.
	Status ControlStatus `json:"status"`

	// Evidence collects proof of compliance or non-compliance.
	Evidence []Evidence `json:"evidence,omitempty"`

	// RelatedRuleTypes maps to Aotanami scanner rule types.
	RelatedRuleTypes []string `json:"related_rule_types,omitempty"`

	// RemediationGuidance is prescriptive fix guidance.
	RemediationGuidance string `json:"remediation_guidance,omitempty"`
}

// Evidence is proof of compliance or non-compliance.
type Evidence struct {
	// Type describes the evidence kind.
	Type string `json:"type"`

	// Description is what this evidence shows.
	Description string `json:"description"`

	// ResourceRef points to the Kubernetes resource.
	ResourceRef string `json:"resource_ref,omitempty"`

	// Timestamp is when the evidence was collected.
	Timestamp time.Time `json:"timestamp"`

	// Data is the raw evidence (e.g., YAML snippet, scan result).
	Data string `json:"data,omitempty"`
}

// Report is a compliance assessment report.
type Report struct {
	// Framework is the compliance standard evaluated.
	Framework Framework `json:"framework"`

	// GeneratedAt is when the report was created.
	GeneratedAt time.Time `json:"generated_at"`

	// ClusterName is the evaluated cluster.
	ClusterName string `json:"cluster_name"`

	// Controls are all evaluated controls.
	Controls []Control `json:"controls"`

	// Summary aggregates pass/fail counts.
	Summary ReportSummary `json:"summary"`
}

// ReportSummary provides aggregate compliance stats.
type ReportSummary struct {
	TotalControls int     `json:"total_controls"`
	Passed        int     `json:"passed"`
	Failed        int     `json:"failed"`
	Exceptions    int     `json:"exceptions"`
	NotChecked    int     `json:"not_checked"`
	CompliancePct float64 `json:"compliance_pct"`
}

// CISKubernetesBenchmark returns the CIS Kubernetes Benchmark v1.8 controls
// mapped to Aotanami scanner rule types.
func CISKubernetesBenchmark() []Control {
	return []Control{
		{
			ID: "5.2.1", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of privileged containers",
			Severity:         "critical",
			RelatedRuleTypes: []string{"container-security-context", "pod-security"},
		},
		{
			ID: "5.2.2", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of containers wishing to share the host process ID namespace",
			Severity:         "critical",
			RelatedRuleTypes: []string{"pod-security"},
		},
		{
			ID: "5.2.3", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of containers wishing to share the host IPC namespace",
			Severity:         "high",
			RelatedRuleTypes: []string{"pod-security"},
		},
		{
			ID: "5.2.4", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of containers wishing to share the host network namespace",
			Severity:         "critical",
			RelatedRuleTypes: []string{"pod-security", "network-policy"},
		},
		{
			ID: "5.2.5", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of containers with allowPrivilegeEscalation",
			Severity:         "high",
			RelatedRuleTypes: []string{"privilege-escalation", "container-security-context"},
		},
		{
			ID: "5.2.6", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of root containers",
			Severity:         "critical",
			RelatedRuleTypes: []string{"privilege-escalation", "container-security-context"},
		},
		{
			ID: "5.2.7", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of containers with the NET_RAW capability",
			Severity:         "high",
			RelatedRuleTypes: []string{"pod-security"},
		},
		{
			ID: "5.2.8", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of containers with added capabilities",
			Severity:         "high",
			RelatedRuleTypes: []string{"pod-security"},
		},
		{
			ID: "5.2.9", Framework: FrameworkCISK8s,
			Title:            "Minimize the admission of containers with capabilities assigned",
			Severity:         "medium",
			RelatedRuleTypes: []string{"pod-security"},
		},
		{
			ID: "5.4.1", Framework: FrameworkCISK8s,
			Title:            "Prefer using secrets as files over secrets as environment variables",
			Severity:         "medium",
			RelatedRuleTypes: []string{"secrets-exposure"},
		},
		{
			ID: "5.4.2", Framework: FrameworkCISK8s,
			Title:            "Consider external secret storage",
			Severity:         "medium",
			RelatedRuleTypes: []string{"secrets-exposure"},
		},
		{
			ID: "5.7.1", Framework: FrameworkCISK8s,
			Title:            "Create administrative boundaries between resources using namespaces",
			Severity:         "medium",
			RelatedRuleTypes: []string{"rbac-audit"},
		},
		{
			ID: "5.7.2", Framework: FrameworkCISK8s,
			Title:            "Ensure that the seccomp profile is set to docker/default in pod definitions",
			Severity:         "medium",
			RelatedRuleTypes: []string{"container-security-context"},
		},
		{
			ID: "5.7.3", Framework: FrameworkCISK8s,
			Title:            "Apply Security Context to pods and containers",
			Severity:         "high",
			RelatedRuleTypes: []string{"container-security-context"},
		},
		{
			ID: "5.7.4", Framework: FrameworkCISK8s,
			Title:            "The default namespace should not be used",
			Severity:         "medium",
			RelatedRuleTypes: []string{"rbac-audit"},
		},
	}
}

// CalculateSummary computes aggregate compliance statistics from controls.
func CalculateSummary(controls []Control) ReportSummary {
	s := ReportSummary{TotalControls: len(controls)}
	for i := range controls {
		c := controls[i]
		switch c.Status {
		case ControlPassed:
			s.Passed++
		case ControlFailed:
			s.Failed++
		case ControlException:
			s.Exceptions++
		case ControlNotChecked:
			s.NotChecked++
		}
	}
	if s.TotalControls > 0 {
		s.CompliancePct = float64(s.Passed) / float64(s.TotalControls) * 100
	}
	return s
}
