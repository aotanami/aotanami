/*
Copyright 2026 Zelyo AI
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

	// RelatedRuleTypes maps to Zelyo Operator scanner rule types.
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
// mapped to Zelyo Operator scanner rule types.
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

// SOC2Controls returns SOC 2 Trust Services Criteria controls
// mapped to cloud security scanner rule types.
func SOC2Controls() []Control {
	return []Control{
		{ID: "CC6.1", Framework: FrameworkSOC2, Title: "Logical and Physical Access Controls",
			Severity: "high", RelatedRuleTypes: []string{
				"ciem-overprivileged-iam", "ciem-mfa-not-enforced", "ciem-root-access-keys",
				"ciem-unused-access-keys", "ciem-inactive-users",
			}},
		{ID: "CC6.2", Framework: FrameworkSOC2, Title: "Credentials and Authentication Mechanisms",
			Severity: "high", RelatedRuleTypes: []string{
				"ciem-mfa-not-enforced", "ciem-long-lived-service-keys", "ciem-root-access-keys",
			}},
		{ID: "CC6.3", Framework: FrameworkSOC2, Title: "Role-Based Access and Least Privilege",
			Severity: "high", RelatedRuleTypes: []string{
				"ciem-overprivileged-iam", "ciem-wildcard-permissions", "ciem-cross-account-trust",
				"cicd-overprivileged-codebuild",
			}},
		{ID: "CC6.6", Framework: FrameworkSOC2, Title: "Security Over External Threats",
			Severity: "critical", RelatedRuleTypes: []string{
				"network-ssh-open", "network-rdp-open", "network-db-ports-exposed",
				"network-default-sg-traffic", "network-unrestricted-egress",
			}},
		{ID: "CC6.7", Framework: FrameworkSOC2, Title: "Data Protection in Transit and at Rest",
			Severity: "high", RelatedRuleTypes: []string{
				"cspm-unencrypted-ebs", "cspm-rds-encryption", "dspm-s3-no-encryption",
				"dspm-dynamodb-encryption", "dspm-cloudwatch-unencrypted",
				"network-alb-not-https", "cicd-unencrypted-artifacts",
			}},
		{ID: "CC7.1", Framework: FrameworkSOC2, Title: "Detection of Changes and Anomalies",
			Severity: "medium", RelatedRuleTypes: []string{
				"cspm-cloudtrail-disabled", "cspm-vpc-flow-logs", "cicd-no-audit-logging",
			}},
		{ID: "CC7.2", Framework: FrameworkSOC2, Title: "Monitoring for Anomalous Activity",
			Severity: "medium", RelatedRuleTypes: []string{
				"cspm-cloudtrail-disabled", "cspm-vpc-flow-logs",
			}},
		{ID: "CC8.1", Framework: FrameworkSOC2, Title: "Change Management Controls",
			Severity: "medium", RelatedRuleTypes: []string{
				"cicd-no-manual-approval", "cspm-s3-versioning",
			}},
		{ID: "CC6.8", Framework: FrameworkSOC2, Title: "Prevention of Unauthorized Data Access",
			Severity: "critical", RelatedRuleTypes: []string{
				"cspm-public-s3-bucket", "dspm-s3-public-acls", "dspm-rds-public",
				"dspm-ebs-snapshots-public",
			}},
		{ID: "CC7.4", Framework: FrameworkSOC2, Title: "Security Incident Response",
			Severity: "medium", RelatedRuleTypes: []string{
				"cspm-cloudtrail-disabled",
			}},
	}
}

// PCIDSSControls returns PCI-DSS v4.0 controls mapped to cloud scanner rule types.
func PCIDSSControls() []Control {
	return []Control{
		{ID: "1.3.1", Framework: FrameworkPCIDSS, Title: "Restrict Inbound Traffic to CDE",
			Severity: "critical", RelatedRuleTypes: []string{
				"network-ssh-open", "network-rdp-open", "network-db-ports-exposed",
				"network-default-sg-traffic",
			}},
		{ID: "1.3.2", Framework: FrameworkPCIDSS, Title: "Restrict Outbound Traffic from CDE",
			Severity: "high", RelatedRuleTypes: []string{
				"network-unrestricted-egress",
			}},
		{ID: "2.2.7", Framework: FrameworkPCIDSS, Title: "Encrypt Non-Console Administrative Access",
			Severity: "high", RelatedRuleTypes: []string{
				"network-alb-not-https",
			}},
		{ID: "3.4.1", Framework: FrameworkPCIDSS, Title: "Render PAN Unreadable with Cryptography",
			Severity: "critical", RelatedRuleTypes: []string{
				"cspm-unencrypted-ebs", "cspm-rds-encryption", "dspm-s3-no-encryption",
				"dspm-dynamodb-encryption",
			}},
		{ID: "3.5.1", Framework: FrameworkPCIDSS, Title: "Protect Cryptographic Keys",
			Severity: "high", RelatedRuleTypes: []string{
				"cspm-kms-rotation", "cspm-secrets-rotation",
			}},
		{ID: "6.3.1", Framework: FrameworkPCIDSS, Title: "Identify Security Vulnerabilities",
			Severity: "high", RelatedRuleTypes: []string{
				"supplychain-ecr-critical-cves", "supplychain-third-party-cves",
				"supplychain-images-not-scanned",
			}},
		{ID: "7.2.1", Framework: FrameworkPCIDSS, Title: "Restrict Access Based on Need-to-Know",
			Severity: "high", RelatedRuleTypes: []string{
				"ciem-overprivileged-iam", "ciem-wildcard-permissions",
			}},
		{ID: "8.3.1", Framework: FrameworkPCIDSS, Title: "Enforce MFA for Administrative Access",
			Severity: "critical", RelatedRuleTypes: []string{
				"ciem-mfa-not-enforced", "ciem-root-access-keys",
			}},
		{ID: "10.2.1", Framework: FrameworkPCIDSS, Title: "Audit Logging for All System Components",
			Severity: "high", RelatedRuleTypes: []string{
				"cspm-cloudtrail-disabled", "cspm-vpc-flow-logs", "cicd-no-audit-logging",
			}},
		{ID: "6.5.4", Framework: FrameworkPCIDSS, Title: "Protect Secrets in Source Code",
			Severity: "critical", RelatedRuleTypes: []string{
				"cicd-hardcoded-secrets-repo", "cicd-secrets-plaintext-env",
				"supplychain-hardcoded-secrets-env",
			}},
	}
}

// HIPAAControls returns HIPAA Security Rule controls mapped to cloud scanner rule types.
func HIPAAControls() []Control {
	return []Control{
		{ID: "164.312(a)(1)", Framework: FrameworkHIPAA, Title: "Access Control — Unique User ID",
			Severity: "high", RelatedRuleTypes: []string{
				"ciem-overprivileged-iam", "ciem-mfa-not-enforced", "ciem-inactive-users",
			}},
		{ID: "164.312(a)(2)(i)", Framework: FrameworkHIPAA, Title: "Unique User Identification",
			Severity: "high", RelatedRuleTypes: []string{
				"ciem-root-access-keys", "ciem-long-lived-service-keys",
			}},
		{ID: "164.312(a)(2)(iii)", Framework: FrameworkHIPAA, Title: "Automatic Logoff",
			Severity: "medium", RelatedRuleTypes: []string{
				"ciem-unused-access-keys", "ciem-inactive-users",
			}},
		{ID: "164.312(a)(2)(iv)", Framework: FrameworkHIPAA, Title: "Encryption and Decryption",
			Severity: "critical", RelatedRuleTypes: []string{
				"cspm-unencrypted-ebs", "cspm-rds-encryption", "dspm-s3-no-encryption",
				"dspm-dynamodb-encryption", "dspm-cloudwatch-unencrypted",
			}},
		{ID: "164.312(b)", Framework: FrameworkHIPAA, Title: "Audit Controls",
			Severity: "high", RelatedRuleTypes: []string{
				"cspm-cloudtrail-disabled", "cspm-vpc-flow-logs", "cicd-no-audit-logging",
			}},
		{ID: "164.312(c)(1)", Framework: FrameworkHIPAA, Title: "Integrity — ePHI Protection",
			Severity: "critical", RelatedRuleTypes: []string{
				"cspm-public-s3-bucket", "dspm-s3-public-acls", "dspm-rds-public",
				"dspm-ebs-snapshots-public", "cspm-s3-versioning", "dspm-s3-object-lock",
			}},
		{ID: "164.312(d)", Framework: FrameworkHIPAA, Title: "Person or Entity Authentication",
			Severity: "critical", RelatedRuleTypes: []string{
				"ciem-mfa-not-enforced", "ciem-root-access-keys",
			}},
		{ID: "164.312(e)(1)", Framework: FrameworkHIPAA, Title: "Transmission Security",
			Severity: "high", RelatedRuleTypes: []string{
				"network-alb-not-https", "network-ssh-open", "network-rdp-open",
			}},
		{ID: "164.308(a)(3)", Framework: FrameworkHIPAA, Title: "Workforce Security",
			Severity: "high", RelatedRuleTypes: []string{
				"ciem-wildcard-permissions", "ciem-cross-account-trust",
				"cicd-overprivileged-codebuild",
			}},
		{ID: "164.308(a)(4)", Framework: FrameworkHIPAA, Title: "Information Access Management",
			Severity: "high", RelatedRuleTypes: []string{
				"ciem-overprivileged-iam", "dspm-no-data-tags",
			}},
	}
}

// Finding represents a scan finding for compliance evaluation.
// This mirrors the scanner.Finding fields without importing the scanner package.
type Finding struct {
	RuleType          string
	Severity          string
	Title             string
	ResourceKind      string
	ResourceNamespace string
	ResourceName      string
}

// EvaluateFindings maps scan findings to compliance controls and returns
// a compliance report. Controls whose RelatedRuleTypes match any finding's
// RuleType are marked as Failed; others are marked Passed.
func EvaluateFindings(framework Framework, findings []Finding) *Report {
	var controls []Control

	switch framework {
	case FrameworkCISK8s:
		controls = CISKubernetesBenchmark()
	case FrameworkSOC2:
		controls = SOC2Controls()
	case FrameworkPCIDSS:
		controls = PCIDSSControls()
	case FrameworkHIPAA:
		controls = HIPAAControls()
	default:
		controls = CISKubernetesBenchmark()
	}

	// Build a set of violated rule types.
	violatedRules := make(map[string][]Finding)
	for _, f := range findings {
		violatedRules[f.RuleType] = append(violatedRules[f.RuleType], f)
	}

	// Evaluate each control.
	now := time.Now()
	for i := range controls {
		c := &controls[i]
		var failed bool
		for _, ruleType := range c.RelatedRuleTypes {
			if matchedFindings, ok := violatedRules[ruleType]; ok {
				failed = true
				// Attach evidence from the findings.
				for _, f := range matchedFindings {
					c.Evidence = append(c.Evidence, Evidence{
						Type:        "scan-finding",
						Description: f.Title,
						ResourceRef: f.ResourceKind + "/" + f.ResourceNamespace + "/" + f.ResourceName,
						Timestamp:   now,
					})
				}
			}
		}

		if failed {
			c.Status = ControlFailed
		} else {
			c.Status = ControlPassed
		}
	}

	report := &Report{
		Framework:   framework,
		GeneratedAt: now,
		Controls:    controls,
		Summary:     CalculateSummary(controls),
	}

	return report
}
