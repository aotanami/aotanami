/*
Copyright 2026 Zelyo AI

demo seed: populates the fake Kubernetes client used by the standalone
dashboard-demo binary with a realistic set of Zelyo CRDs so every page
(Overview, Policies, Scans, Cloud Security, Compliance, Settings) renders
with meaningful content during investor demos.

Everything below is intentionally structured to match the scenarios fired
by the internal/events synthesizer — same scan names, same severities,
same resource types — so the dashboard tells one coherent story.
*/

package main

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
)

// DemoObjects returns the fixture objects used to seed the fake client.
// Pass them to fake.NewClientBuilder().WithObjects(...) so the dashboard
// handlers see a populated cluster from the very first render.
//
//nolint:funlen // fixture data is intentionally verbose; splitting it costs more than it clarifies.
func DemoObjects() []client.Object {
	now := metav1.Now()
	yesterday := metav1.NewTime(now.Add(-24 * 60 * 60 * 1_000_000_000))

	objs := make([]client.Object, 0, 24)
	objs = append(objs, demoSecurityPolicies(&now)...)
	objs = append(objs, demoClusterScans(&now, &yesterday)...)
	objs = append(objs, demoScanReports(&now, &yesterday)...)
	objs = append(objs, demoCloudAccounts(&now)...)
	objs = append(objs, demoNotificationChannels(&now)...)
	objs = append(objs,
		demoZelyoConfig(&now),
		demoGitOpsRepo(&now),
		demoRemediationPolicy(&now),
		demoMonitoringPolicy(&now),
		demoCostPolicy(&now),
	)
	return objs
}

// ---- Security policies ----------------------------------------------------

func demoSecurityPolicies(now *metav1.Time) []client.Object {
	return []client.Object{
		&zelyov1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "block-privileged-containers", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.SecurityPolicySpec{
				Severity:      "critical",
				AutoRemediate: true,
				Schedule:      "*/15 * * * *",
				Match: zelyov1alpha1.PolicyMatch{
					ExcludeNamespaces: []string{"kube-system"},
					ResourceKinds:     []string{"Pod", "Deployment", "DaemonSet", "StatefulSet"},
				},
				Rules: []zelyov1alpha1.SecurityRule{
					{Name: "no-privileged", Type: "container-security-context", Enforce: true},
					{Name: "no-privilege-escalation", Type: "privilege-escalation", Enforce: true},
				},
			},
			Status: zelyov1alpha1.SecurityPolicyStatus{
				Phase:          "Active",
				ViolationCount: 3,
				LastEvaluated:  now,
			},
		},
		&zelyov1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "enforce-nonroot-least-caps", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.SecurityPolicySpec{
				Severity:      "high",
				AutoRemediate: true,
				Schedule:      "*/30 * * * *",
				Match: zelyov1alpha1.PolicyMatch{
					Namespaces: []string{"payments", "platform", "apps"},
				},
				Rules: []zelyov1alpha1.SecurityRule{
					{Name: "run-as-nonroot", Type: "pod-security", Enforce: true},
					{Name: "drop-dangerous-caps", Type: "container-security-context", Enforce: true},
				},
			},
			Status: zelyov1alpha1.SecurityPolicyStatus{
				Phase:          "Active",
				ViolationCount: 5,
				LastEvaluated:  now,
			},
		},
		&zelyov1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default-deny-network-policies", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.SecurityPolicySpec{
				Severity: "high",
				Match: zelyov1alpha1.PolicyMatch{
					ExcludeNamespaces: []string{"kube-system", "zelyo-system"},
				},
				Rules: []zelyov1alpha1.SecurityRule{
					{Name: "require-default-deny", Type: "network-policy", Enforce: true},
				},
			},
			Status: zelyov1alpha1.SecurityPolicyStatus{
				Phase:          "Active",
				ViolationCount: 2,
				LastEvaluated:  now,
			},
		},
		&zelyov1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "scan-image-vulnerabilities", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.SecurityPolicySpec{
				Severity: "medium",
				Match:    zelyov1alpha1.PolicyMatch{},
				Rules: []zelyov1alpha1.SecurityRule{
					{Name: "no-critical-cves", Type: "image-vulnerability", Enforce: false},
				},
			},
			Status: zelyov1alpha1.SecurityPolicyStatus{
				Phase:          "Active",
				ViolationCount: 11,
				LastEvaluated:  now,
			},
		},
		&zelyov1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "detect-secret-exposure", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.SecurityPolicySpec{
				Severity: "critical",
				Match:    zelyov1alpha1.PolicyMatch{},
				Rules: []zelyov1alpha1.SecurityRule{
					{Name: "no-secrets-in-env", Type: "secrets-exposure", Enforce: true},
				},
			},
			Status: zelyov1alpha1.SecurityPolicyStatus{
				Phase:          "Active",
				ViolationCount: 1,
				LastEvaluated:  now,
			},
		},
		&zelyov1alpha1.SecurityPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: "rbac-least-privilege", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.SecurityPolicySpec{
				Severity: "medium",
				Match:    zelyov1alpha1.PolicyMatch{},
				Rules: []zelyov1alpha1.SecurityRule{
					{Name: "no-wildcard-verbs", Type: "rbac-audit", Enforce: false},
				},
			},
			Status: zelyov1alpha1.SecurityPolicyStatus{
				Phase:          "Active",
				ViolationCount: 4,
				LastEvaluated:  now,
			},
		},
	}
}

// ---- ClusterScans ---------------------------------------------------------

func demoClusterScans(now, yesterday *metav1.Time) []client.Object {
	return []client.Object{
		&zelyov1alpha1.ClusterScan{
			ObjectMeta: metav1.ObjectMeta{
				Name: "payments-hourly", Namespace: "payments",
				CreationTimestamp: *yesterday,
			},
			Spec: zelyov1alpha1.ClusterScanSpec{
				Schedule:             "0 * * * *",
				Scanners:             []string{"privileged", "root-user", "capabilities"},
				HistoryLimit:         20,
				ComplianceFrameworks: []string{"cis", "soc2"},
				Scope: zelyov1alpha1.ScanScope{
					Namespaces: []string{"payments"},
				},
			},
			Status: zelyov1alpha1.ClusterScanStatus{
				Phase:            "Completed",
				FindingsCount:    3,
				LastScheduleTime: now,
				CompletedAt:      now,
				LastReportName:   "payments-hourly-report-latest",
			},
		},
		&zelyov1alpha1.ClusterScan{
			ObjectMeta: metav1.ObjectMeta{
				Name: "platform-nightly", Namespace: "platform",
				CreationTimestamp: *yesterday,
			},
			Spec: zelyov1alpha1.ClusterScanSpec{
				Schedule:             "0 2 * * *",
				Scanners:             []string{"host-mounts", "network-policy"},
				HistoryLimit:         14,
				ComplianceFrameworks: []string{"cis", "nist-800-53"},
			},
			Status: zelyov1alpha1.ClusterScanStatus{
				Phase:            "Completed",
				FindingsCount:    2,
				LastScheduleTime: now,
				CompletedAt:      now,
				LastReportName:   "platform-nightly-report-latest",
			},
		},
		&zelyov1alpha1.ClusterScan{
			ObjectMeta: metav1.ObjectMeta{
				Name: "continuous-pod-audit", Namespace: "zelyo-system",
				CreationTimestamp: *yesterday,
			},
			Spec: zelyov1alpha1.ClusterScanSpec{
				Scanners:     []string{"privileged", "root-user", "capabilities", "host-mounts", "secrets-exposure"},
				HistoryLimit: 5,
			},
			Status: zelyov1alpha1.ClusterScanStatus{
				Phase:            "Running",
				FindingsCount:    7,
				LastScheduleTime: now,
			},
		},
	}
}

// ---- ScanReports ----------------------------------------------------------

func demoScanReports(now, yesterday *metav1.Time) []client.Object {
	mkFinding := func(id, sev, cat, title, desc, kind, ns, name string) zelyov1alpha1.Finding {
		return zelyov1alpha1.Finding{
			ID: id, Severity: sev, Category: cat, Title: title, Description: desc,
			Resource: zelyov1alpha1.AffectedResource{Kind: kind, Namespace: ns, Name: name},
		}
	}
	return []client.Object{
		&zelyov1alpha1.ScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "payments-hourly-report-latest", Namespace: "payments",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.ScanReportSpec{
				ScanRef: "payments-hourly",
				Findings: []zelyov1alpha1.Finding{
					mkFinding("privileged-1", "critical", "privileged", "Pod running in privileged mode",
						"This pod has `securityContext.privileged: true` which bypasses container isolation.",
						"Pod", "payments", "checkout-api-7f8d"),
					mkFinding("root-user-1", "high", "root-user", "Container running as UID 0",
						"Container uses root inside its namespace, increasing blast radius of any RCE.",
						"Deployment", "payments", "checkout-api"),
					mkFinding("caps-1", "high", "capabilities", "CAP_SYS_ADMIN granted unnecessarily",
						"CAP_SYS_ADMIN is near-root and enables container escape techniques.",
						"Pod", "payments", "ledger-writer-2bc9"),
				},
				Summary: zelyov1alpha1.ScanSummary{
					TotalFindings: 3, Critical: 1, High: 2, Medium: 0, Low: 0, Info: 0,
					ResourcesScanned: 47,
				},
				Compliance: []zelyov1alpha1.ComplianceResult{
					{Framework: "cis", PassRate: 78, TotalControls: 32, FailedControls: 7},
					{Framework: "soc2", PassRate: 85, TotalControls: 18, FailedControls: 3},
				},
			},
			Status: zelyov1alpha1.ScanReportStatus{Phase: "Complete"},
		},
		&zelyov1alpha1.ScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "platform-nightly-report-latest", Namespace: "platform",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.ScanReportSpec{
				ScanRef: "platform-nightly",
				Findings: []zelyov1alpha1.Finding{
					mkFinding("host-mount-1", "critical", "host-mounts", "hostPath mount to /var/run/docker.sock",
						"The DaemonSet mounts the Docker socket — any RCE yields cluster root.",
						"DaemonSet", "platform", "telemetry-agent"),
					mkFinding("netpol-1", "high", "network-policy", "No default-deny NetworkPolicy",
						"Namespace has no default-deny policy, allowing unrestricted lateral movement.",
						"Namespace", "", "platform"),
				},
				Summary: zelyov1alpha1.ScanSummary{
					TotalFindings: 2, Critical: 1, High: 1,
					ResourcesScanned: 28,
				},
				Compliance: []zelyov1alpha1.ComplianceResult{
					{Framework: "cis", PassRate: 82, TotalControls: 32, FailedControls: 6},
					{Framework: "nist-800-53", PassRate: 74, TotalControls: 45, FailedControls: 12},
				},
			},
			Status: zelyov1alpha1.ScanReportStatus{Phase: "Complete"},
		},
		&zelyov1alpha1.ScanReport{
			ObjectMeta: metav1.ObjectMeta{
				Name: "continuous-pod-audit-report-1", Namespace: "zelyo-system",
				CreationTimestamp: *yesterday,
			},
			Spec: zelyov1alpha1.ScanReportSpec{
				ScanRef: "continuous-pod-audit",
				Findings: []zelyov1alpha1.Finding{
					mkFinding("img-cve-1", "medium", "image-vulnerability", "High-severity CVE in base image",
						"Image ghcr.io/acme/api:v1.12 ships with known CVE-2026-1234.",
						"Pod", "apps", "order-service-0"),
					mkFinding("img-cve-2", "medium", "image-vulnerability", "Outdated OpenSSL in container",
						"OpenSSL 1.1.1 is end-of-life.",
						"Pod", "apps", "risk-engine-1"),
					mkFinding("secret-exp-1", "critical", "secrets-exposure", "AWS secret in container environment",
						"Environment variable AWS_SECRET_ACCESS_KEY detected — move to a Secret + projected volume.",
						"Deployment", "apps", "billing-worker"),
				},
				Summary: zelyov1alpha1.ScanSummary{
					TotalFindings: 7, Critical: 1, High: 2, Medium: 4,
					ResourcesScanned: 112,
				},
				Compliance: []zelyov1alpha1.ComplianceResult{
					{Framework: "cis", PassRate: 80, TotalControls: 32, FailedControls: 6},
				},
			},
			Status: zelyov1alpha1.ScanReportStatus{Phase: "Complete"},
		},
	}
}

// ---- CloudAccountConfigs --------------------------------------------------

func demoCloudAccounts(now *metav1.Time) []client.Object {
	return []client.Object{
		&zelyov1alpha1.CloudAccountConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aws-prod-817293", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.CloudAccountConfigSpec{
				Provider:             "aws",
				AccountID:            "817293040501",
				Regions:              []string{"us-east-1", "us-west-2", "eu-central-1"},
				ScanCategories:       []string{"cspm", "ciem", "network", "dspm"},
				ComplianceFrameworks: []string{"cis-aws", "soc2", "pci-dss"},
				Schedule:             "0 */6 * * *",
				HistoryLimit:         15,
				Credentials: zelyov1alpha1.CloudCredentials{
					Method:  "irsa",
					RoleARN: "arn:aws:iam::817293040501:role/zelyo-cspm-reader",
				},
			},
			Status: zelyov1alpha1.CloudAccountConfigStatus{
				Phase:            "Active",
				FindingsCount:    42,
				LastScanTime:     now,
				CompletedAt:      now,
				ScannedRegions:   []string{"us-east-1", "us-west-2", "eu-central-1"},
				ResourcesScanned: 1842,
				LastReportName:   "aws-prod-817293-report-latest",
				FindingsSummary: zelyov1alpha1.FindingsSummary{
					Critical: 4, High: 11, Medium: 18, Low: 7, Info: 2,
				},
			},
		},
		&zelyov1alpha1.CloudAccountConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aws-staging-443190", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.CloudAccountConfigSpec{
				Provider:             "aws",
				AccountID:            "443190276614",
				Regions:              []string{"us-east-1"},
				ScanCategories:       []string{"cspm", "supply-chain"},
				ComplianceFrameworks: []string{"cis-aws"},
				Schedule:             "0 */12 * * *",
				HistoryLimit:         10,
				Credentials: zelyov1alpha1.CloudCredentials{
					Method:  "irsa",
					RoleARN: "arn:aws:iam::443190276614:role/zelyo-cspm-reader",
				},
			},
			Status: zelyov1alpha1.CloudAccountConfigStatus{
				Phase:            "Active",
				FindingsCount:    9,
				LastScanTime:     now,
				CompletedAt:      now,
				ScannedRegions:   []string{"us-east-1"},
				ResourcesScanned: 387,
				FindingsSummary: zelyov1alpha1.FindingsSummary{
					Critical: 0, High: 2, Medium: 4, Low: 3,
				},
			},
		},
	}
}

// ---- ZelyoConfig ----------------------------------------------------------

func demoZelyoConfig(now *metav1.Time) client.Object {
	return &zelyov1alpha1.ZelyoConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "zelyo", CreationTimestamp: *now},
		Spec: zelyov1alpha1.ZelyoConfigSpec{
			Mode: "protect",
			LLM: zelyov1alpha1.LLMConfig{
				Provider:            "anthropic",
				Model:               "anthropic/claude-sonnet-4-5-20251001",
				APIKeySecret:        "zelyo-llm-api-key",
				MaxTokensPerRequest: 4096,
			},
			GitHub: &zelyov1alpha1.GitHubConfig{
				AppID:          1234567,
				InstallationID: 89012345,
			},
			TokenBudget: zelyov1alpha1.TokenBudgetConfig{
				HourlyTokenLimit:  50_000,
				DailyTokenLimit:   500_000,
				MonthlyTokenLimit: 5_000_000,
			},
		},
		Status: zelyov1alpha1.ZelyoConfigStatus{
			Phase:              "Active",
			ActiveMode:         "protect",
			LLMKeyStatus:       "Verified",
			LLMKeyLastVerified: now,
			LastReconciled:     now,
			TokenUsage: zelyov1alpha1.TokenUsageStatus{
				TokensUsedToday:     47_321,
				TokensUsedThisMonth: 1_284_907,
				EstimatedCostUSD:    "$18.42",
			},
		},
	}
}

// ---- GitOpsRepository -----------------------------------------------------

func demoGitOpsRepo(now *metav1.Time) client.Object {
	return &zelyov1alpha1.GitOpsRepository{
		ObjectMeta: metav1.ObjectMeta{
			Name: "platform-gitops", Namespace: "zelyo-system",
			CreationTimestamp: *now,
		},
		Spec: zelyov1alpha1.GitOpsRepositorySpec{
			URL:        "https://github.com/zelyo-ai/platform-gitops",
			Branch:     "main",
			Provider:   "github",
			AuthSecret: "platform-gitops-auth",
			SourceType: zelyov1alpha1.ManifestSourceAuto,
		},
		Status: zelyov1alpha1.GitOpsRepositoryStatus{Phase: "Active"},
	}
}

// ---- RemediationPolicy ----------------------------------------------------

func demoRemediationPolicy(now *metav1.Time) client.Object {
	return &zelyov1alpha1.RemediationPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "auto-pr-critical-and-high", Namespace: "zelyo-system",
			CreationTimestamp: *now,
		},
		Spec: zelyov1alpha1.RemediationPolicySpec{
			GitOpsRepository: "platform-gitops",
			SeverityFilter:   "high",
			DryRun:           false,
		},
		Status: zelyov1alpha1.RemediationPolicyStatus{Phase: "Active"},
	}
}

// ---- MonitoringPolicy -----------------------------------------------------

func demoMonitoringPolicy(now *metav1.Time) client.Object {
	return &zelyov1alpha1.MonitoringPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "anomaly-detection-default", Namespace: "zelyo-system",
			CreationTimestamp: *now,
		},
		Spec: zelyov1alpha1.MonitoringPolicySpec{
			NotificationChannels: []string{"slack-security-incidents"},
		},
		Status: zelyov1alpha1.MonitoringPolicyStatus{
			Phase:           "Active",
			EventsProcessed: 12_847,
		},
	}
}

// ---- NotificationChannels -------------------------------------------------

func demoNotificationChannels(now *metav1.Time) []client.Object {
	return []client.Object{
		&zelyov1alpha1.NotificationChannel{
			ObjectMeta: metav1.ObjectMeta{
				Name: "slack-security-incidents", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.NotificationChannelSpec{
				Type:             "slack",
				CredentialSecret: "slack-webhook",
				SeverityFilter:   "high",
				Slack: &zelyov1alpha1.SlackConfig{
					Channel: "#security-incidents",
				},
			},
			Status: zelyov1alpha1.NotificationChannelStatus{Phase: "Active"},
		},
		&zelyov1alpha1.NotificationChannel{
			ObjectMeta: metav1.ObjectMeta{
				Name: "pagerduty-oncall", Namespace: "zelyo-system",
				CreationTimestamp: *now,
			},
			Spec: zelyov1alpha1.NotificationChannelSpec{
				Type:             "pagerduty",
				CredentialSecret: "pagerduty-token",
				SeverityFilter:   "critical",
				PagerDuty: &zelyov1alpha1.PagerDutyConfig{
					DefaultSeverity: "critical",
				},
			},
			Status: zelyov1alpha1.NotificationChannelStatus{Phase: "Active"},
		},
	}
}

// ---- CostPolicy -----------------------------------------------------------

func demoCostPolicy(now *metav1.Time) client.Object {
	return &zelyov1alpha1.CostPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cost-guardrails-prod", Namespace: "zelyo-system",
			CreationTimestamp: *now,
		},
		Spec: zelyov1alpha1.CostPolicySpec{
			NotificationChannels: []string{"slack-security-incidents"},
		},
		Status: zelyov1alpha1.CostPolicyStatus{Phase: "Active"},
	}
}
