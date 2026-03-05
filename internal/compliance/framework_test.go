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

package compliance

import (
	"testing"
)

func TestEvaluateFindings_AllPassed(t *testing.T) {
	// No findings = all controls should pass.
	report := EvaluateFindings(FrameworkCISK8s, nil)

	if report == nil {
		t.Fatal("Expected non-nil report")
	}
	if report.Framework != FrameworkCISK8s {
		t.Errorf("Expected framework CIS-Kubernetes, got %s", report.Framework)
	}
	if report.Summary.TotalControls != 15 {
		t.Errorf("Expected 15 CIS controls, got %d", report.Summary.TotalControls)
	}
	if report.Summary.Passed != 15 {
		t.Errorf("Expected 15 passed when no findings, got %d", report.Summary.Passed)
	}
	if report.Summary.Failed != 0 {
		t.Errorf("Expected 0 failed when no findings, got %d", report.Summary.Failed)
	}
	if report.Summary.CompliancePct != 100.0 {
		t.Errorf("Expected 100%% compliance, got %.1f%%", report.Summary.CompliancePct)
	}
}

func TestEvaluateFindings_FailedControls(t *testing.T) {
	findings := []Finding{
		{
			RuleType:          "pod-security",
			Severity:          "critical",
			Title:             "Host PID enabled",
			ResourceKind:      "Pod",
			ResourceNamespace: "production",
			ResourceName:      "web-app",
		},
	}

	report := EvaluateFindings(FrameworkCISK8s, findings)

	if report.Summary.Failed == 0 {
		t.Fatal("Expected at least one failed control for pod-security finding")
	}

	// pod-security maps to controls 5.2.1, 5.2.2, 5.2.3, 5.2.4, 5.2.7, 5.2.8, 5.2.9 = 7 controls.
	expectedFailed := 7
	if report.Summary.Failed != expectedFailed {
		t.Errorf("Expected %d failed controls for pod-security, got %d", expectedFailed, report.Summary.Failed)
	}

	expectedPassed := 15 - expectedFailed
	if report.Summary.Passed != expectedPassed {
		t.Errorf("Expected %d passed controls, got %d", expectedPassed, report.Summary.Passed)
	}
}

func TestEvaluateFindings_EvidenceAttachment(t *testing.T) {
	findings := []Finding{
		{
			RuleType:          "secrets-exposure",
			Severity:          "high",
			Title:             "Secrets exposed as env vars",
			ResourceKind:      "Deployment",
			ResourceNamespace: "staging",
			ResourceName:      "api-server",
		},
	}

	report := EvaluateFindings(FrameworkCISK8s, findings)

	// secrets-exposure maps to controls 5.4.1 and 5.4.2.
	failedCount := 0
	for _, c := range report.Controls {
		if c.Status == ControlFailed {
			failedCount++
			if len(c.Evidence) == 0 {
				t.Errorf("Control %s failed but has no evidence", c.ID)
			}
			// Verify evidence content.
			found := false
			for _, e := range c.Evidence {
				if e.Type == "scan-finding" && e.Description == "Secrets exposed as env vars" {
					found = true
					if e.ResourceRef != "Deployment/staging/api-server" {
						t.Errorf("Expected resource ref Deployment/staging/api-server, got %s", e.ResourceRef)
					}
				}
			}
			if !found {
				t.Errorf("Control %s: expected scan-finding evidence with correct description", c.ID)
			}
		}
	}

	if failedCount != 2 {
		t.Errorf("Expected 2 failed controls for secrets-exposure, got %d", failedCount)
	}
}

func TestEvaluateFindings_MultipleRuleTypes(t *testing.T) {
	findings := []Finding{
		{RuleType: "container-security-context", Severity: "critical", Title: "Privileged container"},
		{RuleType: "rbac-audit", Severity: "medium", Title: "Default service account"},
	}

	report := EvaluateFindings(FrameworkCISK8s, findings)

	// container-security-context → 5.2.1, 5.2.5, 5.2.6, 5.7.2, 5.7.3 = 5 controls
	// rbac-audit → 5.7.1, 5.7.4 = 2 controls
	// Some controls overlap (none in this case), so total failed = 7.
	if report.Summary.Failed != 7 {
		t.Errorf("Expected 7 failed controls for container-security-context + rbac-audit, got %d", report.Summary.Failed)
	}
}

func TestEvaluateFindings_DefaultFramework(t *testing.T) {
	// Unknown framework should default to CIS.
	report := EvaluateFindings("unknown-framework", nil)

	if report.Summary.TotalControls != 15 {
		t.Errorf("Expected 15 controls with default framework, got %d", report.Summary.TotalControls)
	}
}

func TestCalculateSummary(t *testing.T) {
	controls := []Control{
		{Status: ControlPassed},
		{Status: ControlPassed},
		{Status: ControlFailed},
		{Status: ControlException},
		{Status: ControlNotChecked},
	}

	s := CalculateSummary(controls)

	if s.TotalControls != 5 {
		t.Errorf("Expected 5 total, got %d", s.TotalControls)
	}
	if s.Passed != 2 {
		t.Errorf("Expected 2 passed, got %d", s.Passed)
	}
	if s.Failed != 1 {
		t.Errorf("Expected 1 failed, got %d", s.Failed)
	}
	if s.Exceptions != 1 {
		t.Errorf("Expected 1 exception, got %d", s.Exceptions)
	}
	if s.NotChecked != 1 {
		t.Errorf("Expected 1 not_checked, got %d", s.NotChecked)
	}
	if s.CompliancePct != 40.0 {
		t.Errorf("Expected 40%% compliance, got %.1f%%", s.CompliancePct)
	}
}
