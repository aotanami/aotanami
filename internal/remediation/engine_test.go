/*
Copyright 2026 The Aotanami Authors. Originally created by Zelyo AI.
*/

package remediation

import (
	"testing"

	"github.com/aotanami/aotanami/internal/gitops"
	"github.com/aotanami/aotanami/internal/scanner"
)

func TestExtractFixes_StructuredJSON(t *testing.T) {
	llmResponse := `{
		"analysis": "The container runs as root which is a security risk.",
		"fixes": [
			{
				"file_path": "k8s/default/nginx.yaml",
				"description": "Set runAsNonRoot to true",
				"patch": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: nginx",
				"operation": "update"
			}
		],
		"risk_assessment": "Low risk — only affects container user.",
		"risk_score": 15
	}`

	finding := &scanner.Finding{
		RuleType:          "container-security-context",
		Title:             "Container runs as root",
		ResourceName:      "nginx",
		ResourceNamespace: "default",
	}

	fixes, analysis, riskScore := extractFixes(llmResponse, finding)

	if len(fixes) != 1 {
		t.Fatalf("Expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].FilePath != "k8s/default/nginx.yaml" {
		t.Errorf("Unexpected file path: %s", fixes[0].FilePath)
	}
	if fixes[0].Operation != gitops.FileOpUpdate {
		t.Errorf("Expected update operation, got %s", fixes[0].Operation)
	}
	if fixes[0].Description != "Set runAsNonRoot to true" {
		t.Errorf("Unexpected description: %s", fixes[0].Description)
	}
	if analysis == "" {
		t.Error("Expected non-empty analysis")
	}
	if riskScore != 15 {
		t.Errorf("Expected risk score 15, got %d", riskScore)
	}
}

func TestExtractFixes_MarkdownCodeBlock(t *testing.T) {
	llmResponse := "Here's the fix:\n\n```json\n" + `{
		"analysis": "Missing network policy.",
		"fixes": [
			{
				"file_path": "k8s/prod/netpol.yaml",
				"description": "Add default deny network policy",
				"patch": "apiVersion: networking.k8s.io/v1",
				"operation": "create"
			}
		],
		"risk_assessment": "Medium risk.",
		"risk_score": 40
	}` + "\n```\n"

	finding := &scanner.Finding{RuleType: "network-policy", Title: "Missing NetworkPolicy"}

	fixes, _, riskScore := extractFixes(llmResponse, finding)

	if len(fixes) != 1 {
		t.Fatalf("Expected 1 fix from markdown code block, got %d", len(fixes))
	}
	if fixes[0].Operation != gitops.FileOpCreate {
		t.Errorf("Expected create operation, got %s", fixes[0].Operation)
	}
	if riskScore != 40 {
		t.Errorf("Expected risk score 40, got %d", riskScore)
	}
}

func TestExtractFixes_Fallback(t *testing.T) {
	// Unstructured response should fall back gracefully.
	llmResponse := "You should add securityContext with runAsNonRoot: true to the container spec."

	finding := &scanner.Finding{
		RuleType:          "container-security-context",
		Title:             "Root container",
		ResourceName:      "app",
		ResourceNamespace: "default",
	}

	fixes, analysis, riskScore := extractFixes(llmResponse, finding)

	if len(fixes) != 1 {
		t.Fatalf("Expected 1 fallback fix, got %d", len(fixes))
	}
	if fixes[0].Patch != llmResponse {
		t.Error("Expected raw LLM response as patch in fallback mode")
	}
	if analysis != llmResponse {
		t.Error("Expected raw LLM response as analysis in fallback mode")
	}
	if riskScore != -1 {
		t.Errorf("Expected -1 sentinel risk score in fallback, got %d", riskScore)
	}
}

func TestExtractFixes_DeleteOperation(t *testing.T) {
	llmResponse := `{
		"analysis": "Unused ClusterRoleBinding should be removed.",
		"fixes": [
			{
				"file_path": "k8s/default/crb.yaml",
				"description": "Delete unused ClusterRoleBinding",
				"patch": "",
				"operation": "delete"
			}
		],
		"risk_assessment": "High risk — verify no services depend on this."
	}`

	finding := &scanner.Finding{RuleType: "rbac-audit", Title: "Unused CRB"}
	fixes, _, riskScore := extractFixes(llmResponse, finding)

	if len(fixes) != 1 {
		t.Fatalf("Expected 1 fix, got %d", len(fixes))
	}
	if fixes[0].Operation != gitops.FileOpDelete {
		t.Errorf("Expected delete operation, got %s", fixes[0].Operation)
	}
	// No risk_score in JSON → sentinel.
	if riskScore != -1 {
		t.Errorf("Expected -1 for missing risk_score, got %d", riskScore)
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantJSON bool
	}{
		{"direct JSON", `{"analysis": "test"}`, true},
		{"markdown code block", "```json\n{\"a\": 1}\n```", true},
		{"plain code block", "```\n{\"a\": 1}\n```", true},
		{"embedded in text", "Here is the fix: {\"a\": 1} done.", true},
		{"no JSON", "Just plain text with no braces.", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJSON(tt.input)
			if tt.wantJSON && result == "" {
				t.Error("Expected JSON extraction, got empty")
			}
			if !tt.wantJSON && result != "" {
				t.Errorf("Expected no JSON, got %q", result)
			}
		})
	}
}

func TestEstimateRisk(t *testing.T) {
	tests := []struct {
		severity   string
		fixCount   int
		expectedLo int
		expectedHi int
	}{
		{"critical", 1, 10, 20},
		{"high", 1, 20, 30},
		{"medium", 2, 40, 55},
		{"low", 1, 60, 70},
	}

	for _, tt := range tests {
		fixes := make([]Fix, tt.fixCount)
		finding := &scanner.Finding{Severity: tt.severity}
		risk := estimateRisk(finding, fixes)
		if risk < tt.expectedLo || risk > tt.expectedHi {
			t.Errorf("estimateRisk(severity=%s, fixes=%d) = %d, want [%d, %d]",
				tt.severity, tt.fixCount, risk, tt.expectedLo, tt.expectedHi)
		}
	}
}
