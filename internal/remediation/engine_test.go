/*
Copyright 2026 Zelyo AI
*/

package remediation

import (
	"context"
	"testing"

	"github.com/go-logr/logr"

	"github.com/zelyo-ai/zelyo-operator/internal/gitops"
	"github.com/zelyo-ai/zelyo-operator/internal/llm"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// fakeLLMClient implements llm.Client for tests — returns a pre-canned
// response string and records the request count.
type fakeLLMClient struct {
	response string
	calls    int
}

func (f *fakeLLMClient) Complete(_ context.Context, _ llm.Request) (*llm.Response, error) {
	f.calls++
	return &llm.Response{Content: f.response, Model: "fake"}, nil
}
func (f *fakeLLMClient) Provider() llm.Provider { return "fake" }
func (f *fakeLLMClient) Close() error           { return nil }

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

func TestExtractFixes_UnstructuredResponseRejected(t *testing.T) {
	// Unstructured LLM prose MUST NOT be committed as a patch. The previous
	// behavior wrapped the raw text as a single fix — this test guards
	// against regressing to that by asserting the plan is rejected with
	// zero fixes when the LLM fails to return the structured JSON shape.
	llmResponse := "You should add securityContext with runAsNonRoot: true to the container spec."

	finding := &scanner.Finding{
		RuleType:          "container-security-context",
		Title:             "Root container",
		ResourceName:      "app",
		ResourceNamespace: "default",
	}

	fixes, analysis, riskScore := extractFixes(llmResponse, finding)

	if len(fixes) != 0 {
		t.Fatalf("Expected 0 fixes from unstructured response, got %d", len(fixes))
	}
	if analysis != llmResponse {
		t.Errorf("Expected raw LLM content preserved as analysis for operator visibility, got %q", analysis)
	}
	if riskScore != -1 {
		t.Errorf("Expected -1 sentinel risk score, got %d", riskScore)
	}
}

func TestExtractFixes_UnsafeFilePathDropped(t *testing.T) {
	// Guard against LLM-emitted path traversal and absolute paths. Each
	// fix carries a legit file plus an unsafe variant; validated output
	// must contain only the safe one.
	llmResponse := `{
		"analysis": "Add RBAC constraints.",
		"fixes": [
			{"file_path": "k8s/ns/role.yaml", "description": "ok", "patch": "x", "operation": "update"},
			{"file_path": "../secret.yaml",  "description": "bad", "patch": "x", "operation": "update"},
			{"file_path": "/etc/passwd",     "description": "bad", "patch": "x", "operation": "delete"}
		]
	}`
	finding := &scanner.Finding{RuleType: "rbac-audit"}
	fixes, _, _ := extractFixes(llmResponse, finding)
	if len(fixes) != 1 {
		t.Fatalf("expected only the safe fix to survive validation, got %d fixes", len(fixes))
	}
	if fixes[0].FilePath != "k8s/ns/role.yaml" {
		t.Errorf("unexpected surviving path: %q", fixes[0].FilePath)
	}
}

func TestExtractFixes_EmptyPatchForCreateUpdateDropped(t *testing.T) {
	// A create or update with empty patch content would land as a commit
	// that blanks out the target manifest. Only delete legitimately has
	// no patch body. The validator drops the empty-patch create/update
	// fixes and keeps a legitimate delete (which has empty patch by design).
	llmResponse := `{
		"analysis": "Mixed fixes.",
		"fixes": [
			{"file_path": "k8s/a.yaml", "description": "blank create", "patch": "",   "operation": "create"},
			{"file_path": "k8s/b.yaml", "description": "blank update", "patch": "   ", "operation": "update"},
			{"file_path": "k8s/c.yaml", "description": "legit delete", "patch": "",   "operation": "delete"},
			{"file_path": "k8s/d.yaml", "description": "legit update", "patch": "apiVersion: v1", "operation": "update"}
		]
	}`
	finding := &scanner.Finding{RuleType: "test"}
	fixes, _, _ := extractFixes(llmResponse, finding)
	if len(fixes) != 2 {
		t.Fatalf("expected 2 surviving fixes (delete + non-blank update), got %d", len(fixes))
	}
	var seen = map[string]gitops.FileOp{}
	for _, f := range fixes {
		seen[f.FilePath] = f.Operation
	}
	if seen["k8s/c.yaml"] != gitops.FileOpDelete {
		t.Errorf("expected delete for k8s/c.yaml, got %s", seen["k8s/c.yaml"])
	}
	if seen["k8s/d.yaml"] != gitops.FileOpUpdate {
		t.Errorf("expected update for k8s/d.yaml, got %s", seen["k8s/d.yaml"])
	}
	if _, ok := seen["k8s/a.yaml"]; ok {
		t.Errorf("blank-patch create should have been dropped")
	}
	if _, ok := seen["k8s/b.yaml"]; ok {
		t.Errorf("blank-patch update should have been dropped")
	}
}

func TestExtractFixes_UnknownOperationDropped(t *testing.T) {
	// Unknown operations previously defaulted to "update" silently — we now
	// drop the fix rather than invent an operation the LLM never asked for.
	llmResponse := `{
		"analysis": "Try something weird.",
		"fixes": [
			{"file_path": "k8s/a.yaml", "description": "patch", "patch": "x", "operation": "patch"}
		]
	}`
	finding := &scanner.Finding{RuleType: "test"}
	fixes, _, _ := extractFixes(llmResponse, finding)
	if len(fixes) != 0 {
		t.Fatalf("expected unknown operation to be dropped, got %d fixes", len(fixes))
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

// TestGeneratePlan_ZeroValidatedFixes_ReturnsError verifies that when the
// LLM response passes through extractFixes with zero surviving fixes —
// whether because it was unstructured prose, or because every proposed
// fix was filtered out as unsafe — GeneratePlan surfaces an error so the
// caller (processIncidents) does NOT resolve the incident. Silent
// zero-fix plans were how unsafe/malformed LLM output could close
// incidents with no remediation applied.
func TestGeneratePlan_ZeroValidatedFixes_ReturnsError(t *testing.T) {
	cases := []struct {
		name     string
		response string
	}{
		{
			name:     "unstructured prose",
			response: "Just describe the fix in natural language.",
		},
		{
			name: "all fixes filtered — path traversal",
			response: `{
				"analysis": "Try these.",
				"fixes": [
					{"file_path": "../etc/passwd", "description": "bad", "patch": "x", "operation": "delete"},
					{"file_path": "/root/.ssh/authorized_keys", "description": "bad", "patch": "x", "operation": "delete"}
				]
			}`,
		},
		{
			name: "all fixes filtered — unknown operation",
			response: `{
				"analysis": "Try this.",
				"fixes": [{"file_path": "k8s/a.yaml", "description": "x", "patch": "x", "operation": "patch"}]
			}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewEngine(&fakeLLMClient{response: tc.response}, nil,
				EngineConfig{Strategy: StrategyDryRun}, logr.Discard())
			plan, err := engine.GeneratePlan(context.Background(), &scanner.Finding{RuleType: "test", Title: "t"}, nil)
			if err == nil {
				t.Fatalf("expected error for zero validated fixes, got plan=%+v", plan)
			}
			if plan != nil {
				t.Errorf("expected nil plan when fixes are rejected, got %+v", plan)
			}
		})
	}
}
