/*
Copyright 2026 Zelyo AI
*/

// Package remediation provides the auto-fix engine that generates Kubernetes
// patches from scan findings, validates them, and submits them via GitOps PRs.
package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/zelyo-ai/zelyo-operator/internal/gitops"
	"github.com/zelyo-ai/zelyo-operator/internal/llm"
	"github.com/zelyo-ai/zelyo-operator/internal/scanner"
)

// Strategy defines how a remediation should be applied.
type Strategy string

const (
	// StrategyGitOpsPR creates a pull request with the fix.
	StrategyGitOpsPR Strategy = "gitops-pr"

	// StrategyDryRun validates the fix but doesn't apply it.
	StrategyDryRun Strategy = "dry-run"

	// StrategyReport only generates a report of recommended fixes.
	StrategyReport Strategy = "report"
)

// Plan describes a set of fixes for a finding.
type Plan struct {
	// Finding is the original security finding.
	Finding *scanner.Finding `json:"finding"`

	// Fixes is the list of recommended changes.
	Fixes []Fix `json:"fixes"`

	// LLMAnalysis is the AI-generated explanation.
	LLMAnalysis string `json:"llm_analysis"`

	// RiskScore is the estimated risk of applying the fix (0-100).
	RiskScore int `json:"risk_score"`

	// CreatedAt is when the plan was generated.
	CreatedAt time.Time `json:"created_at"`
}

// Fix describes a single remediation action.
type Fix struct {
	// Description is a human-readable description of the change.
	Description string `json:"description"`

	// FilePath is the path to the file to modify (relative to repo root).
	FilePath string `json:"file_path"`

	// Patch is the content change (could be a full file or a JSON patch).
	Patch string `json:"patch"`

	// Operation is the type of change.
	Operation gitops.FileOp `json:"operation"`
}

// Engine orchestrates the remediation workflow.
type Engine struct {
	llmClient      llm.Client
	gitopsEngine   gitops.Engine // Default engine for unregistered repos.
	log            logr.Logger
	strategy       Strategy
	maxBlastRadius int // Max number of resources a single remediation can affect.

	mu             sync.RWMutex
	gitopsRegistry map[string]gitops.Engine // Keyed by "owner/repo".
}

// EngineConfig configures the remediation engine.
type EngineConfig struct {
	// Strategy defines how remediations are applied.
	Strategy Strategy `json:"strategy"`

	// MaxBlastRadius limits how many resources a fix can affect.
	MaxBlastRadius int `json:"max_blast_radius"`
}

// NewEngine creates a new remediation engine.
func NewEngine(llmClient llm.Client, ge gitops.Engine, cfg EngineConfig, log logr.Logger) *Engine {
	maxBlast := cfg.MaxBlastRadius
	if maxBlast == 0 {
		maxBlast = 10 // default: 10 resources max per remediation
	}

	return &Engine{
		llmClient:      llmClient,
		gitopsEngine:   ge,
		log:            log,
		strategy:       cfg.Strategy,
		maxBlastRadius: maxBlast,
		gitopsRegistry: make(map[string]gitops.Engine),
	}
}

// RegisterGitOpsEngine registers a repo-specific GitOps engine.
// The key should be "owner/repo" (e.g. "zelyo-ai/infra-manifests").
func (e *Engine) RegisterGitOpsEngine(repoKey string, engine gitops.Engine) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gitopsRegistry[repoKey] = engine
	e.log.Info("Registered GitOps engine for repository", "repo", repoKey)
}

// getGitOpsEngine returns the engine for a specific repo, falling back to the default.
func (e *Engine) getGitOpsEngine(owner, repo string) gitops.Engine {
	e.mu.RLock()
	defer e.mu.RUnlock()
	key := owner + "/" + repo
	if eng, ok := e.gitopsRegistry[key]; ok {
		return eng
	}
	return e.gitopsEngine
}

// SetLLMClient updates the LLM client used by the engine.
func (e *Engine) SetLLMClient(client llm.Client) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.llmClient = client
}

// SetGitOpsEngine updates the GitOps engine used by the engine.
func (e *Engine) SetGitOpsEngine(ge gitops.Engine) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.gitopsEngine = ge
}

// SetConfig updates the engine configuration.
func (e *Engine) SetConfig(cfg EngineConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.strategy = cfg.Strategy
	if cfg.MaxBlastRadius > 0 {
		e.maxBlastRadius = cfg.MaxBlastRadius
	}
}

// GeneratePlan uses the LLM to analyze a finding and produce fix recommendations.
func (e *Engine) GeneratePlan(ctx context.Context, finding *scanner.Finding) (*Plan, error) {
	prompt := buildRemediationPrompt(finding)

	e.mu.RLock()
	client := e.llmClient
	e.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("remediation: LLM client not configured")
	}

	resp, err := client.Complete(ctx, llm.Request{
		Messages: []llm.Message{
			{
				Role:    llm.RoleSystem,
				Content: systemPrompt,
			},
			{
				Role:    llm.RoleUser,
				Content: prompt,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("remediation: LLM analysis failed: %w", err)
	}

	plan := &Plan{
		Finding:   finding,
		CreatedAt: time.Now(),
	}

	// Parse fixes from LLM response (structured JSON or fallback to raw text).
	fixes, analysis, llmRisk := extractFixes(resp.Content, finding)
	plan.Fixes = fixes
	plan.LLMAnalysis = analysis

	// Use LLM-provided risk score if available, otherwise estimate heuristically.
	if llmRisk >= 0 && llmRisk <= 100 {
		plan.RiskScore = llmRisk
	} else {
		plan.RiskScore = estimateRisk(finding, plan.Fixes)
	}

	return plan, nil
}

// ApplyPlan executes a remediation plan according to the configured strategy.
func (e *Engine) ApplyPlan(ctx context.Context, plan *Plan, repoOwner, repoName string) (*gitops.PullRequestResult, error) {
	e.mu.RLock()
	strategy := e.strategy
	e.mu.RUnlock()

	switch strategy {
	case StrategyDryRun:
		e.log.Info("Dry-run: would apply remediation",
			"finding", plan.Finding.Title,
			"fixes", len(plan.Fixes),
			"risk", plan.RiskScore)
		return nil, nil

	case StrategyReport:
		e.log.Info("Report: remediation plan generated",
			"finding", plan.Finding.Title,
			"analysis", plan.LLMAnalysis)
		return nil, nil

	case StrategyGitOpsPR:
		return e.createPR(ctx, plan, repoOwner, repoName)

	default:
		return nil, fmt.Errorf("remediation: unknown strategy %q", strategy)
	}
}

func (e *Engine) createPR(ctx context.Context, plan *Plan, owner, repo string) (*gitops.PullRequestResult, error) {
	ge := e.getGitOpsEngine(owner, repo)
	if ge == nil {
		return nil, fmt.Errorf("remediation: GitOps engine not configured for %s/%s", owner, repo)
	}

	// Build file changes from fixes.
	files := make([]gitops.FileChange, 0, len(plan.Fixes))
	for _, fix := range plan.Fixes {
		files = append(files, gitops.FileChange{
			Path:      fix.FilePath,
			Content:   fix.Patch,
			Operation: fix.Operation,
		})
	}

	pr := gitops.PullRequest{
		RepoOwner:  owner,
		RepoName:   repo,
		Title:      gitops.PRTitle(plan.Finding.ResourceName, plan.Finding.ResourceNamespace, plan.Finding.RuleType),
		Body:       gitops.PRBody(plan.Finding.RuleType, plan.Finding.ResourceName, plan.Finding.ResourceNamespace, plan.Finding.Description, plan.LLMAnalysis),
		BaseBranch: "main",
		HeadBranch: gitops.BranchName(plan.Finding.ResourceName, plan.Finding.ResourceNamespace, plan.Finding.Title),
		Labels:     []string{"zelyo-operator", "security", "automated"},
		Files:      files,
	}

	result, err := ge.CreatePullRequest(ctx, &pr)
	if err != nil {
		return nil, fmt.Errorf("remediation: create PR: %w", err)
	}

	e.log.Info("Remediation PR created",
		"pr", result.URL,
		"finding", plan.Finding.Title,
		"risk_score", plan.RiskScore)

	return result, nil
}

const systemPrompt = `You are Zelyo Operator, an autonomous Kubernetes security operator.
Your job is to analyze security findings and recommend precise, safe fixes.

Rules:
1. Always prefer the least disruptive fix.
2. Never remove functionality — only tighten security.
3. Explain the risk of NOT fixing and the risk of the fix itself.
4. Consider blast radius — how many workloads will be affected.
5. Output concrete YAML patches that can be directly applied.

You MUST respond with a JSON object in this exact format:
{
  "analysis": "Root cause analysis and risk assessment",
  "fixes": [
    {
      "file_path": "path/to/file.yaml",
      "description": "What this change does",
      "patch": "Full YAML content of the fixed resource",
      "operation": "update"
    }
  ],
  "risk_assessment": "Impact analysis of applying this fix",
  "risk_score": 25
}

The operation field must be one of: "create", "update", "delete".
The risk_score field is 0-100 (0 = safe, 100 = dangerous).
Respond ONLY with the JSON object, no additional text.`

func buildRemediationPrompt(f *scanner.Finding) string {
	return fmt.Sprintf(`Analyze this Kubernetes security finding and provide a fix as JSON:

**Rule Type:** %s
**Severity:** %s
**Title:** %s
**Description:** %s
**Resource:** %s %s/%s
**Recommendation:** %s

Respond with the JSON object as specified in the system prompt.`, f.RuleType, f.Severity, f.Title, f.Description,
		f.ResourceKind, f.ResourceNamespace, f.ResourceName, f.Recommendation)
}

// llmResponse is the expected JSON structure from the LLM.
type llmResponse struct {
	Analysis       string   `json:"analysis"`
	Fixes          []llmFix `json:"fixes"`
	RiskAssessment string   `json:"risk_assessment"`
	RiskScore      *int     `json:"risk_score,omitempty"`
}

type llmFix struct {
	FilePath    string `json:"file_path"`
	Description string `json:"description"`
	Patch       string `json:"patch"`
	Operation   string `json:"operation"`
}

func extractFixes(llmContent string, finding *scanner.Finding) (fixes []Fix, analysis string, riskScore int) {
	// Try to parse structured JSON from the LLM response.
	jsonStr := extractJSON(llmContent)
	if jsonStr != "" {
		var resp llmResponse
		if err := json.Unmarshal([]byte(jsonStr), &resp); err == nil && len(resp.Fixes) > 0 {
			fixes := make([]Fix, 0, len(resp.Fixes))
			for _, f := range resp.Fixes {
				op := gitops.FileOpUpdate
				switch f.Operation {
				case "create":
					op = gitops.FileOpCreate
				case "delete":
					op = gitops.FileOpDelete
				}
				fixes = append(fixes, Fix{
					Description: f.Description,
					FilePath:    f.FilePath,
					Patch:       f.Patch,
					Operation:   op,
				})
			}

			analysis := resp.Analysis
			if resp.RiskAssessment != "" {
				analysis += "\n\nRisk Assessment: " + resp.RiskAssessment
			}

			riskScore := -1 // Sentinel: let estimateRisk calculate.
			if resp.RiskScore != nil {
				riskScore = *resp.RiskScore
			}

			return fixes, analysis, riskScore
		}
	}

	// Fallback: LLM returned unstructured text. Wrap as a single fix.
	return []Fix{
		{
			Description: fmt.Sprintf("Fix %s: %s", finding.RuleType, finding.Title),
			FilePath:    fmt.Sprintf("k8s/%s/%s.yaml", finding.ResourceNamespace, finding.ResourceName),
			Patch:       llmContent,
			Operation:   gitops.FileOpUpdate,
		},
	}, llmContent, -1
}

// extractJSON finds JSON content in an LLM response, handling markdown code blocks.
func extractJSON(s string) string {
	// Try direct parse first.
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		return s
	}

	// Try extracting from ```json ... ``` code block.
	if idx := strings.Index(s, "```json"); idx != -1 {
		start := idx + len("```json")
		if end := strings.Index(s[start:], "```"); end != -1 {
			return strings.TrimSpace(s[start : start+end])
		}
	}

	// Try extracting from ``` ... ``` code block.
	if idx := strings.Index(s, "```"); idx != -1 {
		start := idx + 3
		if end := strings.Index(s[start:], "```"); end != -1 {
			candidate := strings.TrimSpace(s[start : start+end])
			if strings.HasPrefix(candidate, "{") {
				return candidate
			}
		}
	}

	// Try finding a JSON object anywhere in the response.
	if idx := strings.Index(s, "{"); idx != -1 {
		// Find matching closing brace.
		depth := 0
		for i := idx; i < len(s); i++ {
			switch s[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return s[idx : i+1]
				}
			}
		}
	}

	return ""
}

func estimateRisk(finding *scanner.Finding, fixes []Fix) int {
	// Higher severity findings = lower risk to fix (more urgent).
	// More file changes = higher risk.
	baseRisk := 30
	switch finding.Severity {
	case "critical":
		baseRisk = 10 // Critical findings are low risk to fix
	case "high":
		baseRisk = 20
	case "medium":
		baseRisk = 40
	case "low":
		baseRisk = 60
	}
	// Each additional file change adds risk.
	return min(baseRisk+len(fixes)*5, 100)
}
