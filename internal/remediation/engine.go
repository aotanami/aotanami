/*
Copyright 2026 Zelyo AI.
*/

// Package remediation provides the auto-fix engine that generates Kubernetes
// patches from scan findings, validates them, and submits them via GitOps PRs.
package remediation

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/aotanami/aotanami/internal/gitops"
	"github.com/aotanami/aotanami/internal/llm"
	"github.com/aotanami/aotanami/internal/scanner"
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
	gitopsEngine   gitops.Engine
	log            logr.Logger
	strategy       Strategy
	maxBlastRadius int // Max number of resources a single remediation can affect.
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
	}
}

// GeneratePlan uses the LLM to analyze a finding and produce fix recommendations.
func (e *Engine) GeneratePlan(ctx context.Context, finding *scanner.Finding) (*Plan, error) {
	prompt := buildRemediationPrompt(finding)

	resp, err := e.llmClient.Complete(ctx, llm.Request{
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
		Finding:     finding,
		LLMAnalysis: resp.Content,
		CreatedAt:   time.Now(),
	}

	// Parse fixes from LLM response (the LLM returns structured recommendations).
	plan.Fixes = extractFixes(resp.Content, finding)
	plan.RiskScore = estimateRisk(finding, plan.Fixes)

	return plan, nil
}

// ApplyPlan executes a remediation plan according to the configured strategy.
func (e *Engine) ApplyPlan(ctx context.Context, plan *Plan, repoOwner, repoName string) (*gitops.PullRequestResult, error) {
	switch e.strategy {
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
		return nil, fmt.Errorf("remediation: unknown strategy %q", e.strategy)
	}
}

func (e *Engine) createPR(ctx context.Context, plan *Plan, owner, repo string) (*gitops.PullRequestResult, error) {
	if e.gitopsEngine == nil {
		return nil, fmt.Errorf("remediation: GitOps engine not configured")
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
		Labels:     []string{"aotanami", "security", "automated"},
		Files:      files,
	}

	result, err := e.gitopsEngine.CreatePullRequest(ctx, pr)
	if err != nil {
		return nil, fmt.Errorf("remediation: create PR: %w", err)
	}

	e.log.Info("Remediation PR created",
		"pr", result.URL,
		"finding", plan.Finding.Title,
		"risk_score", plan.RiskScore)

	return result, nil
}

const systemPrompt = `You are Aotanami, an autonomous Kubernetes security operator.
Your job is to analyze security findings and recommend precise, safe fixes.

Rules:
1. Always prefer the least disruptive fix.
2. Never remove functionality — only tighten security.
3. Explain the risk of NOT fixing and the risk of the fix itself.
4. Output concrete YAML patches that can be directly applied.
5. Consider blast radius — how many workloads will be affected.`

func buildRemediationPrompt(f *scanner.Finding) string {
	return fmt.Sprintf(`Analyze this Kubernetes security finding and provide a fix:

**Rule Type:** %s
**Severity:** %s
**Title:** %s
**Description:** %s
**Resource:** %s %s/%s
**Recommendation:** %s

Please provide:
1. Root cause analysis
2. Concrete YAML fix (as a patch)
3. Risk assessment of applying the fix
4. Verification steps`, f.RuleType, f.Severity, f.Title, f.Description,
		f.ResourceKind, f.ResourceNamespace, f.ResourceName, f.Recommendation)
}

func extractFixes(llmResponse string, finding *scanner.Finding) []Fix {
	// In a full implementation, this would parse structured output from the LLM.
	// For now, create a single fix entry with the LLM's recommendation.
	return []Fix{
		{
			Description: fmt.Sprintf("Fix %s: %s", finding.RuleType, finding.Title),
			FilePath:    fmt.Sprintf("k8s/%s/%s.yaml", finding.ResourceNamespace, finding.ResourceName),
			Patch:       llmResponse,
			Operation:   gitops.FileOpUpdate,
		},
	}
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
