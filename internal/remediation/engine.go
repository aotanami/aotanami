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

	"github.com/zelyo-ai/zelyo-operator/internal/events"
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

// GitOpsEngineForRepo is the public accessor callers (RemediationPolicy
// controller) use to consult the gitops engine for read-only calls like
// ListOpenPRs — needed for PR dedup before ApplyPlan.
func (e *Engine) GitOpsEngineForRepo(owner, repo string) gitops.Engine {
	return e.getGitOpsEngine(owner, repo)
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
//
// allowedPaths, when non-empty, constrains the LLM's file_path choice to
// repo-relative paths under one of those prefixes. This is how we stop
// the LLM from inventing arbitrary paths like "demo-app/redis.yaml" when
// the GitOpsRepository's configured paths are ["helm/zelyo-demo"]. Paths
// that don't fall under an allowed prefix are dropped in extractFixes;
// if all fixes get dropped, GeneratePlan returns the same zero-fix error
// it returns for any other filtered-to-empty plan.
func (e *Engine) GeneratePlan(ctx context.Context, finding *scanner.Finding, allowedPaths []string) (*Plan, error) {
	var prompt string
	if isCloudFinding(finding.RuleType) {
		prompt = buildCloudRemediationPrompt(finding, allowedPaths)
	} else {
		prompt = buildRemediationPrompt(finding, allowedPaths)
	}

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

	// Parse fixes from LLM response. extractFixes enforces the strict JSON
	// schema + per-fix validation (path safety, operation allowlist, size
	// caps) and drops anything unsafe. If NOTHING survives, the plan has
	// no remediation to apply — treat that as an error so the caller keeps
	// the incident open for retry/manual triage. The previous behavior
	// returned an empty plan with nil error, which led processIncidents
	// to ResolveIncident() and silently close the case with nothing done.
	//
	// The error message deliberately does NOT include the raw LLM analysis:
	// the controller emits GeneratePlan errors as Kubernetes Events
	// (remediationpolicy_controller.go), and model output may echo secrets
	// or large manifest snippets that must not land on a cluster-visible
	// sink. The full analysis stays in the operator-level log via whatever
	// log.Error wrapper the caller chooses.
	fixes, analysis, llmRisk := extractFixes(resp.Content, finding)
	if len(allowedPaths) > 0 {
		fixes = filterFixesToAllowedPaths(fixes, allowedPaths)
	}
	if len(fixes) == 0 {
		return nil, fmt.Errorf("remediation: no valid fixes produced from LLM response (analysis omitted)")
	}
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

	// Emit pipeline events so the dashboard Pipeline view shows real
	// remediation activity. Previously only the Compliance preset flow
	// emitted these, so the real Fix column stayed empty even while
	// remediation was running. We populate the remediation store too so
	// clicking the PR card in the Pipeline opens a Before/Diff/After
	// panel with the LLM analysis, the same panel the preset flow uses.
	repoSlug := fmt.Sprintf("%s/%s", owner, repo)
	resourceKey := events.ResourceKey(
		plan.Finding.ResourceKind,
		plan.Finding.ResourceNamespace,
		plan.Finding.ResourceName,
	)
	items := make([]events.RemediationItem, 0, len(plan.Fixes))
	filesChanged := make([]string, 0, len(plan.Fixes))
	for _, fix := range plan.Fixes {
		items = append(items, events.RemediationItem{
			// Canonical kind/namespace/name key so the dashboard's
			// MarkResolved lookup after a clean re-scan matches.
			ResourceKey: resourceKey,
			Resource:    fix.FilePath,
			Rule:        plan.Finding.RuleType,
			Severity:    plan.Finding.Severity,
			Title:       fix.Description,
		})
		filesChanged = append(filesChanged, fix.FilePath)
	}
	events.DefaultRemediationStore().Upsert(&events.RemediationContext{
		ScanRef:      plan.Finding.RuleType,
		Namespace:    plan.Finding.ResourceNamespace,
		Repo:         repoSlug,
		PRURL:        result.URL,
		Summary:      plan.Finding.Title,
		Findings:     items,
		Diff:         buildFixPlanDiff(plan.Fixes),
		FilesChanged: filesChanged,
	})
	events.EmitRemediationDrafted(plan.Finding.RuleType, plan.Finding.Title, len(plan.Fixes))
	events.EmitPullRequestOpened(result.URL, repoSlug, len(plan.Fixes))

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

// isCloudFinding returns true if the rule type indicates a cloud security finding.
func isCloudFinding(ruleType string) bool {
	prefixes := []string{"cspm-", "ciem-", "network-", "dspm-", "supplychain-", "cicd-"}
	for _, p := range prefixes {
		if len(ruleType) > len(p) && ruleType[:len(p)] == p {
			return true
		}
	}
	return false
}

func buildCloudRemediationPrompt(f *scanner.Finding, allowedPaths []string) string {
	return fmt.Sprintf(`Analyze this cloud security finding and provide an Infrastructure-as-Code fix as JSON:

**Rule Type:** %s
**Severity:** %s
**Title:** %s
**Description:** %s
**Cloud Resource:** %s (Region: %s, Name: %s)
**Recommendation:** %s

Provide a fix using one of these IaC formats:
1. Terraform HCL patch (preferred for Terraform-managed infrastructure)
2. CloudFormation YAML patch (for CFN-managed infrastructure)
3. AWS CLI remediation command (for immediate manual fix)

Use the same JSON response schema from the system prompt.
%s
Include both the IaC fix and the equivalent AWS CLI command in the analysis field.`,
		f.RuleType, f.Severity, f.Title, f.Description,
		f.ResourceKind, f.ResourceNamespace, f.ResourceName, f.Recommendation,
		pathConstraintsPromptFragment(allowedPaths))
}

func buildRemediationPrompt(f *scanner.Finding, allowedPaths []string) string {
	return fmt.Sprintf(`Analyze this Kubernetes security finding and provide a fix as JSON:

**Rule Type:** %s
**Severity:** %s
**Title:** %s
**Description:** %s
**Resource:** %s %s/%s
**Recommendation:** %s

%s
Respond with the JSON object as specified in the system prompt.`,
		f.RuleType, f.Severity, f.Title, f.Description,
		f.ResourceKind, f.ResourceNamespace, f.ResourceName, f.Recommendation,
		pathConstraintsPromptFragment(allowedPaths))
}

// pathConstraintsPromptFragment injects the GitOpsRepository's configured
// path prefixes into the LLM prompt so the model doesn't hallucinate file
// locations. Without this the LLM invents paths from the resource name
// (e.g. "demo-app/redis.yaml") that land at repo root instead of under
// the configured manifest directory.
func pathConstraintsPromptFragment(allowedPaths []string) string {
	if len(allowedPaths) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(allowedPaths))
	for _, p := range allowedPaths {
		quoted = append(quoted, fmt.Sprintf("%q", strings.TrimSuffix(p, "/")))
	}
	return fmt.Sprintf(
		"**Repository layout constraint:** All file_path values in the response MUST be repo-relative paths that begin with one of: %s. Do NOT invent paths outside these directories — the GitOps repo is only watched under these prefixes.\n",
		strings.Join(quoted, ", "),
	)
}

// filterFixesToAllowedPaths drops any fix whose FilePath doesn't fall
// under one of the GitOpsRepository's configured paths. This is the
// post-LLM belt-and-braces check complementing the prompt constraint —
// even if the model ignores the prompt we never commit outside the
// allowed directory set.
func filterFixesToAllowedPaths(fixes []Fix, allowedPaths []string) []Fix {
	if len(allowedPaths) == 0 {
		return fixes
	}
	prefixes := make([]string, 0, len(allowedPaths))
	for _, p := range allowedPaths {
		p = strings.TrimPrefix(strings.TrimSuffix(p, "/"), "/")
		if p == "" {
			// An allowed path of "" or "/" means "the whole repo" — any
			// path is valid; don't apply prefix filtering at all.
			return fixes
		}
		prefixes = append(prefixes, p+"/")
	}
	out := make([]Fix, 0, len(fixes))
	for _, f := range fixes {
		fp := strings.TrimPrefix(f.FilePath, "/")
		for _, pref := range prefixes {
			if strings.HasPrefix(fp+"/", pref) || fp == strings.TrimSuffix(pref, "/") {
				out = append(out, f)
				break
			}
		}
	}
	return out
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

// Upper bounds on LLM fix-plan content. These are defensive caps, not
// business rules: a legitimate fix plan is nowhere near these limits, and
// anything beyond them is either a hallucination or an attempted abuse
// of the remediation pipeline.
const (
	maxFixesPerPlan       = 20
	maxFixFilePathLen     = 512
	maxFixPatchBytes      = 256 * 1024 // 256 KiB
	maxFixDescriptionSize = 4 * 1024   // 4 KiB
)

func extractFixes(llmContent string, finding *scanner.Finding) (fixes []Fix, analysis string, riskScore int) {
	// The LLM MUST return the structured JSON shape we asked for. If it
	// doesn't, we refuse the plan rather than wrapping the raw response
	// as a "patch" and letting arbitrary prose land in a commit.
	jsonStr := extractJSON(llmContent)
	if jsonStr == "" {
		return nil, llmContent, -1
	}
	var resp llmResponse
	if err := json.Unmarshal([]byte(jsonStr), &resp); err != nil {
		return nil, llmContent, -1
	}
	if len(resp.Fixes) == 0 {
		return nil, resp.Analysis, -1
	}
	if len(resp.Fixes) > maxFixesPerPlan {
		resp.Fixes = resp.Fixes[:maxFixesPerPlan]
	}
	validated := make([]Fix, 0, len(resp.Fixes))
	for _, f := range resp.Fixes {
		op, ok := parseFixOperation(f.Operation)
		if !ok {
			continue
		}
		if !validFixFilePath(f.FilePath) {
			continue
		}
		if len(f.Patch) > maxFixPatchBytes {
			continue
		}
		// A create/update with empty content would land as a commit that
		// blanks out the target file. Only delete legitimately has no
		// patch body — the operation carries the intent by itself.
		if op != gitops.FileOpDelete && strings.TrimSpace(f.Patch) == "" {
			continue
		}
		desc := f.Description
		if len(desc) > maxFixDescriptionSize {
			desc = desc[:maxFixDescriptionSize]
		}
		validated = append(validated, Fix{
			Description: desc,
			FilePath:    f.FilePath,
			Patch:       f.Patch,
			Operation:   op,
		})
	}
	if len(validated) == 0 {
		return nil, resp.Analysis, -1
	}

	analysis = resp.Analysis
	if resp.RiskAssessment != "" {
		analysis += "\n\nRisk Assessment: " + resp.RiskAssessment
	}

	riskScore = -1 // Sentinel: let estimateRisk calculate when LLM omits.
	if resp.RiskScore != nil {
		riskScore = *resp.RiskScore
	}
	_ = finding // retained for future finding-scoped validation.
	return validated, analysis, riskScore
}

// parseFixOperation maps the LLM's operation string to a gitops.FileOp.
// Anything we don't explicitly accept is rejected — no silent fallback
// to "update" that would let a hallucinated operation overwrite a file.
func parseFixOperation(op string) (gitops.FileOp, bool) {
	switch op {
	case "create":
		return gitops.FileOpCreate, true
	case "update":
		return gitops.FileOpUpdate, true
	case "delete":
		return gitops.FileOpDelete, true
	default:
		return "", false
	}
}

// validFixFilePath enforces the minimum shape of a repo-relative path we
// will ever commit: non-empty, bounded length, no path-traversal
// segments, no absolute paths, no NUL/control bytes. The downstream
// GitHub engine applies additional URL-escaping and rejects backslashes
// via safeRepoPath; this is a belt-and-braces check at the LLM boundary.
func validFixFilePath(p string) bool {
	if p == "" || len(p) > maxFixFilePathLen {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\x00") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
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

// buildFixPlanDiff renders the LLM fix plan as a valid unified diff.
// Zelyo's system prompt instructs the model to return the FULL intended
// file content in `patch` (not a raw diff fragment), so at the
// remediation-engine boundary we're always producing "create-or-replace"
// diffs: /dev/null → +++ b/<path>, one hunk per file, every content line
// prefixed with '+'. Mirrors buildPresetDiff in the dashboard so the
// Before/Diff/After panel renders identically for both preset- and
// AI-authored changes. The previous body ("--- a/<p>\n+++ b/<p>\n<content>")
// was NOT a valid unified diff and broke that panel.
func buildFixPlanDiff(fixes []Fix) string {
	var b strings.Builder
	for _, f := range fixes {
		lines := strings.Split(f.Patch, "\n")
		fmt.Fprintf(&b, "--- /dev/null\n+++ b/%s\n@@ +0,0 +1,%d @@\n", f.FilePath, len(lines))
		for _, line := range lines {
			fmt.Fprintf(&b, "+%s\n", line)
		}
	}
	return b.String()
}
