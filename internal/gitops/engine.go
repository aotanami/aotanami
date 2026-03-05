/*
Copyright 2026 Zelyo AI
*/

// Package gitops provides Git repository operations for Zelyo Operator's auto-remediation
// workflow. It handles cloning repos, creating branches, committing fixes, and
// opening pull requests via the GitHub API.
package gitops

import (
	"context"
	"fmt"
	"time"
)

// PullRequest represents a pull request to create.
type PullRequest struct {
	// RepoOwner is the repository owner (org or user).
	RepoOwner string `json:"repo_owner"`

	// RepoName is the repository name.
	RepoName string `json:"repo_name"`

	// Title is the PR title.
	Title string `json:"title"`

	// Body is the PR description (supports markdown).
	Body string `json:"body"`

	// BaseBranch is the target branch (e.g. "main").
	BaseBranch string `json:"base_branch"`

	// HeadBranch is the source branch with the fix.
	HeadBranch string `json:"head_branch"`

	// Labels are labels to apply to the PR.
	Labels []string `json:"labels,omitempty"`

	// Files are the file changes in this PR.
	Files []FileChange `json:"files"`

	// AutoMerge enables auto-merge when checks pass.
	AutoMerge bool `json:"auto_merge,omitempty"`
}

// FileChange represents a single file modification.
type FileChange struct {
	// Path is the file path relative to the repo root.
	Path string `json:"path"`

	// Content is the new file content.
	Content string `json:"content"`

	// Operation is the type of change.
	Operation FileOp `json:"operation"`
}

// FileOp is the type of file change.
type FileOp string

// Enumeration values.
const (
	FileOpCreate FileOp = "create"
	FileOpUpdate FileOp = "update"
	FileOpDelete FileOp = "delete"
)

// PullRequestResult is the result of creating a PR.
type PullRequestResult struct {
	// Number is the PR number.
	Number int `json:"number"`

	// URL is the web URL of the PR.
	URL string `json:"url"`

	// Branch is the branch name that was created.
	Branch string `json:"branch"`

	// CreatedAt is when the PR was created.
	CreatedAt time.Time `json:"created_at"`
}

// Engine is the interface for GitOps operations.
type Engine interface {
	// CreatePullRequest creates a PR with the given changes.
	CreatePullRequest(ctx context.Context, pr *PullRequest) (*PullRequestResult, error)

	// GetFile retrieves a file from a repository.
	GetFile(ctx context.Context, owner, repo, path, ref string) ([]byte, error)

	// ListOpenPRs returns open PRs created by Zelyo Operator.
	ListOpenPRs(ctx context.Context, owner, repo string) ([]PullRequestResult, error)

	// Close releases resources held by the engine.
	Close() error
}

// GitHubConfig holds GitHub App authentication configuration.
type GitHubConfig struct {
	// AppID is the GitHub App ID.
	AppID int64 `json:"app_id"`

	// InstallationID is the GitHub App Installation ID.
	InstallationID int64 `json:"installation_id"`

	// PrivateKey is the PEM-encoded private key for the GitHub App.
	PrivateKey []byte `json:"-"`

	// BaseURL overrides the GitHub API URL (for GitHub Enterprise).
	BaseURL string `json:"base_url,omitempty"`
}

// BranchName generates a standardized branch name for Zelyo Operator remediation PRs.
func BranchName(resource, namespace, finding string) string {
	branch := fmt.Sprintf("zelyo-operator/fix/%s-%s-%s", namespace, resource, sanitizeBranchName(finding))
	// Git branch names longer than 200 chars cause issues with some providers.
	if len(branch) > 200 {
		branch = branch[:200]
	}
	return branch
}

// PRTitle generates a standardized PR title.
func PRTitle(resource, namespace, scanner string) string {
	return fmt.Sprintf("🛡️ [Zelyo Operator] Fix %s findings in %s/%s", scanner, namespace, resource)
}

// PRBody generates a comprehensive PR body with remediation context.
func PRBody(scanner, resource, namespace, description, llmAnalysis string) string {
	return fmt.Sprintf(`## 🛡️ Zelyo Operator Automated Remediation

**Scanner:** %s
**Resource:** %s/%s
**Namespace:** %s

### What was detected
%s

### AI Analysis & Fix
%s

### Verification
- [ ] Review the proposed changes
- [ ] Verify the fix doesn't break workload functionality
- [ ] Check that security posture improves

---
*This PR was automatically created by [Zelyo Operator](https://github.com/zelyo-ai/zelyo-operator) — your autonomous Kubernetes security operator.*
`, scanner, namespace, resource, namespace, description, llmAnalysis)
}

// sanitizeBranchName removes characters not allowed in Git branch names.
func sanitizeBranchName(s string) string {
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-':
			result = append(result, c)
		case c >= 'A' && c <= 'Z':
			result = append(result, c+32) // lowercase
		case c == ' ' || c == '_':
			result = append(result, '-')
		}
	}
	if len(result) > 40 {
		result = result[:40]
	}
	// Guard against all-special-char input producing an empty branch segment.
	if len(result) == 0 {
		return "untitled"
	}
	return string(result)
}
