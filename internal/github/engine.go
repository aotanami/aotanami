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

package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/zelyo-ai/zelyo-operator/internal/gitops"
)

// GitHubEngine implements gitops.Engine using the GitHub REST API.
// It supports GitHub App authentication and all CRUD operations needed
// for the Zelyo Operator auto-remediation workflow.
//
//nolint:revive // External package wrapper
type GitHubEngine struct {
	client  *Client
	http    *http.Client
	log     logr.Logger
	baseURL string
}

// NewEngine creates a GitHubEngine from an authenticated Client.
func NewEngine(client *Client, log logr.Logger) *GitHubEngine {
	return &GitHubEngine{
		client:  client,
		http:    client.AuthenticatedClient(),
		log:     log,
		baseURL: client.BaseURL(),
	}
}

// CreatePullRequest implements gitops.Engine.CreatePullRequest.
// It creates a branch, commits files, and opens a PR.
func (e *GitHubEngine) CreatePullRequest(ctx context.Context, pr *gitops.PullRequest) (*gitops.PullRequestResult, error) {
	e.log.Info("Creating pull request",
		"owner", pr.RepoOwner, "repo", pr.RepoName,
		"head", pr.HeadBranch, "base", pr.BaseBranch,
		"files", len(pr.Files))

	// Step 1: Get the SHA of the base branch.
	baseSHA, err := e.getRef(ctx, pr.RepoOwner, pr.RepoName, "heads/"+pr.BaseBranch)
	if err != nil {
		return nil, fmt.Errorf("getting base branch ref: %w", err)
	}

	// Step 2: Create the head branch from the base.
	if err := e.createRef(ctx, pr.RepoOwner, pr.RepoName, "refs/heads/"+pr.HeadBranch, baseSHA); err != nil {
		// Branch might already exist from a previous attempt — continue.
		if !strings.Contains(err.Error(), "422") {
			return nil, fmt.Errorf("creating head branch: %w", err)
		}
		e.log.Info("Branch already exists, continuing", "branch", pr.HeadBranch)
	}

	// Step 3: Commit each file to the head branch.
	for _, file := range pr.Files {
		switch file.Operation {
		case gitops.FileOpDelete:
			if err := e.deleteFile(ctx, pr.RepoOwner, pr.RepoName, file.Path, pr.HeadBranch); err != nil {
				return nil, fmt.Errorf("deleting file %s: %w", file.Path, err)
			}
		default: // Create or Update.
			if err := e.createOrUpdateFile(ctx, pr.RepoOwner, pr.RepoName, file.Path, file.Content, pr.HeadBranch); err != nil {
				return nil, fmt.Errorf("updating file %s: %w", file.Path, err)
			}
		}
	}

	// Step 4: Create the pull request.
	prResult, err := e.openPR(ctx, pr)
	if err != nil {
		return nil, fmt.Errorf("opening pull request: %w", err)
	}

	// Step 5: Add labels if specified.
	if len(pr.Labels) > 0 {
		if err := e.addLabels(ctx, pr.RepoOwner, pr.RepoName, prResult.Number, pr.Labels); err != nil {
			e.log.Error(err, "Failed to add labels (non-fatal)", "labels", pr.Labels)
		}
	}

	e.log.Info("Pull request created successfully",
		"number", prResult.Number,
		"url", prResult.URL)

	return prResult, nil
}

// GetFile implements gitops.Engine.GetFile.
func (e *GitHubEngine) GetFile(ctx context.Context, owner, repo, path, ref string) ([]byte, error) {
	escaped, err := safeRepoPath(path)
	if err != nil {
		return nil, fmt.Errorf("validating repository path for get %q: %w", path, err)
	}
	reqURL := fmt.Sprintf("%s/repos/%s/%s/contents/%s?ref=%s", e.baseURL, owner, repo, escaped, url.QueryEscape(ref))

	body, err := e.doRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("getting file %s: %w", path, err)
	}

	var result struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decoding file response: %w", err)
	}

	if result.Encoding != "base64" {
		return []byte(result.Content), nil
	}

	// Decode base64 content (GitHub returns newline-separated base64).
	clean := strings.ReplaceAll(result.Content, "\n", "")
	decoded := make([]byte, len(clean))
	n, err := base64Decode(decoded, []byte(clean))
	if err != nil {
		return nil, fmt.Errorf("decoding base64 content: %w", err)
	}

	return decoded[:n], nil
}

// ListOpenPRs implements gitops.Engine.ListOpenPRs by paginating over
// GitHub's list-PRs endpoint. A single page is 100 PRs (the endpoint's max);
// we keep requesting successive pages until a page comes back short or we
// hit listOpenPRsMaxPages. The cap guards against runaway calls if the
// provider ever misbehaves — at 100/page × 10 pages, callers see up to
// 1000 open PRs before the count saturates, which is far beyond any sane
// MaxConcurrentPRs configuration.
func (e *GitHubEngine) ListOpenPRs(ctx context.Context, owner, repo string) ([]gitops.PullRequestResult, error) {
	var results []gitops.PullRequestResult
	for page := 1; page <= listOpenPRsMaxPages; page++ {
		reqURL := fmt.Sprintf("%s/repos/%s/%s/pulls?state=open&per_page=%d&page=%d",
			e.baseURL, owner, repo, listOpenPRsPageSize, page)

		body, err := e.doRequest(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("listing open PRs (page %d): %w", page, err)
		}

		var prs []struct {
			Number  int    `json:"number"`
			HTMLURL string `json:"html_url"`
			Head    struct {
				Ref string `json:"ref"`
			} `json:"head"`
			CreatedAt time.Time `json:"created_at"`
			Labels    []struct {
				Name string `json:"name"`
			} `json:"labels"`
		}
		if err := json.Unmarshal(body, &prs); err != nil {
			return nil, fmt.Errorf("decoding PRs response (page %d): %w", page, err)
		}

		// Filter to Zelyo Operator-created PRs.
		for _, pr := range prs {
			isZelyoOperator := strings.HasPrefix(pr.Head.Ref, "zelyo-operator/")
			if !isZelyoOperator {
				for _, l := range pr.Labels {
					if l.Name == "zelyo-operator" {
						isZelyoOperator = true
						break
					}
				}
			}
			if isZelyoOperator {
				results = append(results, gitops.PullRequestResult{
					Number:    pr.Number,
					URL:       pr.HTMLURL,
					Branch:    pr.Head.Ref,
					CreatedAt: pr.CreatedAt,
				})
			}
		}

		// Short page → we've drained results. Full page → try the next one.
		if len(prs) < listOpenPRsPageSize {
			return results, nil
		}
		if page == listOpenPRsMaxPages {
			e.log.Info("ListOpenPRs page cap reached — count may be an undercount",
				"owner", owner, "repo", repo,
				"maxPages", listOpenPRsMaxPages, "pageSize", listOpenPRsPageSize)
		}
	}
	return results, nil
}

const (
	listOpenPRsPageSize = 100 // GitHub's max page size for list-PRs.
	listOpenPRsMaxPages = 10  // Safety cap: 100 × 10 = 1000 PRs.
)

// Close implements gitops.Engine.Close.
func (e *GitHubEngine) Close() error {
	e.http.CloseIdleConnections()
	return nil
}

// ── Internal GitHub API helpers ──

func (e *GitHubEngine) getRef(ctx context.Context, owner, repo, ref string) (string, error) {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/git/ref/%s", e.baseURL, owner, repo, ref)
	body, err := e.doRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	var result struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.Object.SHA, nil
}

func (e *GitHubEngine) createRef(ctx context.Context, owner, repo, ref, sha string) error {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/git/refs", e.baseURL, owner, repo)
	payload := map[string]string{"ref": ref, "sha": sha}
	_, err := e.doRequest(ctx, http.MethodPost, reqURL, payload)
	return err
}

func (e *GitHubEngine) createOrUpdateFile(ctx context.Context, owner, repo, path, content, branch string) error {
	escaped, err := safeRepoPath(path)
	if err != nil {
		return fmt.Errorf("validating repository path for upsert %q: %w", path, err)
	}
	reqURL := fmt.Sprintf("%s/repos/%s/%s/contents/%s", e.baseURL, owner, repo, escaped)

	// Check if file exists to get its SHA (required for updates).
	var existingSHA string
	getURL := fmt.Sprintf("%s?ref=%s", reqURL, url.QueryEscape(branch))
	body, err := e.doRequest(ctx, http.MethodGet, getURL, nil)
	if err == nil {
		var existing struct {
			SHA string `json:"sha"`
		}
		if json.Unmarshal(body, &existing) == nil {
			existingSHA = existing.SHA
		}
	}

	payload := map[string]interface{}{
		"message": fmt.Sprintf("[Zelyo Operator] Update %s", path),
		"content": base64Encode([]byte(content)),
		"branch":  branch,
	}
	if existingSHA != "" {
		payload["sha"] = existingSHA
	}

	_, err = e.doRequest(ctx, http.MethodPut, reqURL, payload)
	return err
}

func (e *GitHubEngine) deleteFile(ctx context.Context, owner, repo, path, branch string) error {
	escaped, err := safeRepoPath(path)
	if err != nil {
		return fmt.Errorf("validating repository path for delete %q: %w", path, err)
	}
	reqURL := fmt.Sprintf("%s/repos/%s/%s/contents/%s", e.baseURL, owner, repo, escaped)

	// Get file SHA.
	getURL := fmt.Sprintf("%s?ref=%s", reqURL, url.QueryEscape(branch))
	body, err := e.doRequest(ctx, http.MethodGet, getURL, nil)
	if err != nil {
		return fmt.Errorf("getting file SHA for delete: %w", err)
	}
	var existing struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &existing); err != nil {
		return fmt.Errorf("decoding file SHA: %w", err)
	}

	payload := map[string]interface{}{
		"message": fmt.Sprintf("[Zelyo Operator] Delete %s", path),
		"sha":     existing.SHA,
		"branch":  branch,
	}
	_, err = e.doRequest(ctx, http.MethodDelete, reqURL, payload)
	return err
}

func (e *GitHubEngine) openPR(ctx context.Context, pr *gitops.PullRequest) (*gitops.PullRequestResult, error) {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/pulls", e.baseURL, pr.RepoOwner, pr.RepoName)
	payload := map[string]interface{}{
		"title": pr.Title,
		"body":  pr.Body,
		"head":  pr.HeadBranch,
		"base":  pr.BaseBranch,
	}

	body, err := e.doRequest(ctx, http.MethodPost, reqURL, payload)
	if err != nil {
		return nil, err
	}

	var result struct {
		Number    int       `json:"number"`
		HTMLURL   string    `json:"html_url"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decoding PR response: %w", err)
	}

	return &gitops.PullRequestResult{
		Number:    result.Number,
		URL:       result.HTMLURL,
		Branch:    pr.HeadBranch,
		CreatedAt: result.CreatedAt,
	}, nil
}

func (e *GitHubEngine) addLabels(ctx context.Context, owner, repo string, prNumber int, labels []string) error {
	reqURL := fmt.Sprintf("%s/repos/%s/%s/issues/%d/labels", e.baseURL, owner, repo, prNumber)
	payload := map[string]interface{}{"labels": labels}
	_, err := e.doRequest(ctx, http.MethodPost, reqURL, payload)
	return err
}

// doRequest performs an authenticated HTTP request and returns the response body.
func (e *GitHubEngine) doRequest(ctx context.Context, method, reqURL string, payload interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		jsonBody, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := e.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("GitHub API error %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	return body, nil
}

// truncate limits a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// safeRepoPath validates a repository-relative file path supplied by the
// LLM remediation planner (or, indirectly, by a caller whose Finding
// metadata we cannot trust) and returns a URL-escaped form suitable for
// embedding in a GitHub contents API request. We reject anything that
// could escape the repo root — absolute paths, backslashes, or any
// "../" / "./"  segment — then PathEscape each remaining segment so
// spaces, percent-encodings, and other reserved characters in a legit
// path don't corrupt the URL.
func safeRepoPath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty repository path")
	}
	if strings.ContainsRune(p, '\\') {
		return "", fmt.Errorf("backslash in repository path: %q", p)
	}
	if strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("absolute repository path: %q", p)
	}
	segments := strings.Split(p, "/")
	escaped := make([]string, 0, len(segments))
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("unsafe segment %q in repository path %q", seg, p)
		}
		escaped = append(escaped, url.PathEscape(seg))
	}
	return strings.Join(escaped, "/"), nil
}

// base64Encode encodes bytes to base64 string.
func base64Encode(data []byte) string {
	return base64StdEncoding(data)
}

// base64Decode decodes base64 bytes.
func base64Decode(dst, src []byte) (int, error) {
	return base64StdDecoding(dst, src)
}
