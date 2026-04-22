/*
Copyright 2026 Zelyo AI
*/

package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"

	"github.com/zelyo-ai/zelyo-operator/internal/gitops"
)

func TestGitHubEngine_CreatePullRequest(t *testing.T) {
	// Mock GitHub API server.
	mux := http.NewServeMux()

	// GET ref (base branch SHA).
	mux.HandleFunc("GET /repos/testowner/testrepo/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"object": map[string]string{"sha": "abc123"},
		})
	})

	// POST ref (create branch).
	mux.HandleFunc("POST /repos/testowner/testrepo/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"ref": "refs/heads/zelyo-operator/fix-test"}) //nolint:errcheck
	})

	// GET file (check if exists — return 404 for new files).
	mux.HandleFunc("GET /repos/testowner/testrepo/contents/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	// PUT file (create/update).
	mux.HandleFunc("PUT /repos/testowner/testrepo/contents/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"content": map[string]string{"sha": "newsha123"},
		})
	})

	// POST PR.
	mux.HandleFunc("POST /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"number":     42,
			"html_url":   "https://github.com/testowner/testrepo/pull/42",
			"created_at": time.Now().Format(time.RFC3339),
		})
	})

	// POST labels.
	mux.HandleFunc("POST /repos/testowner/testrepo/issues/42/labels", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]string{{"name": "zelyo-operator"}}) //nolint:errcheck
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	pr := gitops.PullRequest{
		RepoOwner:  "testowner",
		RepoName:   "testrepo",
		Title:      "[Zelyo Operator] Fix security issue",
		Body:       "Automated fix by Zelyo Operator",
		BaseBranch: "main",
		HeadBranch: "zelyo-operator/fix-test",
		Labels:     []string{"zelyo-operator", "security"},
		Files: []gitops.FileChange{
			{
				Path:      "k8s/deployment.yaml",
				Content:   "apiVersion: apps/v1\nkind: Deployment",
				Operation: gitops.FileOpUpdate,
			},
		},
	}

	result, err := engine.CreatePullRequest(context.Background(), &pr)
	if err != nil {
		t.Fatalf("CreatePullRequest failed: %v", err)
	}

	if result.Number != 42 {
		t.Errorf("Expected PR number 42, got %d", result.Number)
	}
	if result.URL != "https://github.com/testowner/testrepo/pull/42" {
		t.Errorf("Unexpected PR URL: %s", result.URL)
	}
	if result.Branch != "zelyo-operator/fix-test" {
		t.Errorf("Unexpected branch: %s", result.Branch)
	}
}

// TestGitHubEngine_CreatePullRequest_SkipsWhenOpenPRExists is the
// regression guard for the "311 commits on one PR" footgun. When the
// target head branch already exists AND an open PR covers it, the engine
// must NOT commit new files and must NOT try to open a duplicate PR — it
// must return the existing PR.
//
// Before the fix: createRef returned 422 (branch exists), the engine
// silently continued, file commits landed on the open PR's branch, and
// openPR finally failed with 422 (PR exists). Every reconcile piled
// another commit on the same PR.
func TestGitHubEngine_CreatePullRequest_SkipsWhenOpenPRExists(t *testing.T) {
	const branch = "zelyo-operator/fix/payment-service"
	var (
		getRefCalls    int
		createRefCalls int
		listPRCalls    int
		putFileCalls   int
		openPRCalls    int
		lastHeadQuery  string
	)

	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/testowner/testrepo/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		getRefCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"object": map[string]string{"sha": "basesha"},
		})
	})

	// createRef returns 422 — branch already exists from a prior cycle.
	mux.HandleFunc("POST /repos/testowner/testrepo/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		createRefCalls++
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Reference already exists"}`))
	})

	// PR lookup — returns one open PR covering the branch. `head.label`
	// is the canonical "owner:ref" GitHub returns; the engine matches on
	// that so a fork PR with the same ref name can't false-match.
	mux.HandleFunc("GET /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, req *http.Request) {
		listPRCalls++
		lastHeadQuery = req.URL.Query().Get("head")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"number":     99,
				"html_url":   "https://github.com/testowner/testrepo/pull/99",
				"head":       map[string]string{"ref": branch, "label": "testowner:" + branch},
				"created_at": time.Now().Format(time.RFC3339),
			},
		})
	})

	// PUT /contents — MUST NOT be called. Failing here is the core
	// regression assertion: landing commits on an existing open PR is
	// what produced 311 duplicate commits in the original incident.
	mux.HandleFunc("PUT /repos/testowner/testrepo/contents/", func(w http.ResponseWriter, _ *http.Request) {
		putFileCalls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	// POST /pulls — MUST NOT be called.
	mux.HandleFunc("POST /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		openPRCalls++
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	result, err := engine.CreatePullRequest(context.Background(), &gitops.PullRequest{
		RepoOwner:  "testowner",
		RepoName:   "testrepo",
		Title:      "[Zelyo Operator] Fix payment-service",
		Body:       "x",
		BaseBranch: "main",
		HeadBranch: branch,
		Files: []gitops.FileChange{
			{Path: "k8s/payment-service.yaml", Content: "apiVersion: v1", Operation: gitops.FileOpUpdate},
		},
	})
	if err != nil {
		t.Fatalf("CreatePullRequest failed: %v", err)
	}

	// Existing PR must be returned.
	if result == nil {
		t.Fatal("expected existing PR to be returned, got nil result")
	}
	if result.Number != 99 {
		t.Errorf("expected existing PR number 99, got %d", result.Number)
	}
	if result.URL != "https://github.com/testowner/testrepo/pull/99" {
		t.Errorf("expected existing PR URL, got %s", result.URL)
	}
	if result.Branch != branch {
		t.Errorf("expected branch %q, got %q", branch, result.Branch)
	}

	// Critical regression assertions.
	if putFileCalls != 0 {
		t.Errorf("PUT /contents must not run when an open PR already covers the branch — got %d call(s)", putFileCalls)
	}
	if openPRCalls != 0 {
		t.Errorf("POST /pulls (openPR) must not run when an open PR already covers the branch — got %d call(s)", openPRCalls)
	}

	// The lookup must scope by head branch — otherwise a heavily-forked
	// repo's PR list could shadow our matcher.
	if lastHeadQuery == "" {
		t.Error("expected head query parameter on PR lookup; got empty")
	}
	if !strings.Contains(lastHeadQuery, branch) {
		t.Errorf("expected head query to contain branch %q, got %q", branch, lastHeadQuery)
	}

	// Sanity: the happy-path lookups DID run.
	if getRefCalls != 1 {
		t.Errorf("expected exactly 1 GET ref call, got %d", getRefCalls)
	}
	if createRefCalls != 1 {
		t.Errorf("expected exactly 1 POST refs call, got %d", createRefCalls)
	}
	if listPRCalls != 1 {
		t.Errorf("expected exactly 1 PR-lookup call, got %d", listPRCalls)
	}
}

// TestGitHubEngine_CreatePullRequest_BranchExistsWithoutOpenPR guards the
// legitimate case: a user manually closed/deleted a PR but left the
// branch behind. The engine should proceed — commit fresh files, open a
// new PR — not short-circuit.
func TestGitHubEngine_CreatePullRequest_BranchExistsWithoutOpenPR(t *testing.T) {
	const branch = "zelyo-operator/fix/orphan-branch"
	var putFileCalls, openPRCalls int

	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/testowner/testrepo/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"object": map[string]string{"sha": "basesha"},
		})
	})
	mux.HandleFunc("POST /repos/testowner/testrepo/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Reference already exists"}`))
	})
	// No open PR on the branch.
	mux.HandleFunc("GET /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
	})
	// Content GET (exists check inside createOrUpdateFile) — 404 so the
	// upsert treats the file as new.
	mux.HandleFunc("GET /repos/testowner/testrepo/contents/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("PUT /repos/testowner/testrepo/contents/", func(w http.ResponseWriter, _ *http.Request) {
		putFileCalls++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"content": map[string]string{"sha": "x"}})
	})
	mux.HandleFunc("POST /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		openPRCalls++
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"number":     42,
			"html_url":   "https://github.com/testowner/testrepo/pull/42",
			"created_at": time.Now().Format(time.RFC3339),
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	result, err := engine.CreatePullRequest(context.Background(), &gitops.PullRequest{
		RepoOwner:  "testowner",
		RepoName:   "testrepo",
		Title:      "t",
		BaseBranch: "main",
		HeadBranch: branch,
		Files: []gitops.FileChange{
			{Path: "a.yaml", Content: "x", Operation: gitops.FileOpUpdate},
		},
	})
	if err != nil {
		t.Fatalf("CreatePullRequest failed: %v", err)
	}
	if result == nil || result.Number != 42 {
		t.Fatalf("expected new PR #42, got %+v", result)
	}
	if putFileCalls != 1 {
		t.Errorf("expected PUT /contents to run when no open PR exists, got %d call(s)", putFileCalls)
	}
	if openPRCalls != 1 {
		t.Errorf("expected POST /pulls to run when no open PR exists, got %d call(s)", openPRCalls)
	}
}

// TestGitHubEngine_CreatePullRequest_DoesNotMatchForkPRWithSameRef
// defends the in-memory filter's owner+branch equality. GitHub's
// head=owner:ref query should narrow server-side, but if a proxy or
// mock ignores it, the response can include PRs from forks that use the
// same ref name. Matching only on head.ref would false-match those; we
// require head.label (canonical "owner:ref") to equal owner+":"+branch.
//
// Without this check, a heavily-forked repo could see CreatePullRequest
// short-circuit on a fork PR and skip the remediation commit entirely.
func TestGitHubEngine_CreatePullRequest_DoesNotMatchForkPRWithSameRef(t *testing.T) {
	const branch = "zelyo-operator/fix/shared-name"
	var putFileCalls, openPRCalls int

	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/testowner/testrepo/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"object": map[string]string{"sha": "basesha"}})
	})
	// Branch exists on our side → 422.
	mux.HandleFunc("POST /repos/testowner/testrepo/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Reference already exists"}`))
	})
	// Server returns a PR from a fork that happens to share the branch
	// name. Simulates a proxy that ignored the head= query filter.
	// head.label = "forkuser:<branch>" — distinct from the owner we sent.
	mux.HandleFunc("GET /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"number":     12345,
				"html_url":   "https://github.com/forkuser/testrepo/pull/12345",
				"head":       map[string]string{"ref": branch, "label": "forkuser:" + branch},
				"created_at": time.Now().Format(time.RFC3339),
			},
		})
	})
	// Content GET + PUT — the test expects the engine to REJECT the fork
	// PR as a false-match and proceed with its own commit + openPR, so
	// these do run.
	mux.HandleFunc("GET /repos/testowner/testrepo/contents/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("PUT /repos/testowner/testrepo/contents/", func(w http.ResponseWriter, _ *http.Request) {
		putFileCalls++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"content": map[string]string{"sha": "x"}})
	})
	mux.HandleFunc("POST /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		openPRCalls++
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"number":     101,
			"html_url":   "https://github.com/testowner/testrepo/pull/101",
			"created_at": time.Now().Format(time.RFC3339),
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	result, err := engine.CreatePullRequest(context.Background(), &gitops.PullRequest{
		RepoOwner:  "testowner",
		RepoName:   "testrepo",
		BaseBranch: "main",
		HeadBranch: branch,
		Files:      []gitops.FileChange{{Path: "a.yaml", Content: "x", Operation: gitops.FileOpUpdate}},
	})
	if err != nil {
		t.Fatalf("CreatePullRequest failed: %v", err)
	}
	if result == nil || result.Number != 101 {
		t.Fatalf("expected new PR #101 (fork PR must NOT match), got %+v", result)
	}
	if putFileCalls != 1 {
		t.Errorf("expected commit to proceed when only a fork PR exists — got %d PUT calls", putFileCalls)
	}
	if openPRCalls != 1 {
		t.Errorf("expected openPR to run when only a fork PR exists — got %d POST /pulls calls", openPRCalls)
	}
}

// TestGitHubEngine_CreatePullRequest_BranchExistsLookupFails asserts we
// fail closed when the dedup lookup itself errors. Proceeding blindly
// after a failed lookup is how the 311-commits bug used to manifest;
// better to surface a transient error and retry next cycle than to
// pollute an open PR with duplicate commits.
func TestGitHubEngine_CreatePullRequest_BranchExistsLookupFails(t *testing.T) {
	var putFileCalls, openPRCalls int

	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/testowner/testrepo/git/ref/heads/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"object": map[string]string{"sha": "basesha"}})
	})
	mux.HandleFunc("POST /repos/testowner/testrepo/git/refs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"Reference already exists"}`))
	})
	// Lookup returns 500 — simulated GitHub transient error.
	mux.HandleFunc("GET /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"upstream error"}`))
	})
	mux.HandleFunc("PUT /repos/testowner/testrepo/contents/", func(w http.ResponseWriter, _ *http.Request) {
		putFileCalls++
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		openPRCalls++
		w.WriteHeader(http.StatusCreated)
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	_, err := engine.CreatePullRequest(context.Background(), &gitops.PullRequest{
		RepoOwner:  "testowner",
		RepoName:   "testrepo",
		BaseBranch: "main",
		HeadBranch: "zelyo-operator/fix/lookup-fails",
		Files:      []gitops.FileChange{{Path: "a.yaml", Content: "x", Operation: gitops.FileOpUpdate}},
	})
	if err == nil {
		t.Fatal("expected error when dedup lookup fails; got nil")
	}
	if putFileCalls != 0 {
		t.Errorf("must not commit files when lookup fails — got %d PUT calls", putFileCalls)
	}
	if openPRCalls != 0 {
		t.Errorf("must not open PR when lookup fails — got %d POST /pulls calls", openPRCalls)
	}
}

func TestGitHubEngine_ListOpenPRs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/testowner/testrepo/pulls", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{ //nolint:errcheck
			{
				"number":     1,
				"html_url":   "https://github.com/testowner/testrepo/pull/1",
				"head":       map[string]string{"ref": "zelyo-operator/fix-something"},
				"created_at": time.Now().Format(time.RFC3339),
				"labels":     []map[string]string{{"name": "zelyo-operator"}},
			},
			{
				"number":     2,
				"html_url":   "https://github.com/testowner/testrepo/pull/2",
				"head":       map[string]string{"ref": "feature/unrelated"},
				"created_at": time.Now().Format(time.RFC3339),
				"labels":     []map[string]string{},
			},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	prs, err := engine.ListOpenPRs(context.Background(), "testowner", "testrepo")
	if err != nil {
		t.Fatalf("ListOpenPRs failed: %v", err)
	}

	// Only 1 should match — the zelyo-operator/fix-something branch.
	if len(prs) != 1 {
		t.Fatalf("Expected 1 Zelyo Operator PR, got %d", len(prs))
	}
	if prs[0].Number != 1 {
		t.Errorf("Expected PR #1, got #%d", prs[0].Number)
	}
}

// TestGitHubEngine_ListOpenPRs_Paginates asserts that ListOpenPRs walks
// successive pages until a short page arrives. Without pagination, the
// maxConcurrentPRs cap silently under-counts once a repo has >100 open
// Zelyo PRs — letting the controller exceed the cap. This guards against
// regressing to single-page behavior.
func TestGitHubEngine_ListOpenPRs_Paginates(t *testing.T) {
	mux := http.NewServeMux()
	var requests []string

	// Pages: 100, 100, 37. 237 PRs total, all Zelyo-branched.
	pages := [][]map[string]interface{}{
		makePRPage(1, 100),
		makePRPage(101, 100),
		makePRPage(201, 37),
	}

	mux.HandleFunc("GET /repos/o/r/pulls", func(w http.ResponseWriter, req *http.Request) {
		requests = append(requests, req.URL.RawQuery)
		pageParam := req.URL.Query().Get("page")
		idx := 0
		if pageParam != "" {
			fmt.Sscanf(pageParam, "%d", &idx) //nolint:errcheck
			idx--
		}
		if idx < 0 || idx >= len(pages) {
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pages[idx])
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	prs, err := engine.ListOpenPRs(context.Background(), "o", "r")
	if err != nil {
		t.Fatalf("ListOpenPRs failed: %v", err)
	}
	if len(prs) != 237 {
		t.Fatalf("expected 237 PRs after paginating 3 pages, got %d", len(prs))
	}
	if got, want := len(requests), 3; got != want {
		t.Errorf("expected %d HTTP calls (one per page), got %d (%v)", want, got, requests)
	}
}

// TestGitHubEngine_ListOpenPRs_PageCap asserts we stop after the safety
// cap when the provider keeps returning full pages forever. Without the
// cap a misbehaving provider could hang the controller indefinitely.
func TestGitHubEngine_ListOpenPRs_PageCap(t *testing.T) {
	mux := http.NewServeMux()
	var requests int

	mux.HandleFunc("GET /repos/o/r/pulls", func(w http.ResponseWriter, req *http.Request) {
		requests++
		page := 1
		if p := req.URL.Query().Get("page"); p != "" {
			fmt.Sscanf(p, "%d", &page) //nolint:errcheck
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(makePRPage((page-1)*100+1, 100))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	prs, err := engine.ListOpenPRs(context.Background(), "o", "r")
	if err != nil {
		t.Fatalf("ListOpenPRs failed: %v", err)
	}
	if requests != listOpenPRsMaxPages {
		t.Errorf("expected exactly %d HTTP calls at the page cap, got %d", listOpenPRsMaxPages, requests)
	}
	if got, want := len(prs), listOpenPRsMaxPages*listOpenPRsPageSize; got != want {
		t.Errorf("expected %d PRs at the page cap, got %d", want, got)
	}
}

func makePRPage(startNum, count int) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, count)
	for i := 0; i < count; i++ {
		n := startNum + i
		out = append(out, map[string]interface{}{
			"number":     n,
			"html_url":   fmt.Sprintf("https://github.com/o/r/pull/%d", n),
			"head":       map[string]string{"ref": fmt.Sprintf("zelyo-operator/fix-%d", n)},
			"created_at": time.Now().Format(time.RFC3339),
			"labels":     []map[string]string{},
		})
	}
	return out
}

func TestGitHubEngine_GetFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/testowner/testrepo/contents/k8s/deployment.yaml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// "apiVersion: apps/v1" in base64.
		json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
			"content":  "YXBpVmVyc2lvbjogYXBwcy92MQ==",
			"encoding": "base64",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	content, err := engine.GetFile(context.Background(), "testowner", "testrepo", "k8s/deployment.yaml", "main")
	if err != nil {
		t.Fatalf("GetFile failed: %v", err)
	}

	if string(content) != "apiVersion: apps/v1" {
		t.Errorf("Unexpected content: %q", string(content))
	}
}

func TestGitHubEngine_ErrorHandling(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"message":"Internal Server Error"}`)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	_, err := engine.GetFile(context.Background(), "o", "r", "f", "main")
	if err == nil {
		t.Fatal("Expected error for 500 response")
	}
}

// TestGitHubEngine_APIErrorTypedUnwrap pins the APIError contract. Callers
// (createRef's 422-on-branch-exists check) rely on errors.As — not string
// matching — to branch on HTTP status codes. A refactor that swallows the
// typed error inside an untyped wrap would silently break CreatePullRequest's
// dedup path; this test catches that.
func TestGitHubEngine_APIErrorTypedUnwrap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		fmt.Fprint(w, `{"message":"Reference already exists"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	engine := &GitHubEngine{
		http:    server.Client(),
		log:     logr.Discard(),
		baseURL: server.URL,
	}

	// doRequest returns APIError directly; callers that wrap with %w
	// must preserve it reachable via errors.As.
	wrapped := fmt.Errorf("outer context: %w", &APIError{StatusCode: 422, Body: "x"})

	var apiErr *APIError
	if !errors.As(wrapped, &apiErr) {
		t.Fatal("errors.As must unwrap APIError through %w-wrapped errors")
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected StatusCode %d, got %d", http.StatusUnprocessableEntity, apiErr.StatusCode)
	}

	// Also verify the live path from doRequest returns APIError on 4xx.
	_, liveErr := engine.GetFile(context.Background(), "o", "r", "f", "main")
	if liveErr == nil {
		t.Fatal("expected error from 422 response")
	}
	var liveAPIErr *APIError
	if !errors.As(liveErr, &liveAPIErr) {
		t.Fatalf("expected live doRequest error to be APIError-typed, got %T: %v", liveErr, liveErr)
	}
	if liveAPIErr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected StatusCode 422, got %d", liveAPIErr.StatusCode)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"a long string that needs truncating", 10, "a long str..."},
		{"exact", 5, "exact"},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}
