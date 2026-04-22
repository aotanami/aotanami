/*
Copyright 2026 Zelyo AI
*/

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
