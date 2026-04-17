/*
Copyright 2026 Zelyo AI
*/

package dashboard

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCannedExplainer_KnownRuleReturnsCuratedContent(t *testing.T) {
	e := &CannedExplainer{}
	for rule := range cannedContent {
		resp, err := e.Explain(context.Background(), &ExplainRequest{
			Rule:     rule,
			Severity: "Critical",
			Resource: "Pod/ns/x",
			Title:    "unit test",
		})
		if err != nil {
			t.Fatalf("rule %q: %v", rule, err)
		}
		if !strings.Contains(resp.Explanation, "What's wrong") {
			t.Fatalf("rule %q: expected curated section headers, got:\n%s", rule, resp.Explanation)
		}
		if resp.Source != "canned" {
			t.Fatalf("rule %q: expected source=canned, got %q", rule, resp.Source)
		}
	}
}

func TestCannedExplainer_UnknownRuleFallsBackBySeverity(t *testing.T) {
	e := &CannedExplainer{}
	cases := []string{"Critical", "High", "Medium", "Low", "UnknownSev"}
	for _, sev := range cases {
		resp, err := e.Explain(context.Background(), &ExplainRequest{
			Rule:     "totally-not-a-real-rule",
			Severity: sev,
			Resource: "Pod/ns/x",
			Title:    "t",
		})
		if err != nil {
			t.Fatalf("sev %q: %v", sev, err)
		}
		if resp.Explanation == "" {
			t.Fatalf("sev %q: empty explanation", sev)
		}
	}
}

func TestCachingExplainer_ServesCachedOnSecondCall(t *testing.T) {
	callCount := 0
	inner := funcExplainer(func(_ context.Context, _ *ExplainRequest) (*ExplainResponse, error) {
		callCount++
		return &ExplainResponse{Explanation: "x", Source: "canned"}, nil
	})
	c := NewCachingExplainer(inner, time.Minute)

	req := &ExplainRequest{Rule: "privileged", Severity: "Critical"}
	if _, err := c.Explain(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Explain(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	if callCount != 1 {
		t.Fatalf("expected inner explainer to be called exactly once (cache hit), got %d", callCount)
	}
	if resp.Source != "cache" {
		t.Fatalf("expected source=cache, got %q", resp.Source)
	}
}

func TestCachingExplainer_TTLExpiresEntry(t *testing.T) {
	inner := funcExplainer(func(_ context.Context, _ *ExplainRequest) (*ExplainResponse, error) {
		return &ExplainResponse{Explanation: "x", Source: "canned"}, nil
	})
	c := NewCachingExplainer(inner, 10*time.Millisecond)
	req := &ExplainRequest{Rule: "privileged", Severity: "Critical"}
	if _, err := c.Explain(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	resp, err := c.Explain(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Source == "cache" {
		t.Fatal("expected TTL to invalidate cache entry")
	}
}

type funcExplainer func(ctx context.Context, req *ExplainRequest) (*ExplainResponse, error)

func (f funcExplainer) Explain(ctx context.Context, req *ExplainRequest) (*ExplainResponse, error) {
	return f(ctx, req)
}
