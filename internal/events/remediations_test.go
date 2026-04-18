/*
Copyright 2026 Zelyo AI
*/

package events

import (
	"sync"
	"testing"
	"time"
)

func newTestStore(capacity int) *remediationStore {
	return &remediationStore{
		byKey:          map[string]*RemediationContext{},
		scanToKeys:     map[string][]string{},
		resourceToKeys: map[string][]string{},
		capacity:       capacity,
	}
}

func TestRemediationStore_UpsertAndGet(t *testing.T) {
	s := newTestStore(10)
	ctx := &RemediationContext{
		ScanRef: "payments-hourly",
		PRURL:   "https://github.com/acme/repo/pull/1",
		Summary: "Drop privileged",
		Findings: []RemediationItem{
			{ResourceKey: "Pod/ns/a", Resource: "Pod/ns/a", Rule: "privileged", Severity: "Critical"},
		},
	}
	s.Upsert(ctx)

	got := s.Get(ctx.PRURL)
	if got == nil {
		t.Fatal("Get returned nil for known key")
	}
	if got.Key != ctx.PRURL {
		t.Errorf("Key = %q, want %q", got.Key, ctx.PRURL)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be defaulted by Upsert")
	}
}

func TestRemediationStore_UpsertDefensivelyCopiesInput(t *testing.T) {
	s := newTestStore(10)
	ctx := &RemediationContext{
		PRURL: "https://github.com/acme/repo/pull/2",
		Findings: []RemediationItem{
			{ResourceKey: "Pod/ns/x", Resource: "Pod/ns/x", Rule: "privileged"},
		},
		FilesChanged: []string{"a.yaml"},
	}
	s.Upsert(ctx)

	// Mutate the caller's copy after Upsert.
	ctx.Summary = "CHANGED AFTER UPSERT"
	ctx.Findings[0].Title = "CHANGED TITLE"
	ctx.FilesChanged[0] = "b.yaml"

	stored := s.Get("https://github.com/acme/repo/pull/2")
	if stored.Summary == "CHANGED AFTER UPSERT" {
		t.Error("store exposed the caller's RemediationContext — should have copied")
	}
	if stored.Findings[0].Title == "CHANGED TITLE" {
		t.Error("store exposed the caller's Findings slice — should have copied")
	}
	if stored.FilesChanged[0] == "b.yaml" {
		t.Error("store exposed the caller's FilesChanged slice — should have copied")
	}
}

func TestRemediationStore_GetReturnsCopy(t *testing.T) {
	s := newTestStore(10)
	s.Upsert(&RemediationContext{
		PRURL: "https://x/pull/1",
		Findings: []RemediationItem{
			{ResourceKey: "Pod/a", Resource: "Pod/a", Rule: "privileged"},
		},
	})

	a := s.Get("https://x/pull/1")
	a.Summary = "mutated by caller"
	a.Findings[0].Resolved = true

	b := s.Get("https://x/pull/1")
	if b.Summary == "mutated by caller" {
		t.Error("Get did not return a deep copy of Summary")
	}
	if b.Findings[0].Resolved {
		t.Error("Get did not return a deep copy of Findings")
	}
}

func TestRemediationStore_ListIsNewestFirst(t *testing.T) {
	s := newTestStore(10)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		s.Upsert(&RemediationContext{
			PRURL:     mkURL(i),
			CreatedAt: base.Add(time.Duration(i) * time.Hour),
		})
	}

	out := s.List(0)
	if len(out) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(out))
	}
	for i := 0; i < len(out)-1; i++ {
		if out[i].CreatedAt.Before(out[i+1].CreatedAt) {
			t.Errorf("List is not newest-first at index %d: %v before %v",
				i, out[i].CreatedAt, out[i+1].CreatedAt)
		}
	}
}

func TestRemediationStore_MarkMerged(t *testing.T) {
	s := newTestStore(10)
	s.Upsert(&RemediationContext{PRURL: "https://x/pull/1"})

	merged := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	s.MarkMerged("https://x/pull/1", merged)

	got := s.Get("https://x/pull/1")
	if got.MergedAt == nil || !got.MergedAt.Equal(merged) {
		t.Fatalf("MergedAt = %v, want %v", got.MergedAt, merged)
	}
}

func TestRemediationStore_MarkResolvedFlipsMatchingFindings(t *testing.T) {
	s := newTestStore(10)
	s.Upsert(&RemediationContext{
		PRURL: "https://x/pull/1",
		Findings: []RemediationItem{
			{ResourceKey: "Pod/ns/a", Rule: "privileged"},
			{ResourceKey: "Pod/ns/b", Rule: "privileged"},
		},
	})

	s.MarkResolved("Pod/ns/a", time.Now().UTC())

	got := s.Get("https://x/pull/1")
	if !got.Findings[0].Resolved {
		t.Error("Pod/ns/a should be resolved")
	}
	if got.Findings[1].Resolved {
		t.Error("Pod/ns/b should NOT be resolved")
	}
}

func TestRemediationStore_CapacityEvictsOldest(t *testing.T) {
	s := newTestStore(3)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		s.Upsert(&RemediationContext{
			PRURL:     mkURL(i),
			CreatedAt: base.Add(time.Duration(i) * time.Hour),
		})
	}

	out := s.List(0)
	if len(out) != 3 {
		t.Fatalf("expected 3 retained after eviction, got %d", len(out))
	}
	// The two oldest (index 0 and 1) should have been evicted.
	if got := s.Get(mkURL(0)); got != nil {
		t.Error("expected oldest entry evicted")
	}
	if got := s.Get(mkURL(4)); got == nil {
		t.Error("expected newest entry retained")
	}
}

func TestRemediationStore_UpsertNilAndEmptyIsNoop(t *testing.T) {
	s := newTestStore(10)
	s.Upsert(nil)
	s.Upsert(&RemediationContext{PRURL: ""})
	if len(s.List(0)) != 0 {
		t.Fatal("expected empty store after nil + empty-URL Upserts")
	}
}

func TestRemediationStore_ConcurrentUpsertAndRead(t *testing.T) {
	s := newTestStore(100)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				s.Upsert(&RemediationContext{
					PRURL: mkURL(i*50 + j),
					Findings: []RemediationItem{
						{ResourceKey: "Pod/ns/x", Rule: "privileged"},
					},
				})
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = s.List(10)
			}
		}()
	}
	wg.Wait()
}

func mkURL(i int) string {
	return "https://github.com/acme/repo/pull/" + itoa(i)
}

// Tiny in-package itoa to avoid importing strconv just for tests.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	buf := make([]byte, 0, 20)
	for i > 0 {
		buf = append([]byte{byte('0' + i%10)}, buf...)
		i /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
