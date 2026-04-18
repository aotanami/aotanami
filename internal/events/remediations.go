/*
Copyright 2026 Zelyo AI
*/

package events

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// RemediationContext is the full before/after story for a single remediation
// proposal: which findings were surfaced, what diff the engine drafted, the
// resulting PR URL, and which findings a follow-up re-scan has since
// confirmed resolved.
//
// It is keyed by PR URL in the store because that is the one identifier the
// dashboard clicks through on. Real remediation engines populate this via
// Upsert* helpers below; the demo synthesizer does the same so the frontend
// code path is identical in both modes.
type RemediationContext struct {
	Key          string              `json:"key"`
	ScanRef      string              `json:"scanRef"`
	Namespace    string              `json:"namespace"`
	Repo         string              `json:"repo,omitempty"`
	PRURL        string              `json:"prUrl,omitempty"`
	Summary      string              `json:"summary,omitempty"`
	CreatedAt    time.Time           `json:"createdAt"`
	MergedAt     *time.Time          `json:"mergedAt,omitempty"`
	Findings     []RemediationItem   `json:"findings"`
	Diff         string              `json:"diff"`
	FilesChanged []string            `json:"filesChanged,omitempty"`
	ResolvedKeys map[string]struct{} `json:"-"`
}

// RemediationItem describes a single finding that feeds into a remediation
// proposal. "ResourceKey" is a stable identifier (Kind/Namespace/Name) the
// store uses to reconcile with subsequent `finding.resolved` events.
type RemediationItem struct {
	ResourceKey string `json:"resourceKey"`
	Resource    string `json:"resource"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Resolved    bool   `json:"resolved"`
	ResolvedAt  string `json:"resolvedAt,omitempty"`
}

// remediationStore is an in-process registry of live remediation contexts.
// We key on PR URL for lookup and also carry a per-scan index so
// finding.resolved events (which carry a scan name) can find the right
// context to update.
//
// The store is bounded by `capacity` — when full, the oldest remediation
// (by CreatedAt) is evicted. That keeps long-running operators from
// growing memory indefinitely. Zero / negative means unbounded.
type remediationStore struct {
	mu             sync.RWMutex
	byKey          map[string]*RemediationContext
	scanToKeys     map[string][]string
	resourceToKeys map[string][]string
	capacity       int
}

const defaultRemediationCapacity = 500

var defaultStore = &remediationStore{
	byKey:          map[string]*RemediationContext{},
	scanToKeys:     map[string][]string{},
	resourceToKeys: map[string][]string{},
	capacity:       defaultRemediationCapacity,
}

// RemediationStore is the public type used by callers; the underlying
// storage is unexported to force construction through DefaultRemediationStore.
type RemediationStore = remediationStore

// DefaultRemediationStore exposes the package store for the dashboard.
func DefaultRemediationStore() *RemediationStore {
	return defaultStore
}

// Upsert records or merges a remediation context. A deep copy of ctx is
// stored so the caller can continue to mutate the argument after return
// without racing with the store's readers.
func (s *remediationStore) Upsert(ctx *RemediationContext) {
	if ctx == nil || ctx.PRURL == "" {
		return
	}
	stored := copyCtx(ctx)
	stored.Key = stored.PRURL
	if stored.ResolvedKeys == nil {
		stored.ResolvedKeys = map[string]struct{}{}
	}
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// If this PR was upserted before, drop its old index references first
	// so a re-upsert with a different ScanRef / Findings doesn't leave
	// stale keys in scanToKeys / resourceToKeys.
	if _, exists := s.byKey[stored.Key]; exists {
		s.removeLocked(stored.Key)
	}

	s.byKey[stored.Key] = stored
	if stored.ScanRef != "" {
		s.scanToKeys[stored.ScanRef] = appendUnique(s.scanToKeys[stored.ScanRef], stored.Key)
	}
	for i := range stored.Findings {
		rk := stored.Findings[i].ResourceKey
		if rk == "" {
			continue
		}
		s.resourceToKeys[rk] = appendUnique(s.resourceToKeys[rk], stored.Key)
	}
	s.evictIfOverCapacity()
}

// evictIfOverCapacity drops the oldest entries (by CreatedAt) while the
// store exceeds its capacity. Called under the write lock.
func (s *remediationStore) evictIfOverCapacity() {
	if s.capacity <= 0 || len(s.byKey) <= s.capacity {
		return
	}
	keys := make([]string, 0, len(s.byKey))
	for k := range s.byKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return s.byKey[keys[i]].CreatedAt.Before(s.byKey[keys[j]].CreatedAt)
	})
	drop := len(s.byKey) - s.capacity
	for i := 0; i < drop && i < len(keys); i++ {
		s.removeLocked(keys[i])
	}
}

// removeLocked unindexes and deletes a key. Must be called under the write lock.
func (s *remediationStore) removeLocked(key string) {
	ctx, ok := s.byKey[key]
	if !ok {
		return
	}
	delete(s.byKey, key)
	if ctx.ScanRef != "" {
		s.scanToKeys[ctx.ScanRef] = removeString(s.scanToKeys[ctx.ScanRef], key)
		if len(s.scanToKeys[ctx.ScanRef]) == 0 {
			delete(s.scanToKeys, ctx.ScanRef)
		}
	}
	for i := range ctx.Findings {
		rk := ctx.Findings[i].ResourceKey
		if rk == "" {
			continue
		}
		s.resourceToKeys[rk] = removeString(s.resourceToKeys[rk], key)
		if len(s.resourceToKeys[rk]) == 0 {
			delete(s.resourceToKeys, rk)
		}
	}
}

func removeString(in []string, v string) []string {
	for i, s := range in {
		if s == v {
			return append(in[:i], in[i+1:]...)
		}
	}
	return in
}

// Get returns a copy of the context for the given key, or nil.
func (s *remediationStore) Get(key string) *RemediationContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.byKey[key]
	if !ok {
		return nil
	}
	return copyCtx(v)
}

// List returns a snapshot of all remediations, newest first.
func (s *remediationStore) List(limit int) []RemediationContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RemediationContext, 0, len(s.byKey))
	for _, v := range s.byKey {
		out = append(out, *copyCtx(v))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// MarkMerged records the merge time for the matching remediation, if any.
func (s *remediationStore) MarkMerged(prURL string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.byKey[prURL]; ok {
		v.MergedAt = &at
	}
}

// MarkResolved flips the `Resolved` flag on any remediation item that
// references the given resource. A single resolved finding may update
// multiple remediations (e.g. when they share a resource).
func (s *remediationStore) MarkResolved(resourceKey string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys, ok := s.resourceToKeys[resourceKey]
	if !ok {
		return
	}
	stamp := at.UTC().Format(time.RFC3339)
	for _, k := range keys {
		ctx, ok := s.byKey[k]
		if !ok {
			continue
		}
		ctx.ResolvedKeys[resourceKey] = struct{}{}
		for i := range ctx.Findings {
			if ctx.Findings[i].ResourceKey == resourceKey && !ctx.Findings[i].Resolved {
				ctx.Findings[i].Resolved = true
				ctx.Findings[i].ResolvedAt = stamp
			}
		}
	}
}

// ---- helpers ----------------------------------------------------------------

func appendUnique(in []string, v string) []string {
	for _, s := range in {
		if s == v {
			return in
		}
	}
	return append(in, v)
}

func copyCtx(v *RemediationContext) *RemediationContext {
	out := *v
	if v.MergedAt != nil {
		mergedAt := *v.MergedAt
		out.MergedAt = &mergedAt
	}
	out.Findings = append([]RemediationItem(nil), v.Findings...)
	out.FilesChanged = append([]string(nil), v.FilesChanged...)
	out.ResolvedKeys = map[string]struct{}{}
	for k := range v.ResolvedKeys {
		out.ResolvedKeys[k] = struct{}{}
	}
	return &out
}

// ResourceKey builds the canonical identifier used both by scanners and
// remediations. Centralizing the format keeps lookups consistent.
func ResourceKey(kind, namespace, name string) string {
	parts := []string{kind, namespace, name}
	return strings.Join(parts, "/")
}
