/*
Copyright 2026 Zelyo AI
*/

package events

import (
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
type remediationStore struct {
	mu             sync.RWMutex
	byKey          map[string]*RemediationContext
	scanToKeys     map[string][]string
	resourceToKeys map[string][]string
}

var defaultStore = &remediationStore{
	byKey:          map[string]*RemediationContext{},
	scanToKeys:     map[string][]string{},
	resourceToKeys: map[string][]string{},
}

// RemediationStore is the public type used by callers; the underlying
// storage is unexported to force construction through DefaultRemediationStore.
type RemediationStore = remediationStore

// DefaultRemediationStore exposes the package store for the dashboard.
func DefaultRemediationStore() *RemediationStore {
	return defaultStore
}

// Upsert records or merges a remediation context. Called by the
// demo synthesizer (and, eventually, the real remediation engine) when a PR
// is about to be opened.
func (s *remediationStore) Upsert(ctx *RemediationContext) {
	if ctx == nil || ctx.PRURL == "" {
		return
	}
	ctx.Key = ctx.PRURL
	if ctx.ResolvedKeys == nil {
		ctx.ResolvedKeys = map[string]struct{}{}
	}
	if ctx.CreatedAt.IsZero() {
		ctx.CreatedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.byKey[ctx.Key] = ctx
	if ctx.ScanRef != "" {
		s.scanToKeys[ctx.ScanRef] = appendUnique(s.scanToKeys[ctx.ScanRef], ctx.Key)
	}
	for i := range ctx.Findings {
		rk := ctx.Findings[i].ResourceKey
		if rk == "" {
			continue
		}
		s.resourceToKeys[rk] = appendUnique(s.resourceToKeys[rk], ctx.Key)
	}
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
	// Newest first by CreatedAt.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.After(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
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
