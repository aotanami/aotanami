/*
Copyright 2026 Zelyo AI
*/

package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/events"
)

// mockPRCounter is a monotonically increasing suffix seeded from the
// process start time. Paired with the per-call PR base, it gives every
// generated URL a unique integer even when called many times per second.
//
//nolint:gochecknoglobals // demo-only monotonic counter, intentional.
var mockPRCounter atomic.Int64

// dispatchPresetRoute routes /api/v1/presets/{id}[/propose|/apply|/status]
// to the matching handler. Go's stdlib mux doesn't support path params, so
// we dispatch by suffix here.
func (s *Server) dispatchPresetRoute(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	// Normalise against basePath so the suffix checks work regardless of
	// where the dashboard is mounted.
	if idx := strings.Index(path, "/api/v1/presets/"); idx >= 0 {
		path = path[idx:]
	}

	switch {
	case strings.HasSuffix(path, "/propose"):
		s.handlePresetPropose(w, r)
	case strings.HasSuffix(path, "/apply"):
		s.handlePresetApply(w, r)
	case strings.HasSuffix(path, "/status"):
		s.handlePresetStatus(w, r)
	default:
		s.handlePresetPreview(w, r)
	}
}

// handlePresets serves the preset catalog joined with per-preset runtime
// state (not_enabled / proposing / pending_merge / enabled) plus cluster
// config capabilities so the UI can pick the right default action.
func (s *Server) handlePresets(w http.ResponseWriter, r *http.Request) {
	store := DefaultPresetStore()
	presets := Presets()
	views := make([]PresetView, 0, len(presets))
	for i := range presets {
		views = append(views, PresetView{
			Preset: presets[i],
			Status: *store.get(presets[i].ID),
		})
	}
	s.writeJSON(w, map[string]interface{}{
		"presets": views,
		"config":  s.resolveConfigStatus(r.Context()),
	})
}

// resolveConfigStatus returns the cluster config snapshot the UI renders,
// deriving GitOpsConfigured/GitOpsRepo live from GitOpsRepositoryList so
// the Compliance badge reflects actual cluster state instead of a cached
// demo default. SealedSecretsReady and DemoMode still come from the store.
func (s *Server) resolveConfigStatus(ctx context.Context) ConfigStatus {
	cfg := DefaultPresetStore().ConfigStatus()
	if s.client == nil {
		return cfg
	}
	repos := &zelyov1alpha1.GitOpsRepositoryList{}
	if err := s.client.List(ctx, repos, &client.ListOptions{Limit: 5}); err != nil {
		// A List error is not necessarily "not configured" — surface it in
		// logs but don't flip the badge, so a transient API hiccup doesn't
		// flicker the UI from connected → disconnected.
		s.log.V(1).Info("listing GitOpsRepositories for config status", "error", err.Error())
		return cfg
	}
	if len(repos.Items) == 0 {
		// Live state is the source of truth. If the list is empty, the
		// badge must read "not connected" even if the store snapshot
		// (SetConfigStatus, or any future seed) carried stale values.
		cfg.GitOpsConfigured = false
		cfg.GitOpsRepo = ""
		return cfg
	}
	cfg.GitOpsConfigured = true
	cfg.GitOpsRepo = displayRepoSlug(&repos.Items[0])
	return cfg
}

// displayRepoSlug returns a short "owner/repo" style identifier for the
// Compliance badge. Falls back to the CR name if the URL can't be parsed.
func displayRepoSlug(repo *zelyov1alpha1.GitOpsRepository) string {
	url := strings.TrimSpace(repo.Spec.URL)
	url = strings.TrimSuffix(url, ".git")
	// Strip scheme://host/ or user@host: prefixes to land on the path segment.
	if i := strings.Index(url, "://"); i >= 0 {
		rest := url[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			url = rest[j+1:]
		}
	}
	if i := strings.LastIndex(url, ":"); i >= 0 && strings.Contains(url[:i], "@") {
		url = url[i+1:]
	}
	if url == "" {
		return repo.Name
	}
	return url
}

// handlePresetPreview returns the preset + rendered unified diff so the
// drawer can show exactly what will be committed or applied.
func (s *Server) handlePresetPreview(w http.ResponseWriter, r *http.Request) {
	id := presetIDFromPath(r.URL.Path, "/api/v1/presets/")
	if !validPresetID(id) {
		s.writeError(w, http.StatusBadRequest, "invalid preset id")
		return
	}
	p := FindPreset(id)
	if p == nil {
		s.writeError(w, http.StatusNotFound, "preset not found")
		return
	}
	s.writeJSON(w, map[string]interface{}{
		"preset": p,
		"diff":   BuildDiff(p),
	})
}

// handlePresetPropose initiates a GitOps PR for the preset.
func (s *Server) handlePresetPropose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := presetIDFromPath(r.URL.Path, "/api/v1/presets/")
	id = strings.TrimSuffix(id, "/propose")
	if !validPresetID(id) {
		s.writeError(w, http.StatusBadRequest, "invalid preset id")
		return
	}
	p := FindPreset(id)
	if p == nil {
		s.writeError(w, http.StatusNotFound, "preset not found")
		return
	}

	store := DefaultPresetStore()
	cfg := s.resolveConfigStatus(r.Context())
	if !cfg.GitOpsConfigured {
		s.writeError(w, http.StatusPreconditionFailed, "no GitOps repository configured — use /apply instead or connect a repo")
		return
	}

	// Idempotency: if a PR is already in flight or the preset is enabled,
	// return the existing status rather than drafting another PR and
	// stacking a second demoAdvancePreset goroutine. Double-clicks, retries,
	// and page refreshes should all be safe.
	if existing := store.get(p.ID); existing != nil {
		switch existing.State {
		case PresetStateProposing, PresetStatePendingMerge, PresetStateEnabled:
			s.writeJSON(w, map[string]interface{}{
				"status": existing,
				"prUrl":  existing.PRURL,
			})
			return
		}
	}

	prURL := mockPRURL(p.ID, cfg.GitOpsRepo)
	now := time.Now().UTC()

	// Populate the remediation store so clicking the PR card in the Pipeline
	// opens the same Before/Diff/After panel used for AI remediations.
	items := make([]events.RemediationItem, 0, len(p.Files))
	for _, f := range p.Files {
		items = append(items, events.RemediationItem{
			ResourceKey: f.Path,
			Resource:    f.Path,
			Rule:        "config-preset",
			Severity:    "Policy",
			Title:       fmt.Sprintf("Create %s", f.Path),
		})
	}
	events.DefaultRemediationStore().Upsert(&events.RemediationContext{
		ScanRef:      p.ID,
		Namespace:    "zelyo-system",
		Repo:         cfg.GitOpsRepo,
		PRURL:        prURL,
		Summary:      p.Name,
		Findings:     items,
		Diff:         BuildDiff(p),
		FilesChanged: filePaths(p.Files),
	})

	// Flip local state and fire pipeline events. Do the full
	// Proposing → PendingMerge transition BEFORE spawning the demo
	// goroutine so the goroutine's later "merged → enabled" writes can't
	// race with this handler's sequential updates.
	store.update(p.ID, func(st *PresetStatus) {
		st.State = PresetStateProposing
		t := now
		st.ProposedAt = &t
		st.PRURL = prURL
		st.Message = "Drafting PR…"
	})
	status := store.update(p.ID, func(st *PresetStatus) {
		st.State = PresetStatePendingMerge
		st.Message = "Waiting for PR review"
	})

	events.EmitConfigPRDrafted(p.Name, prURL, cfg.GitOpsRepo, p.Description, len(p.Files))
	events.EmitPullRequestOpened(prURL, cfg.GitOpsRepo, len(p.Files))

	// In demo mode: auto-merge after a short delay so the Pipeline visibly
	// progresses through open → merged → enabled without human action.
	// Use the server's long-lived context (not the per-request one, which
	// dies when the client disconnects) so the goroutine exits cleanly on
	// server shutdown instead of mutating shared state into a race.
	if cfg.DemoMode {
		go s.demoAdvancePreset(s.backgroundContext(), p, prURL, cfg.GitOpsRepo)
	}

	s.writeJSON(w, map[string]interface{}{
		"status": status,
		"prUrl":  prURL,
	})
}

// handlePresetApply applies the preset directly without a PR (bootstrap
// path / no-GitOps-repo fallback). Fires a config.applied event that lands
// in the Fix stage with a warning-level badge.
func (s *Server) handlePresetApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := presetIDFromPath(r.URL.Path, "/api/v1/presets/")
	id = strings.TrimSuffix(id, "/apply")
	if !validPresetID(id) {
		s.writeError(w, http.StatusBadRequest, "invalid preset id")
		return
	}
	p := FindPreset(id)
	if p == nil {
		s.writeError(w, http.StatusNotFound, "preset not found")
		return
	}

	store := DefaultPresetStore()
	now := time.Now().UTC()
	status := store.update(p.ID, func(st *PresetStatus) {
		st.State = PresetStateEnabled
		st.EnabledAt = &now
		st.PRURL = ""
		st.Message = "Applied directly to cluster"
	})
	events.EmitConfigApplied(p.Name, p.Description, len(p.Files))

	s.writeJSON(w, map[string]interface{}{"status": status})
}

// handlePresetStatus returns the current status for a preset — used by the
// drawer to live-poll while a PR is in flight without waiting for SSE.
func (s *Server) handlePresetStatus(w http.ResponseWriter, r *http.Request) {
	id := presetIDFromPath(r.URL.Path, "/api/v1/presets/")
	id = strings.TrimSuffix(id, "/status")
	if !validPresetID(id) {
		s.writeError(w, http.StatusBadRequest, "invalid preset id")
		return
	}
	if FindPreset(id) == nil {
		s.writeError(w, http.StatusNotFound, "preset not found")
		return
	}
	s.writeJSON(w, DefaultPresetStore().get(id))
}

// demoAdvancePreset simulates the PR lifecycle in demo mode: merge after
// ~3s, then mark the preset enabled after a short "sync" delay. Real
// deployments never call this — the controller that watches PR state does.
//
// ctx lets the goroutine exit cleanly on server shutdown instead of
// continuing to mutate shared state after the process has started to
// unwind. repo is captured at propose time so the EmitPullRequestMerged
// label stays consistent even if the live ConfigStatus changes mid-flight.
func (s *Server) demoAdvancePreset(ctx context.Context, p *Preset, prURL, repo string) {
	//nolint:gosec // cadence jitter only, non-cryptographic.
	rng := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(len(p.ID))))

	if !sleepCtx(ctx, time.Duration(2800+rng.Intn(1200))*time.Millisecond) {
		return
	}
	events.DefaultRemediationStore().MarkMerged(prURL, time.Now().UTC())
	events.EmitPullRequestMerged(prURL, repo)

	if !sleepCtx(ctx, 1400*time.Millisecond) {
		return
	}
	enabledAt := time.Now().UTC()
	DefaultPresetStore().update(p.ID, func(st *PresetStatus) {
		st.State = PresetStateEnabled
		st.EnabledAt = &enabledAt
		st.Message = "GitOps sync complete"
	})

	// Mark each file "resolved" so the After section in the side panel
	// flips green just like for AI remediations.
	for _, f := range p.Files {
		events.DefaultRemediationStore().MarkResolved(f.Path, time.Now().UTC())
		if !sleepCtx(ctx, 200*time.Millisecond) {
			return
		}
	}
}

// sleepCtx sleeps for d or returns false if ctx is canceled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// ---- helpers -------------------------------------------------------------

// presetIDFromPath extracts the path after the "/api/v1/presets/" prefix,
// tolerant of any base-path mount (e.g. /dashboard/api/v1/presets/<id>).
// Callers strip trailing action suffixes (/propose, /apply, /status).
func presetIDFromPath(path, _ string) string {
	const marker = "/api/v1/presets/"
	if idx := strings.Index(path, marker); idx >= 0 {
		return path[idx+len(marker):]
	}
	return ""
}

// validPresetID enforces the catalog's own ID shape (lowercase letters,
// digits, dashes, 1–64 chars). This keeps untrusted path input out of the
// preset catalog lookup, the remediation store key space, and any
// downstream logging that echoes the ID back.
func validPresetID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-':
		default:
			return false
		}
	}
	return true
}

// mockPRURL returns a collision-resistant demo PR URL. The PR number is
// built from an atomic process counter offset by the current second, so
// two near-simultaneous calls (double-click retries, synthesizer bursts,
// etc.) never produce the same URL for the same repo. The previous
// implementation cycled through 800 values once per second and was
// prone to collisions which overwrote remediation contexts.
func mockPRURL(_, repo string) string {
	base := time.Now().Unix() % 100_000 // 5-digit realistic-looking base
	suffix := mockPRCounter.Add(1)
	n := base*1000 + (suffix % 1000)
	return fmt.Sprintf("https://github.com/%s/pull/%d", repo, n)
}

func filePaths(files []PresetFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

// MustEncodePreset is used in tests.
func MustEncodePreset(p *Preset) string {
	b, _ := json.Marshal(p)
	return string(b)
}
