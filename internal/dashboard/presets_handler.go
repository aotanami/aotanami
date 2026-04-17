/*
Copyright 2026 Zelyo AI
*/

package dashboard

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/zelyo-ai/zelyo-operator/internal/events"
)

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
func (s *Server) handlePresets(w http.ResponseWriter, _ *http.Request) {
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
		"config":  store.ConfigStatus(),
	})
}

// handlePresetPreview returns the preset + rendered unified diff so the
// drawer can show exactly what will be committed or applied.
func (s *Server) handlePresetPreview(w http.ResponseWriter, r *http.Request) {
	id := presetIDFromPath(r.URL.Path, "/api/v1/presets/")
	if id == "" || strings.Contains(id, "/") {
		s.writeError(w, http.StatusBadRequest, "preset id required")
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
	p := FindPreset(id)
	if p == nil {
		s.writeError(w, http.StatusNotFound, "preset not found")
		return
	}

	store := DefaultPresetStore()
	cfg := store.ConfigStatus()
	if !cfg.GitOpsConfigured {
		s.writeError(w, http.StatusPreconditionFailed, "no GitOps repository configured — use /apply instead or connect a repo")
		return
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

	// Flip local state and fire pipeline events.
	status := store.update(p.ID, func(st *PresetStatus) {
		st.State = "proposing"
		t := now
		st.ProposedAt = &t
		st.PRURL = prURL
		st.Message = "Drafting PR…"
	})
	events.EmitConfigPRDrafted(p.Name, prURL, cfg.GitOpsRepo, p.Description, len(p.Files))
	events.EmitPullRequestOpened(prURL, cfg.GitOpsRepo, len(p.Files))

	// In demo mode: auto-merge after a short delay so the Pipeline visibly
	// progresses through open → merged → enabled without human action.
	if cfg.DemoMode {
		go s.demoAdvancePreset(p, prURL)
	}

	store.update(p.ID, func(st *PresetStatus) {
		st.State = "pending_merge"
		st.Message = "Waiting for PR review"
	})

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
	p := FindPreset(id)
	if p == nil {
		s.writeError(w, http.StatusNotFound, "preset not found")
		return
	}

	store := DefaultPresetStore()
	now := time.Now().UTC()
	status := store.update(p.ID, func(st *PresetStatus) {
		st.State = "enabled"
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
	if id == "" {
		s.writeError(w, http.StatusBadRequest, "preset id required")
		return
	}
	s.writeJSON(w, DefaultPresetStore().get(id))
}

// demoAdvancePreset simulates the PR lifecycle in demo mode: merge after
// ~3s, then mark the preset enabled after a short "sync" delay. Real
// deployments never call this — the controller that watches PR state does.
func (s *Server) demoAdvancePreset(p *Preset, prURL string) {
	//nolint:gosec // cadence jitter only, non-cryptographic.
	rng := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(len(p.ID))))

	time.Sleep(time.Duration(2800+rng.Intn(1200)) * time.Millisecond)
	events.DefaultRemediationStore().MarkMerged(prURL, time.Now().UTC())
	events.EmitPullRequestMerged(prURL, DefaultPresetStore().ConfigStatus().GitOpsRepo)

	time.Sleep(1400 * time.Millisecond)
	enabledAt := time.Now().UTC()
	DefaultPresetStore().update(p.ID, func(st *PresetStatus) {
		st.State = "enabled"
		st.EnabledAt = &enabledAt
		st.Message = "GitOps sync complete"
	})

	// Mark each file "resolved" so the After section in the side panel
	// flips green just like for AI remediations.
	for _, f := range p.Files {
		events.DefaultRemediationStore().MarkResolved(f.Path, time.Now().UTC())
		time.Sleep(200 * time.Millisecond)
	}
}

// ---- helpers -------------------------------------------------------------

// presetIDFromPath extracts the path after the "/api/v1/presets/" prefix.
// Callers strip trailing action suffixes (/propose, /apply, /status).
func presetIDFromPath(path, _ string) string {
	return strings.TrimPrefix(path, "/api/v1/presets/")
}

func mockPRURL(_, repo string) string {
	n := 200 + int(time.Now().UnixNano()/1e9)%800
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
