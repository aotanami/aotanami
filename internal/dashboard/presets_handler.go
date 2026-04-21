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
	"os"
	pathpkg "path"
	"strings"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	zelyov1alpha1 "github.com/zelyo-ai/zelyo-operator/api/v1alpha1"
	"github.com/zelyo-ai/zelyo-operator/internal/events"
	"github.com/zelyo-ai/zelyo-operator/internal/github"
	"github.com/zelyo-ai/zelyo-operator/internal/gitops"
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

	now := time.Now().UTC()

	// Pick the real GitOpsRepository CR (we already know at least one exists
	// because resolveConfigStatus set GitOpsConfigured=true). The repo
	// carries the URL, auth Secret name, and the allowed path prefixes we
	// must honor when committing preset files.
	repo, err := s.firstGitOpsRepository(r.Context())
	if err != nil {
		s.log.Error(err, "loading GitOpsRepository for preset propose")
		s.writeError(w, http.StatusBadGateway, "could not load GitOpsRepository for propose")
		return
	}

	// Compose preset files into repo-relative paths under the first
	// configured Spec.Paths entry so the PR lands where the user's GitOps
	// controller is actually watching. Without this, preset files went to
	// repo root regardless of the repo's configured directory layout.
	prefix := ""
	if len(repo.Spec.Paths) > 0 {
		prefix = strings.TrimPrefix(strings.TrimSuffix(repo.Spec.Paths[0], "/"), "/")
	}
	committedFiles := make([]PresetFile, 0, len(p.Files))
	for _, f := range p.Files {
		dest := f.Path
		if prefix != "" {
			dest = pathpkg.Join(prefix, f.Path)
		}
		committedFiles = append(committedFiles, PresetFile{Path: dest, Content: f.Content})
	}

	// Demo mode takes the simulated path (fake PR URL, auto-merge goroutine)
	// so staged environments and tests don't hit GitHub. Production
	// deployments run with the env var unset and open a real PR.
	demoMode := os.Getenv("ZELYO_DEMO_MODE") == "true"

	var prURL string
	if demoMode {
		prURL = mockPRURL(p.ID, cfg.GitOpsRepo)
	} else {
		realURL, prErr := s.openPresetPR(r.Context(), p, repo, committedFiles)
		if prErr != nil {
			s.log.Error(prErr, "opening preset PR",
				"preset", p.ID, "repo", repo.Name)
			s.writeError(w, http.StatusBadGateway,
				fmt.Sprintf("GitOps PR failed: %s", prErr.Error()))
			return
		}
		prURL = realURL
	}

	// Populate the remediation store so clicking the PR card in the Pipeline
	// opens the same Before/Diff/After panel used for AI remediations. We
	// record the repo-prefixed paths that were actually committed.
	items := make([]events.RemediationItem, 0, len(committedFiles))
	for _, f := range committedFiles {
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
		Diff:         buildPresetDiff(committedFiles),
		FilesChanged: presetFilePaths(committedFiles),
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

	events.EmitConfigPRDrafted(p.Name, prURL, cfg.GitOpsRepo, p.Description, len(committedFiles))
	events.EmitPullRequestOpened(prURL, cfg.GitOpsRepo, len(committedFiles))

	// In demo mode only: auto-merge after a short delay so the Pipeline
	// visibly progresses through open → merged → enabled without human
	// action. Real PRs wait for human review in the GitOps repo.
	if demoMode {
		go s.demoAdvancePreset(s.backgroundContext(), p, prURL, cfg.GitOpsRepo)
	}

	s.writeJSON(w, map[string]interface{}{
		"status": status,
		"prUrl":  prURL,
	})
}

// firstGitOpsRepository returns the first GitOpsRepository in cluster. We
// already validated (via resolveConfigStatus) that at least one exists.
func (s *Server) firstGitOpsRepository(ctx context.Context) (*zelyov1alpha1.GitOpsRepository, error) {
	repos := &zelyov1alpha1.GitOpsRepositoryList{}
	if err := s.client.List(ctx, repos, &client.ListOptions{Limit: 1}); err != nil {
		return nil, fmt.Errorf("listing GitOpsRepositories: %w", err)
	}
	if len(repos.Items) == 0 {
		return nil, fmt.Errorf("no GitOpsRepository configured")
	}
	return &repos.Items[0], nil
}

// openPresetPR creates a real pull request for a preset using the github
// engine. Auth comes from the Secret referenced by GitOpsRepository.Spec
// .AuthSecret; we accept either "token" or "api-key" Data keys to match
// what the RemediationPolicy controller accepts.
func (s *Server) openPresetPR(ctx context.Context, p *Preset, repo *zelyov1alpha1.GitOpsRepository, files []PresetFile) (string, error) {
	if repo.Spec.AuthSecret == "" {
		return "", fmt.Errorf("GitOpsRepository %q has no authSecret", repo.Name)
	}
	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: repo.Spec.AuthSecret, Namespace: repo.Namespace}
	if err := s.client.Get(ctx, key, secret); err != nil {
		return "", fmt.Errorf("loading auth Secret %s/%s: %w", repo.Namespace, repo.Spec.AuthSecret, err)
	}
	token := string(secret.Data["token"])
	if token == "" {
		token = string(secret.Data["api-key"])
	}
	if token == "" {
		return "", fmt.Errorf("auth Secret %s/%s has no token or api-key data", repo.Namespace, repo.Spec.AuthSecret)
	}
	owner, name := parseOwnerRepo(repo.Spec.URL)
	if owner == "" || name == "" {
		return "", fmt.Errorf("GitOpsRepository URL %q does not parse as owner/repo", repo.Spec.URL)
	}

	gh := github.NewEngine(github.NewPATClient(token, ""), s.log.WithName("github-engine"))

	changes := make([]gitops.FileChange, 0, len(files))
	for _, f := range files {
		changes = append(changes, gitops.FileChange{
			Path:      f.Path,
			Content:   f.Content,
			Operation: gitops.FileOpCreate,
		})
	}

	baseBranch := repo.Spec.Branch
	if baseBranch == "" {
		baseBranch = "main"
	}

	pr := &gitops.PullRequest{
		RepoOwner:  owner,
		RepoName:   name,
		Title:      fmt.Sprintf("[Zelyo] Enable %s (%s)", p.Name, p.Framework),
		Body:       fmt.Sprintf("Enables the **%s** compliance preset.\n\n%s\n\n_Drafted by Zelyo Operator Compliance page._", p.Name, p.Description),
		BaseBranch: baseBranch,
		HeadBranch: fmt.Sprintf("zelyo-operator/preset/%s-%d", p.ID, time.Now().Unix()),
		Labels:     []string{"zelyo-operator", "compliance", p.Framework},
		Files:      changes,
	}
	result, err := gh.CreatePullRequest(ctx, pr)
	if err != nil {
		return "", fmt.Errorf("creating PR in %s/%s: %w", owner, name, err)
	}
	return result.URL, nil
}

// parseOwnerRepo pulls owner and repo from a git URL; duplicates the
// controller-side parseRepoURL logic but avoids a cross-package import.
func parseOwnerRepo(url string) (owner, repo string) {
	u := strings.TrimSpace(url)
	u = strings.TrimSuffix(u, ".git")
	// Strip scheme://host/ prefix.
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			u = rest[j+1:]
		}
	}
	// Strip user@host: prefix for SSH URLs.
	if i := strings.LastIndex(u, ":"); i >= 0 && strings.Contains(u[:i], "@") {
		u = u[i+1:]
	}
	parts := strings.SplitN(u, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// buildPresetDiff renders a unified-diff representation of creating the
// repo-prefixed preset files. Mirrors BuildDiff but operates on the paths
// that were actually committed.
func buildPresetDiff(files []PresetFile) string {
	var b strings.Builder
	for _, f := range files {
		lines := strings.Split(f.Content, "\n")
		fmt.Fprintf(&b, "--- /dev/null\n+++ b/%s\n@@ +0,0 +1,%d @@\n", f.Path, len(lines))
		for _, l := range lines {
			fmt.Fprintf(&b, "+%s\n", l)
		}
	}
	return b.String()
}

// presetFilePaths returns the committed paths.
func presetFilePaths(files []PresetFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
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

	// Real cluster apply. Previously handlePresetApply just flipped
	// in-memory state and emitted a "config.applied" event — nothing
	// actually landed in the cluster. Now we decode each preset file as
	// an unstructured object and create (or patch) it via the k8s client.
	applied, applyErr := s.applyPresetFilesToCluster(r.Context(), p)
	if applyErr != nil {
		s.log.Error(applyErr, "applying preset files to cluster", "preset", p.ID)
		status := store.update(p.ID, func(st *PresetStatus) {
			st.Message = fmt.Sprintf("Direct apply failed: %s", applyErr.Error())
		})
		s.writeError(w, http.StatusBadGateway,
			fmt.Sprintf("direct apply failed after %d/%d files: %s", applied, len(p.Files), applyErr.Error()))
		_ = status
		return
	}

	status := store.update(p.ID, func(st *PresetStatus) {
		st.State = PresetStateEnabled
		st.EnabledAt = &now
		st.PRURL = ""
		st.Message = fmt.Sprintf("Applied %d resource(s) directly to cluster", applied)
	})
	events.EmitConfigApplied(p.Name, p.Description, applied)

	s.writeJSON(w, map[string]interface{}{"status": status, "applied": applied})
}

// applyPresetFilesToCluster decodes each preset file as Kubernetes YAML
// and creates the resource via the controller-runtime client. If an
// object already exists, this returns the error — the caller surfaces it.
// Previously handlePresetApply only mutated in-memory state and the
// "Applied directly to cluster" message was false.
func (s *Server) applyPresetFilesToCluster(ctx context.Context, p *Preset) (int, error) {
	if s.client == nil {
		return 0, fmt.Errorf("dashboard has no k8s client")
	}
	applied := 0
	for _, f := range p.Files {
		// Each preset file may contain a single YAML document.
		obj := &unstructured.Unstructured{}
		if err := yaml.Unmarshal([]byte(f.Content), &obj.Object); err != nil {
			return applied, fmt.Errorf("parsing %s: %w", f.Path, err)
		}
		if obj.GetKind() == "" {
			return applied, fmt.Errorf("parsing %s: empty or non-object YAML", f.Path)
		}
		if err := s.client.Create(ctx, obj); err != nil {
			return applied, fmt.Errorf("creating %s/%s (%s): %w",
				obj.GetNamespace(), obj.GetName(), obj.GetKind(), err)
		}
		applied++
	}
	return applied, nil
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

// MustEncodePreset is used in tests.
func MustEncodePreset(p *Preset) string {
	b, _ := json.Marshal(p)
	return string(b)
}
