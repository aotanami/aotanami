/*
Copyright 2026 Zelyo AI
Dashboard — Compliance Page Module

Two sections:
 1. Policy presets — one-click compliance bundles. Enabling a preset opens
    a GitOps PR (hybrid mode) or applies directly, and the resulting change
    flows through the same Pipeline as AI-drafted remediations.
 2. Current compliance — framework pass rates from the latest scan.
*/

const { fetchJSON, onSSE, offSSE, formatTime } = window.ZelyoApp;

let _container = null;
let _state = {
  presets: [],
  config: { gitOpsConfigured: false, demoMode: false },
  frameworks: [],
  overallPct: 0,
};
let _drawerEl = null;
let _drawerBackdropEl = null;
let _drawerPresetID = null;
let _drawerPoll = null;
let _sseHandlers = [];
let _clickBound = false;
let _documentClickHandler = null;

/* ---------- Data loading ---------- */

async function load() {
  try {
    const [presetsResp, compResp] = await Promise.all([
      fetchJSON('/api/v1/presets'),
      fetchJSON('/api/v1/compliance').catch(() => ({ frameworks: [], overallPct: 0 })),
    ]);
    _state.presets = presetsResp.presets || [];
    _state.config = presetsResp.config || {};
    _state.frameworks = compResp.frameworks || [];
    _state.overallPct = compResp.overallPct || 0;
    renderAll();
  } catch (err) {
    if (_container) {
      _container.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">Failed to load: ${escapeHTML(err.message)}</div></div></div>`;
    }
  }
}

/* ---------- Rendering ---------- */

function renderAll() {
  if (!_container) return;
  _container.innerHTML = `
    <div class="compliance-page">
      <header class="compliance-header">
        <div>
          <h1 class="compliance-title">Compliance</h1>
          <p class="compliance-subtitle">One-click policy presets &middot; every change flows through a reviewable GitOps PR.</p>
        </div>
        ${renderConfigStatusBadge()}
      </header>

      <section class="preset-section">
        <div class="preset-section-head">
          <div>
            <div class="preset-section-title">Policy presets</div>
            <div class="preset-section-desc">Enable a framework in one click. Zelyo drafts the policy CRDs and opens a PR in your GitOps repo.</div>
          </div>
        </div>
        <div class="preset-grid">
          ${_state.presets.map(renderPresetCard).join('')}
        </div>
      </section>

      ${_state.frameworks.length > 0 ? renderFrameworkSection() : ''}
    </div>
  `;
}

function renderConfigStatusBadge() {
  const c = _state.config || {};
  if (c.gitOpsConfigured) {
    return `
      <div class="compliance-config-badge compliance-config-badge-ok">
        <span class="compliance-config-dot"></span>
        <div>
          <div class="compliance-config-label">GitOps connected</div>
          <div class="compliance-config-repo">${escapeHTML(c.gitOpsRepo || '')}</div>
        </div>
      </div>
    `;
  }
  return `
    <div class="compliance-config-badge compliance-config-badge-warn">
      <span class="compliance-config-dot"></span>
      <div>
        <div class="compliance-config-label">No GitOps repo</div>
        <div class="compliance-config-repo">Direct apply only &middot; <a href="#settings">Connect &rarr;</a></div>
      </div>
    </div>
  `;
}

function renderPresetCard(v) {
  const s = v.status || {};
  const state = s.state || 'not_enabled';
  const stateLabel = {
    not_enabled: 'Not enabled',
    proposing: 'Drafting PR…',
    pending_merge: 'PR pending merge',
    enabled: 'Enabled',
  }[state] || state;
  const stateClass = `preset-state-${state.replace('_', '-')}`;

  return `
    <button class="preset-card ${stateClass}" style="--preset-accent:${escapeAttr(v.accentHex || '#6366F1')}" data-preset-id="${escapeAttr(v.id)}">
      <div class="preset-card-top">
        <div class="preset-card-icon">${escapeHTML(v.icon || '')}</div>
        <span class="preset-card-state">
          <span class="preset-card-state-dot"></span>
          ${stateLabel}
        </span>
      </div>
      <div class="preset-card-name">${escapeHTML(v.name)}</div>
      <div class="preset-card-desc">${escapeHTML(v.description)}</div>
      <div class="preset-card-foot">
        <span class="preset-card-meta">${v.controls.length} controls &middot; ${v.files.length} CRD${v.files.length === 1 ? '' : 's'}</span>
        ${state === 'enabled'
          ? '<span class="preset-card-cta">Manage &rarr;</span>'
          : '<span class="preset-card-cta">Enable &rarr;</span>'}
      </div>
    </button>
  `;
}

function renderFrameworkSection() {
  return `
    <section class="framework-section">
      <div class="preset-section-head">
        <div>
          <div class="preset-section-title">Current posture</div>
          <div class="preset-section-desc">Pass rates from the latest scan across every framework Zelyo tracks.</div>
        </div>
        <div class="framework-overall">
          <span class="framework-overall-label">Overall</span>
          <span class="framework-overall-value" style="color:${overallColor(_state.overallPct)}">${Number(_state.overallPct).toFixed(1)}%</span>
        </div>
      </div>
      <div class="framework-grid">
        ${_state.frameworks.map(renderFrameworkRow).join('')}
      </div>
    </section>
  `;
}

function renderFrameworkRow(fw) {
  const total = fw.totalControls || 0;
  const failed = fw.failedControls || 0;
  const passed = Math.max(0, total - failed);
  const pct = fw.passRate || 0;
  const color = overallColor(pct);
  return `
    <div class="framework-row">
      <div class="framework-row-main">
        <div class="framework-row-name">${escapeHTML((fw.framework || '').toUpperCase())}</div>
        <div class="framework-row-stats">${passed}/${total} passed &middot; ${failed} failed</div>
      </div>
      <div class="framework-row-bar">
        <div class="framework-row-bar-fill" style="width:${pct}%;background:${color}"></div>
      </div>
      <div class="framework-row-pct" style="color:${color}">${Number(pct).toFixed(0)}%</div>
    </div>
  `;
}

function overallColor(pct) {
  if (pct >= 90) return 'var(--success)';
  if (pct >= 70) return 'var(--warning)';
  return 'var(--severity-critical)';
}

/* ---------- Drawer ---------- */

async function openDrawer(presetID) {
  _drawerPresetID = presetID;
  ensureDrawer();
  _drawerEl.classList.add('open');
  _drawerBackdropEl.classList.add('open');
  renderDrawerLoading();

  try {
    const resp = await fetchJSON(`/api/v1/presets/${encodeURIComponent(presetID)}`);
    const view = _state.presets.find((v) => v.id === presetID) || {};
    renderDrawer(view, resp);
  } catch (err) {
    _drawerEl.querySelector('.pipeline-panel-body').innerHTML = `<div class="pipeline-error">${escapeHTML(err.message)}</div>`;
  }
}

function closeDrawer() {
  if (_drawerEl) _drawerEl.classList.remove('open');
  if (_drawerBackdropEl) _drawerBackdropEl.classList.remove('open');
  _drawerPresetID = null;
  if (_drawerPoll) { clearInterval(_drawerPoll); _drawerPoll = null; }
}

function ensureDrawer() {
  if (_drawerEl) return;
  _drawerBackdropEl = document.createElement('div');
  _drawerBackdropEl.className = 'pipeline-panel-backdrop';
  document.body.appendChild(_drawerBackdropEl);
  _drawerBackdropEl.addEventListener('click', closeDrawer);

  _drawerEl = document.createElement('aside');
  _drawerEl.className = 'pipeline-panel preset-drawer';
  _drawerEl.innerHTML = `
    <div class="pipeline-panel-head">
      <div>
        <div class="pipeline-panel-title">Preview changes</div>
        <div class="pipeline-panel-subtitle"></div>
      </div>
      <button class="pipeline-panel-close" aria-label="Close">&times;</button>
    </div>
    <div class="pipeline-panel-body"></div>
  `;
  document.body.appendChild(_drawerEl);
  _drawerEl.querySelector('.pipeline-panel-close').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && _drawerPresetID) closeDrawer();
  });
}

function renderDrawerLoading() {
  _drawerEl.querySelector('.pipeline-panel-body').innerHTML = `
    <div class="pipeline-panel-loading">
      <div class="skeleton" style="height:24px;margin-bottom:12px"></div>
      <div class="skeleton" style="height:300px"></div>
    </div>
  `;
}

function renderDrawer(view, data) {
  const preset = data.preset || {};
  const diff = data.diff || '';
  const status = view.status || { state: 'not_enabled' };
  const cfg = _state.config || {};
  const canPR = !!cfg.gitOpsConfigured;

  _drawerEl.querySelector('.pipeline-panel-title').textContent = preset.name || 'Preset';
  _drawerEl.querySelector('.pipeline-panel-subtitle').textContent = preset.framework + ' · ' + (preset.files || []).length + ' file(s)';

  const actionRow = renderDrawerActions(preset.id, status, canPR, cfg.gitOpsRepo);

  _drawerEl.querySelector('.pipeline-panel-body').innerHTML = `
    <div class="pipeline-panel-pills">
      ${renderDrawerStatusPill(status)}
      ${canPR ? `<span class="pipeline-panel-pill pipeline-panel-pill-info">PR-mode</span>` : `<span class="pipeline-panel-pill">Direct-apply mode</span>`}
      <span class="pipeline-panel-pill">${preset.controls.length} controls</span>
    </div>

    <div class="pipeline-panel-section">
      <div class="pipeline-panel-section-title">What this enables</div>
      <ul class="preset-controls">
        ${(preset.controls || []).map((c) => `<li>${escapeHTML(c)}</li>`).join('')}
      </ul>
    </div>

    <div class="pipeline-panel-section">
      <div class="pipeline-panel-section-title">Files that will be created &middot; ${(preset.files || []).length}</div>
      <pre class="pipeline-panel-diff">${renderDiff(diff)}</pre>
    </div>

    ${actionRow}
  `;

  // Poll status while the PR is in flight so the button state reflects
  // merge progress without waiting for SSE.
  if (_drawerPoll) { clearInterval(_drawerPoll); _drawerPoll = null; }
  if (status.state === 'proposing' || status.state === 'pending_merge') {
    _drawerPoll = setInterval(() => pollDrawerStatus(preset.id), 700);
  }
}

function renderDrawerStatusPill(status) {
  const label = {
    not_enabled: 'Not enabled',
    proposing: 'Drafting PR…',
    pending_merge: 'PR pending merge',
    enabled: 'Enabled',
  }[status.state] || status.state;
  const cls = status.state === 'enabled' ? 'pipeline-panel-pill-success' : (status.state === 'not_enabled' ? '' : 'pipeline-panel-pill-info');
  return `<span class="pipeline-panel-pill ${cls}">${label}</span>`;
}

function renderDrawerActions(presetID, status, canPR, repo) {
  if (status.state === 'enabled') {
    return `
      <div class="preset-actions">
        <div class="preset-action-hint">This preset is active in your cluster.</div>
        ${status.prUrl ? `<a class="btn btn-secondary" href="${escapeAttr(status.prUrl)}" target="_blank" rel="noopener">View merged PR</a>` : ''}
      </div>
    `;
  }
  if (status.state === 'proposing' || status.state === 'pending_merge') {
    return `
      <div class="preset-actions preset-actions-pending">
        <div class="preset-action-spinner">
          <span class="pipeline-explain-dot"></span>
          <span class="pipeline-explain-dot"></span>
          <span class="pipeline-explain-dot"></span>
        </div>
        <div>
          <div class="preset-action-hint">${escapeHTML(status.message || 'Waiting for review')}</div>
          ${status.prUrl ? `<a class="preset-action-link" href="${escapeAttr(status.prUrl)}" target="_blank" rel="noopener">${escapeHTML(shortPR(status.prUrl))}</a>` : ''}
        </div>
      </div>
    `;
  }

  // not_enabled — PR-only flow. Zelyo never applies policies directly to
  // the cluster from the UI; every declarative change must flow through
  // a reviewable GitOps PR. When no repo is connected, we gate the flow
  // behind Settings → Connect GitOps rather than offering a bypass.
  if (!canPR) {
    return `
      <div class="preset-actions preset-actions-blocked">
        <div class="preset-action-hint">
          No GitOps repository connected. Zelyo only ships policies via a
          reviewable PR — connect a repo to enable this preset.
        </div>
        <div class="preset-actions-row">
          <a class="btn btn-primary" href="#settings">Connect GitOps &rarr;</a>
        </div>
      </div>
    `;
  }

  return `
    <div class="preset-actions">
      <div class="preset-action-hint">
        Opens a PR in <strong>${escapeHTML(repo || 'your GitOps repo')}</strong>.
        Review &amp; merge to apply — Zelyo never writes directly to the cluster.
      </div>
      <div class="preset-actions-row">
        <button class="btn btn-primary preset-propose" data-preset-id="${escapeAttr(presetID)}">Propose via PR &rarr;</button>
      </div>
    </div>
  `;
}

async function pollDrawerStatus(presetID) {
  try {
    const s = await fetchJSON(`/api/v1/presets/${encodeURIComponent(presetID)}/status`);
    const v = _state.presets.find((x) => x.id === presetID);
    if (v) v.status = s;
    // Also refresh the preset list so the main page updates.
    if (s.state === 'enabled' || s.state === 'pending_merge') {
      updatePresetCardInPlace(presetID, s);
    }
    // Re-render drawer if it's currently open for this preset.
    if (_drawerPresetID === presetID && _drawerEl && _drawerEl.classList.contains('open')) {
      const preview = await fetchJSON(`/api/v1/presets/${encodeURIComponent(presetID)}`);
      renderDrawer({ ...v, status: s }, preview);
    }
  } catch (_) { /* ignore */ }
}

async function triggerPropose(presetID) {
  try {
    const s = await postJSON(`/api/v1/presets/${encodeURIComponent(presetID)}/propose`, {});
    const v = _state.presets.find((x) => x.id === presetID);
    if (v) v.status = s.status;
    await openDrawer(presetID); // re-open with updated state
  } catch (err) {
    alert('Could not draft PR: ' + (err.message || err));
  }
}

// triggerApply is intentionally not wired to any UI element. The /apply
// backend endpoint is retained for admin/CLI use (e.g. bootstrapping a
// cluster before a GitOps repo is onboarded), but Zelyo's UI contract is
// PR-only: every declarative change surfaces as a reviewable PR.

function updatePresetCardInPlace(presetID, status) {
  const v = _state.presets.find((x) => x.id === presetID);
  if (!v) return;
  v.status = status;
  const card = _container && _container.querySelector(`[data-preset-id="${CSS.escape(presetID)}"]`);
  if (!card) return;
  card.outerHTML = renderPresetCard(v);
}

/* ---------- Diff renderer (shared shape with Pipeline panel) ---------- */

function renderDiff(diff) {
  if (!diff) return '<span style="opacity:0.6">No diff.</span>';
  return diff.split('\n').map((l) => {
    let cls = 'd-ctx';
    if (l.startsWith('+++') || l.startsWith('---')) cls = 'd-file';
    else if (l.startsWith('@@')) cls = 'd-hunk';
    else if (l.startsWith('+')) cls = 'd-add';
    else if (l.startsWith('-')) cls = 'd-del';
    return `<span class="${cls}">${escapeHTML(l)}</span>`;
  }).join('\n');
}

/* ---------- Click + SSE wiring ---------- */

function bindClicks() {
  // Idempotent: only attach once per page render. Without this guard,
  // every SSE-driven reload would stack another document-level listener,
  // causing action clicks to fire multiple POSTs.
  if (_clickBound || !_container) return;
  _clickBound = true;

  _container.addEventListener('click', (e) => {
    const card = e.target.closest('[data-preset-id]');
    if (!card) return;
    // The drawer button clicks are handled by delegated listener below.
    if (e.target.closest('.preset-propose')) return;
    openDrawer(card.getAttribute('data-preset-id'));
  });

  _documentClickHandler = (e) => {
    const prop = e.target.closest('.preset-propose');
    if (prop) { e.preventDefault(); triggerPropose(prop.getAttribute('data-preset-id')); }
  };
  document.addEventListener('click', _documentClickHandler);
}

function handleConfigEvent() {
  // A config-related event fired — reload preset status so the main list
  // reflects the change.
  fetchJSON('/api/v1/presets').then((resp) => {
    _state.presets = resp.presets || _state.presets;
    renderAll();
    // bindClicks() is idempotent + uses event delegation, so the new DOM
    // (with fresh [data-preset-id] cards) works with the existing listener.
    if (_drawerPresetID) {
      // keep the drawer in sync.
      pollDrawerStatus(_drawerPresetID);
    }
  }).catch(() => {});
}

/* ---------- Helpers ---------- */

function postJSON(url, body) {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  }).then(async (res) => {
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    return res.json();
  });
}

function escapeHTML(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}
function escapeAttr(s) { return escapeHTML(s); }
function shortPR(url) {
  const m = String(url || '').match(/github\.com\/([^/]+\/[^/]+)\/pull\/(\d+)/);
  return m ? `${m[1]}#${m[2]}` : url;
}

/* ---------- Lifecycle ---------- */

export function render(container) {
  _container = container;
  _container.innerHTML = `<div class="compliance-page"><div class="page-loading"><div class="skeleton" style="height:96px;margin-bottom:16px"></div><div class="skeleton" style="height:400px"></div></div></div>`;
  load().then(bindClicks);

  const handler = () => handleConfigEvent();
  ['config.pr.drafted', 'config.applied', 'pr.opened', 'pr.merged', 'finding.resolved'].forEach((t) => {
    onSSE(t, handler);
    _sseHandlers.push({ t, h: handler });
  });
}

export function destroy() {
  _sseHandlers.forEach(({ t, h }) => offSSE(t, h));
  _sseHandlers = [];
  if (_documentClickHandler) {
    document.removeEventListener('click', _documentClickHandler);
    _documentClickHandler = null;
  }
  _clickBound = false;
  closeDrawer();
  if (_drawerEl && _drawerEl.parentNode) _drawerEl.parentNode.removeChild(_drawerEl);
  if (_drawerBackdropEl && _drawerBackdropEl.parentNode) _drawerBackdropEl.parentNode.removeChild(_drawerBackdropEl);
  _drawerEl = null;
  _drawerBackdropEl = null;
  _container = null;
}
