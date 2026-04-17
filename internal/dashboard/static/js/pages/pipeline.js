/*
Copyright 2026 Zelyo AI
Dashboard — Pipeline Page Module

A left-to-right visualization of the Zelyo agentic pipeline:
  Scan  →  Correlate  →  Fix  →  Verify

Events stream in from /api/v1/events (SSE) and are also backfilled from
/api/v1/pipeline on page load so the visual is never empty.
*/

const { fetchJSON, onSSE, offSSE, formatTime } = window.ZelyoApp;

const STAGES = [
  {
    id: 'scan',
    label: 'Scan',
    description: 'Detect issues across pods & cloud',
    color: '#3b82f6',
    icon: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>',
  },
  {
    id: 'correlate',
    label: 'Correlate',
    description: 'Group findings into root causes',
    color: '#a855f7',
    icon: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M9 9l6 6"/></svg>',
  },
  {
    id: 'fix',
    label: 'Fix',
    description: 'Draft remediations & open PRs',
    color: '#06b6d4',
    icon: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>',
  },
  {
    id: 'verify',
    label: 'Verify',
    description: 'Re-scan confirms the fix',
    color: '#22c55e',
    icon: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
  },
];

const MAX_EVENTS_PER_STAGE = 12;

let _container = null;
let _eventsByStage = { scan: [], correlate: [], fix: [], verify: [] };
let _counts = { scan: 0, correlate: 0, fix: 0, verify: 0 };
let _sseHandlers = [];
let _totalProcessed = 0;
let _panelURL = null;
let _panelCtx = null;
let _panelEl = null;
let _panelBackdropEl = null;
let _clickBound = false;

/* ---------- Initial load ---------- */

async function loadPipeline() {
  try {
    const data = await fetchJSON('/api/v1/pipeline?limit=400');
    _eventsByStage = { scan: [], correlate: [], fix: [], verify: [] };
    // Backend returns oldest-first; we want newest at top inside each column.
    (data.events || []).forEach((e) => appendEvent(e, /*silent=*/ true));
    _counts = data.counts || _counts;
    _totalProcessed = Object.values(_counts).reduce((a, b) => a + b, 0);
    renderAll();
  } catch (err) {
    console.error('Failed to load pipeline', err);
    renderError(err.message);
  }
}

/* ---------- Event ingestion ---------- */

function handlePipelineEvent(payload) {
  // The payload is the outer SSE envelope { type, data, timestamp } where
  // `data` is the events.Event struct.
  const e = payload.data || payload;
  if (!e || !e.stage) return;

  appendEvent(e, /*silent=*/ false);
  _counts[e.stage] = (_counts[e.stage] || 0) + 1;
  _totalProcessed++;
  renderStage(e.stage);
  renderHeader();
  pulseStage(e.stage);

  // Keep the side panel in sync if it's open — resolved findings, merges,
  // and follow-up PRs all update the store server-side.
  if (_panelURL && (e.type === 'finding.resolved' || e.type === 'pr.merged' || e.type === 'pr.opened')) {
    refreshPanelIfOpen();
  }
}

function appendEvent(e, silent) {
  const stage = e.stage;
  if (!_eventsByStage[stage]) return;
  _eventsByStage[stage].unshift(e);
  if (_eventsByStage[stage].length > MAX_EVENTS_PER_STAGE) {
    _eventsByStage[stage].length = MAX_EVENTS_PER_STAGE;
  }
  if (!silent) {
    // We already re-render in handlePipelineEvent; silent path is used
    // for the initial backfill which renders once at the end.
  }
}

/* ---------- Rendering ---------- */

function renderAll() {
  if (!_container) return;
  _container.innerHTML = `
    <div class="pipeline-page">
      ${renderHeaderHTML()}
      <div class="pipeline-stages" id="pipeline-stages">
        ${STAGES.map(renderStageHTML).join('')}
      </div>
      <div class="pipeline-footer">
        <span class="pipeline-dot"></span>
        <span>Live feed — events stream from the operator as scans and remediations run</span>
      </div>
    </div>
  `;
}

function renderHeader() {
  const el = _container && _container.querySelector('.pipeline-header');
  if (!el) return;
  el.outerHTML = renderHeaderHTML();
}

function renderHeaderHTML() {
  return `
    <div class="pipeline-header">
      <div>
        <h1 class="pipeline-title">Pipeline</h1>
        <p class="pipeline-subtitle">Detect → Correlate → Fix → Verify · ${_totalProcessed} events in the last session</p>
      </div>
      <div class="pipeline-lights">
        ${STAGES.map((s) => `
          <div class="pipeline-light" data-stage="${s.id}" style="--stage-color:${s.color}">
            <span class="pipeline-light-dot"></span>
            <span class="pipeline-light-label">${s.label}</span>
            <span class="pipeline-light-count">${_counts[s.id] || 0}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderStageHTML(stage) {
  return `
    <div class="pipeline-stage" data-stage="${stage.id}" style="--stage-color:${stage.color}">
      <div class="pipeline-stage-head">
        <span class="pipeline-stage-icon">${stage.icon}</span>
        <div class="pipeline-stage-text">
          <div class="pipeline-stage-label">${stage.label}</div>
          <div class="pipeline-stage-desc">${stage.description}</div>
        </div>
      </div>
      <div class="pipeline-stage-feed" id="stage-feed-${stage.id}">
        ${renderFeedHTML(stage.id)}
      </div>
    </div>
  `;
}

function renderStage(stageId) {
  const feed = _container && _container.querySelector(`#stage-feed-${stageId}`);
  if (!feed) return;
  feed.innerHTML = renderFeedHTML(stageId);
}

function renderFeedHTML(stageId) {
  const items = _eventsByStage[stageId] || [];
  if (items.length === 0) {
    return `<div class="pipeline-empty">Waiting for activity…</div>`;
  }
  return items.map(renderEventHTML).join('');
}

function renderEventHTML(e) {
  const levelClass = `pipeline-event-${e.level || 'info'}`;
  const severityBadge = e.severity
    ? `<span class="pipeline-sev pipeline-sev-${(e.severity || '').toLowerCase()}">${escapeHtml(e.severity)}</span>`
    : '';
  const resource = e.resource
    ? `<div class="pipeline-event-resource">${escapeHtml(e.resource)}</div>`
    : '';
  const url = e.meta && e.meta.url;
  const hasDiff = !!url;
  const explainable = eventExplainable(e);
  const explainAttrs = explainable
    ? buildExplainAttrs(e)
    : '';
  const actions = [
    explainable
      ? `<button class="pipeline-explain-btn pipeline-explain-btn-sm" ${explainAttrs}>
           <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4"/><path d="M12 18v4"/><path d="M4.93 4.93l2.83 2.83"/><path d="M16.24 16.24l2.83 2.83"/><path d="M2 12h4"/><path d="M18 12h4"/><path d="M4.93 19.07l2.83-2.83"/><path d="M16.24 7.76l2.83-2.83"/></svg>
           <span>Explain</span>
         </button>`
      : '',
    hasDiff
      ? `<button class="pipeline-event-action" data-open-pr="${escapeAttr(url)}">View diff →</button>`
      : '',
  ].filter(Boolean).join('');
  const clickableAttrs = hasDiff ? `data-open-pr="${escapeAttr(url)}" role="button" tabindex="0"` : '';
  const clickableClass = hasDiff ? ' pipeline-event-clickable' : '';
  const fingerprint = explainable ? escapeAttr(eventFingerprint(e)) : '';
  const explanationContainer = explainable
    ? `<div class="pipeline-finding-explanation" data-explanation-for="${fingerprint}" hidden></div>`
    : '';
  return `
    <div class="pipeline-event ${levelClass}${clickableClass}" ${clickableAttrs}>
      <div class="pipeline-event-row">
        <span class="pipeline-event-title">${escapeHtml(e.title || '')}</span>
        ${severityBadge}
      </div>
      ${e.detail ? `<div class="pipeline-event-detail">${escapeHtml(e.detail)}</div>` : ''}
      ${resource}
      <div class="pipeline-event-meta">
        <span>${formatTime(e.timestamp)}</span>
        <div class="pipeline-event-actions">${actions}</div>
      </div>
      ${explanationContainer}
    </div>
  `;
}

function eventExplainable(e) {
  return e.type === 'finding.detected' || e.type === 'correlation.grouped';
}

// Translate an event's fields into the rule/severity/resource/title the
// /api/v1/explain endpoint expects.
function eventExplainPayload(e) {
  if (e.type === 'finding.detected') {
    return {
      rule: e.detail || '',
      severity: e.severity || '',
      resource: e.resource || '',
      title: e.title || '',
    };
  }
  if (e.type === 'correlation.grouped') {
    return {
      rule: 'correlation',
      severity: '',
      resource: (e.meta && e.meta.scan) ? `scan:${e.meta.scan}` : '',
      title: e.title || '',
    };
  }
  return null;
}

function buildExplainAttrs(e) {
  const p = eventExplainPayload(e);
  if (!p) return '';
  return [
    `data-explain-rule="${escapeAttr(p.rule)}"`,
    `data-explain-severity="${escapeAttr(p.severity)}"`,
    `data-explain-resource="${escapeAttr(p.resource)}"`,
    `data-explain-title="${escapeAttr(p.title)}"`,
    `data-finding-id="${escapeAttr(eventFingerprint(e))}"`,
  ].join(' ');
}

function eventFingerprint(e) {
  const p = eventExplainPayload(e) || {};
  return `${p.rule || ''}|${(p.severity || '').toLowerCase()}|${p.resource || ''}`;
}

function pulseStage(stageId) {
  const light = _container && _container.querySelector(`.pipeline-light[data-stage="${stageId}"]`);
  if (light) {
    light.classList.remove('pulsing');
    // Force reflow so the animation restarts.
    // eslint-disable-next-line no-unused-expressions
    void light.offsetWidth;
    light.classList.add('pulsing');
  }
  const col = _container && _container.querySelector(`.pipeline-stage[data-stage="${stageId}"]`);
  if (col) {
    col.classList.remove('flash');
    // eslint-disable-next-line no-unused-expressions
    void col.offsetWidth;
    col.classList.add('flash');
  }
}

/* ---------- Side panel: Before / Diff / After ---------- */

async function openPanel(url) {
  _panelURL = url;
  ensurePanel();
  _panelEl.classList.add('open');
  if (_panelBackdropEl) _panelBackdropEl.classList.add('open');
  _panelEl.querySelector('.pipeline-panel-body').innerHTML = `<div class="pipeline-panel-loading"><div class="skeleton" style="height:24px;margin-bottom:12px"></div><div class="skeleton" style="height:200px"></div></div>`;
  try {
    _panelCtx = await fetchJSON(`/api/v1/remediations?url=${encodeURIComponent(url)}`);
    renderPanelBody();
  } catch (err) {
    _panelEl.querySelector('.pipeline-panel-body').innerHTML = `<div class="pipeline-error">No remediation context found for this PR yet. It may still be drafting.<div style="margin-top:8px;opacity:0.7">${escapeHtml(err.message || '')}</div></div>`;
  }
}

function closePanel() {
  if (_panelEl) _panelEl.classList.remove('open');
  if (_panelBackdropEl) _panelBackdropEl.classList.remove('open');
  _panelURL = null;
  _panelCtx = null;
}

function ensurePanel() {
  if (_panelEl) return;
  _panelBackdropEl = document.createElement('div');
  _panelBackdropEl.className = 'pipeline-panel-backdrop';
  document.body.appendChild(_panelBackdropEl);
  _panelBackdropEl.addEventListener('click', closePanel);

  _panelEl = document.createElement('aside');
  _panelEl.className = 'pipeline-panel';
  _panelEl.innerHTML = `
    <div class="pipeline-panel-head">
      <div>
        <div class="pipeline-panel-title">Remediation</div>
        <div class="pipeline-panel-subtitle"></div>
      </div>
      <button class="pipeline-panel-close" aria-label="Close">×</button>
    </div>
    <div class="pipeline-panel-body"></div>
  `;
  document.body.appendChild(_panelEl);
  _panelEl.querySelector('.pipeline-panel-close').addEventListener('click', closePanel);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closePanel();
  });
}

function renderPanelBody() {
  if (!_panelEl || !_panelCtx) return;
  const ctx = _panelCtx;
  _panelEl.querySelector('.pipeline-panel-title').textContent = ctx.summary || 'Remediation';
  const sub = ctx.repo + (ctx.prUrl ? ` · <a href="${escapeAttr(ctx.prUrl)}" target="_blank" rel="noopener">${escapeHtml(shortPR(ctx.prUrl))}</a>` : '');
  _panelEl.querySelector('.pipeline-panel-subtitle').innerHTML = sub;

  const total = (ctx.findings || []).length;
  const resolved = (ctx.findings || []).filter((f) => f.resolved).length;
  const merged = !!ctx.mergedAt;

  const statusPill = merged
    ? `<span class="pipeline-panel-pill pipeline-panel-pill-success">PR merged</span>`
    : `<span class="pipeline-panel-pill pipeline-panel-pill-info">PR open</span>`;
  const resolvedPill = `<span class="pipeline-panel-pill pipeline-panel-pill-${resolved === total ? 'success' : 'info'}">${resolved}/${total} resolved</span>`;

  _panelEl.querySelector('.pipeline-panel-body').innerHTML = `
    <div class="pipeline-panel-pills">
      ${statusPill}
      ${resolvedPill}
      <span class="pipeline-panel-pill">${escapeHtml((ctx.filesChanged || []).length + ' file(s)')}</span>
    </div>

    <div class="pipeline-panel-section">
      <div class="pipeline-panel-section-title">Before · ${total} finding${total === 1 ? '' : 's'}</div>
      <div class="pipeline-panel-findings">
        ${(ctx.findings || []).map(renderFindingCard).join('')}
      </div>
    </div>

    <div class="pipeline-panel-section">
      <div class="pipeline-panel-section-title">Proposed diff</div>
      <pre class="pipeline-panel-diff">${renderDiff(ctx.diff || '')}</pre>
    </div>

    <div class="pipeline-panel-section">
      <div class="pipeline-panel-section-title">After · ${resolved}/${total} resolved ${merged ? '· after re-scan' : '· waiting for merge + re-scan'}</div>
      <div class="pipeline-panel-after">
        ${renderAfterStatus(ctx)}
      </div>
    </div>
  `;
}

function renderFindingCard(f) {
  const sev = (f.severity || 'info').toLowerCase();
  const resolvedClass = f.resolved ? ' pipeline-finding-resolved' : '';
  const fingerprint = escapeAttr(findingFingerprint(f));
  return `
    <div class="pipeline-finding${resolvedClass}" data-finding-id="${fingerprint}">
      <div class="pipeline-finding-row">
        <span class="pipeline-sev pipeline-sev-${sev}">${escapeHtml(f.severity || '')}</span>
        <span class="pipeline-finding-title">${escapeHtml(f.title || '')}</span>
        ${f.resolved ? `<span class="pipeline-finding-check">✓</span>` : ''}
      </div>
      <div class="pipeline-finding-resource">${escapeHtml(f.resource || '')} · <span class="pipeline-finding-rule">${escapeHtml(f.rule || '')}</span></div>
      <div class="pipeline-finding-actions">
        <button class="pipeline-explain-btn"
                data-explain-rule="${escapeAttr(f.rule || '')}"
                data-explain-severity="${escapeAttr(f.severity || '')}"
                data-explain-resource="${escapeAttr(f.resource || '')}"
                data-explain-title="${escapeAttr(f.title || '')}"
                data-finding-id="${fingerprint}">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4"/><path d="M12 18v4"/><path d="M4.93 4.93l2.83 2.83"/><path d="M16.24 16.24l2.83 2.83"/><path d="M2 12h4"/><path d="M18 12h4"/><path d="M4.93 19.07l2.83-2.83"/><path d="M16.24 7.76l2.83-2.83"/></svg>
          <span>Explain</span>
        </button>
      </div>
      <div class="pipeline-finding-explanation" data-explanation-for="${fingerprint}" hidden></div>
    </div>
  `;
}

function findingFingerprint(f) {
  return `${f.rule || ''}|${(f.severity || '').toLowerCase()}|${f.resource || ''}`;
}

function renderAfterStatus(ctx) {
  const items = (ctx.findings || []);
  if (items.length === 0) return '<div class="pipeline-empty">No findings.</div>';
  return items.map((f) => `
    <div class="pipeline-after-row ${f.resolved ? 'resolved' : ''}">
      <span class="pipeline-after-status">${f.resolved ? '✓ resolved' : '… pending'}</span>
      <span class="pipeline-after-resource">${escapeHtml(f.resource || '')}</span>
    </div>
  `).join('');
}

function renderDiff(diff) {
  if (!diff) return '<span style="opacity:0.6">No diff available.</span>';
  const lines = diff.split('\n');
  return lines.map((l) => {
    let cls = 'd-ctx';
    if (l.startsWith('+++') || l.startsWith('---')) cls = 'd-file';
    else if (l.startsWith('@@')) cls = 'd-hunk';
    else if (l.startsWith('+')) cls = 'd-add';
    else if (l.startsWith('-')) cls = 'd-del';
    return `<span class="${cls}">${escapeHtml(l)}</span>`;
  }).join('\n');
}

function shortPR(url) {
  const m = String(url || '').match(/github\.com\/([^/]+\/[^/]+)\/pull\/(\d+)/);
  return m ? `${m[1]}#${m[2]}` : url;
}

/* ---------- Delegated click handling for event cards ---------- */

function bindClicks() {
  if (_clickBound) return;
  _clickBound = true;

  document.addEventListener('click', (evt) => {
    const explainBtn = evt.target.closest('[data-explain-rule]');
    if (explainBtn) {
      evt.preventDefault();
      triggerExplain(explainBtn);
      return;
    }
    const host = evt.target.closest('[data-open-pr]');
    if (host && _container && _container.contains(host)) {
      evt.preventDefault();
      openPanel(host.getAttribute('data-open-pr'));
    }
  });
  document.addEventListener('keydown', (evt) => {
    if (evt.key !== 'Enter' && evt.key !== ' ') return;
    const host = evt.target.closest && evt.target.closest('[data-open-pr]');
    if (host && _container && _container.contains(host)) {
      evt.preventDefault();
      openPanel(host.getAttribute('data-open-pr'));
    }
  });
}

/* ---------- Explain this finding ---------- */

const _explainCache = new Map(); // fingerprint -> rendered HTML string

async function triggerExplain(btn) {
  const fingerprint = btn.getAttribute('data-finding-id');
  // The explanation container is always a sibling of the button's containing
  // card — either a .pipeline-finding (side panel) or a .pipeline-event
  // (main column feed). Searching from the shared ancestor handles both.
  const card = btn.closest('.pipeline-finding, .pipeline-event');
  const panel = card
    ? card.querySelector(`[data-explanation-for="${CSS.escape(fingerprint)}"]`)
    : null;
  if (!panel) return;

  // Toggle closed if already visible.
  if (!panel.hasAttribute('hidden')) {
    panel.setAttribute('hidden', '');
    btn.classList.remove('active');
    return;
  }

  panel.removeAttribute('hidden');
  btn.classList.add('active');

  if (_explainCache.has(fingerprint)) {
    panel.innerHTML = _explainCache.get(fingerprint);
    return;
  }

  panel.innerHTML = `<div class="pipeline-explain-loading"><span class="pipeline-explain-dot"></span><span class="pipeline-explain-dot"></span><span class="pipeline-explain-dot"></span><span class="pipeline-explain-loading-text">Analyzing…</span></div>`;

  try {
    const body = {
      rule: btn.getAttribute('data-explain-rule') || '',
      severity: btn.getAttribute('data-explain-severity') || '',
      resource: btn.getAttribute('data-explain-resource') || '',
      title: btn.getAttribute('data-explain-title') || '',
    };
    const res = await fetch('/api/v1/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    const data = await res.json();
    const html = renderExplanationHTML(data);
    _explainCache.set(fingerprint, html);
    panel.innerHTML = '';
    revealText(panel, html);
  } catch (err) {
    panel.innerHTML = `<div class="pipeline-explain-error">Couldn't generate an explanation: ${escapeHtml(err.message || String(err))}</div>`;
  }
}

function renderExplanationHTML(data) {
  const source = (data.source || 'canned').toLowerCase();
  const badge = source === 'llm'
    ? `<span class="pipeline-explain-source pipeline-explain-source-llm">AI-generated</span>`
    : source === 'cache'
      ? `<span class="pipeline-explain-source">cached</span>`
      : `<span class="pipeline-explain-source">curated</span>`;
  const body = renderMarkdownLite(data.explanation || '');
  return `<div class="pipeline-explain-body">${body}</div><div class="pipeline-explain-foot">${badge}</div>`;
}

// Tiny subset of markdown → HTML used by our canned explanations.
// Supports: **bold**, `inline code`, *italic*, and paragraph breaks.
function renderMarkdownLite(md) {
  return escapeHtml(md)
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .split(/\n{2,}/)
    .map((p) => `<p>${p.replace(/\n/g, '<br>')}</p>`)
    .join('');
}

// Fade in the rendered HTML all at once — short animation is enough to
// signal "something intelligent is happening" without delaying the content.
function revealText(panel, html) {
  panel.style.opacity = '0';
  panel.innerHTML = html;
  requestAnimationFrame(() => {
    panel.style.transition = 'opacity 260ms ease';
    panel.style.opacity = '1';
  });
}

function refreshPanelIfOpen() {
  if (!_panelURL) return;
  fetchJSON(`/api/v1/remediations?url=${encodeURIComponent(_panelURL)}`)
    .then((ctx) => { _panelCtx = ctx; renderPanelBody(); })
    .catch(() => { /* ignore */ });
}

function renderError(msg) {
  if (!_container) return;
  _container.innerHTML = `
    <div class="pipeline-page">
      <div class="pipeline-error">
        <strong>Could not load pipeline.</strong>
        <div>${escapeHtml(msg)}</div>
      </div>
    </div>
  `;
}

/* ---------- Escaping ---------- */

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeAttr(s) {
  return escapeHtml(s);
}

/* ---------- Page lifecycle ---------- */

export function render(container) {
  _container = container;
  _container.innerHTML = `<div class="pipeline-page"><div class="page-loading"><div class="skeleton" style="height:96px;margin-bottom:16px"></div><div class="skeleton" style="height:400px"></div></div></div>`;
  loadPipeline();
  bindClicks();

  const eventTypes = [
    'scan.started', 'scan.completed', 'finding.detected', 'report.created',
    'correlation.grouped',
    'remediation.drafted', 'pr.opened', 'pr.merged',
    'finding.resolved',
  ];
  eventTypes.forEach((t) => {
    const h = (data) => handlePipelineEvent(data);
    onSSE(t, h);
    _sseHandlers.push({ t, h });
  });
}

export function destroy() {
  _sseHandlers.forEach(({ t, h }) => offSSE(t, h));
  _sseHandlers = [];
  closePanel();
  if (_panelEl && _panelEl.parentNode) _panelEl.parentNode.removeChild(_panelEl);
  if (_panelBackdropEl && _panelBackdropEl.parentNode) _panelBackdropEl.parentNode.removeChild(_panelBackdropEl);
  _panelEl = null;
  _panelBackdropEl = null;
  _container = null;
}
