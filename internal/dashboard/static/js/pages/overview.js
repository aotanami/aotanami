/*
Copyright 2026 Zelyo AI
Dashboard — Overview Page Module

Landing page layout inspired by Prowler (Findings by Severity, Top Failing
Checks, Top Affected Resources, Compliance Strip, Cloud Account Risk) with
Zelyo-specific elements: the live Pipeline snapshot + "Open PR" as the
primary action on failing items (our differentiator over Prowler — we ship
GitOps remediations).
*/

const { fetchJSON, onSSE, offSSE, formatTime } = window.ZelyoApp;

let _container = null;
let _data = null;
let _sseHandlers = [];

/* ---------- Load + SSE ---------- */

async function load() {
  try {
    _data = await fetchJSON('/api/v1/overview');
    renderAll();
  } catch (err) {
    if (_container) {
      _container.innerHTML = `<div class="empty-state"><h3>Failed to load overview</h3><p>${escapeHTML(err.message)}</p></div>`;
    }
  }
}

function bindSSE() {
  const refresh = () => load();
  // High-signal events that change Overview numbers. Other pipeline events
  // update the Pipeline view directly and don't need a full refetch.
  ['scan.completed', 'report.created', 'pr.merged', 'config.applied', 'finding.resolved', 'overview.refresh']
    .forEach((t) => { onSSE(t, refresh); _sseHandlers.push({ t, h: refresh }); });
}

/* ---------- Rendering ---------- */

function renderAll() {
  if (!_container || !_data) return;
  _container.innerHTML = `
    <div class="ov-page">
      ${renderHeader()}
      ${renderKPIStrip()}
      <div class="ov-row ov-row-2">
        ${renderSeverityCard()}
        ${renderPipelineCard()}
      </div>
      <div class="ov-row ov-row-2">
        ${renderTopChecksCard()}
        ${renderTopKindsCard()}
      </div>
      ${renderComplianceStrip()}
      ${renderCloudAccountsCard()}
      ${renderTrendCard()}
    </div>
  `;
}

/* ---------- Header ---------- */

function renderHeader() {
  const d = _data;
  const mode = (d.operatorMode || '').toUpperCase() || '—';
  const phase = d.operatorPhase || 'Unknown';
  const phaseClass = phase === 'Active' ? 'ov-phase-ok' : 'ov-phase-warn';
  return `
    <header class="ov-header">
      <div>
        <h1 class="ov-title">Security posture</h1>
        <p class="ov-subtitle">Real-time view across Kubernetes + cloud &middot; last updated ${escapeHTML(formatTime(d.updatedAt))}</p>
      </div>
      <div class="ov-op-state">
        <span class="ov-op-mode">${escapeHTML(mode)} MODE</span>
        <span class="ov-op-phase ${phaseClass}"><span class="ov-op-dot"></span>${escapeHTML(phase)}</span>
      </div>
    </header>
  `;
}

/* ---------- KPI strip ---------- */

function renderKPIStrip() {
  const d = _data;
  const score = d.securityScore ?? 0;
  const scoreColor = score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warning)' : 'var(--severity-critical)';
  const scoreLabel = score >= 80 ? 'Strong' : score >= 60 ? 'At-risk' : 'Critical';

  const kpis = [
    {
      label: 'Security Score',
      value: `<span style="color:${scoreColor}">${score}</span>`,
      sub: scoreLabel,
      accent: scoreColor,
    },
    {
      label: 'Active Findings',
      value: (d.totalFindings || 0).toLocaleString(),
      sub: `${d.resolvedFindings || 0} resolved`,
      accent: 'var(--severity-critical)',
    },
    {
      label: 'Cloud Findings',
      value: (d.cloudFindings || 0).toLocaleString(),
      sub: `${d.cloudAccounts || 0} accounts`,
      accent: 'var(--primary)',
    },
    {
      label: 'Compliance',
      value: `${(d.compliancePct || 0).toFixed(1)}<span class="ov-kpi-unit">%</span>`,
      sub: `${(d.frameworks || []).length} frameworks`,
      accent: 'var(--accent)',
    },
  ];

  return `
    <div class="ov-kpi-strip">
      ${kpis.map((k) => `
        <div class="ov-kpi" style="--kpi-accent:${k.accent}">
          <div class="ov-kpi-label">${escapeHTML(k.label)}</div>
          <div class="ov-kpi-value">${k.value}</div>
          <div class="ov-kpi-sub">${escapeHTML(k.sub)}</div>
        </div>
      `).join('')}
    </div>
  `;
}

/* ---------- Findings by Severity ---------- */

function renderSeverityCard() {
  const d = _data;
  const total = (d.criticalViolations || 0) + (d.highViolations || 0) + (d.mediumViolations || 0) + (d.lowViolations || 0);
  const resolved = d.resolvedFindings || 0;
  const active = Math.max(0, total);
  const seg = [
    { label: 'Critical', value: d.criticalViolations || 0, color: 'var(--severity-critical)' },
    { label: 'High',     value: d.highViolations || 0,     color: 'var(--severity-high)' },
    { label: 'Medium',   value: d.mediumViolations || 0,   color: 'var(--severity-medium)' },
    { label: 'Low',      value: d.lowViolations || 0,      color: 'var(--severity-low)' },
  ];
  const maxWidth = Math.max(total, 1);
  return `
    <section class="ov-card">
      <div class="ov-card-head">
        <div>
          <div class="ov-card-title">Findings by severity</div>
          <div class="ov-card-sub">${active} active &middot; ${resolved} resolved via remediation</div>
        </div>
        <a href="#scans" class="ov-card-link">View scans →</a>
      </div>
      <div class="ov-sev-bar">
        ${seg.map((s) => s.value > 0
          ? `<div class="ov-sev-bar-seg" style="flex:${s.value};background:${s.color}" title="${s.label}: ${s.value}"></div>`
          : '').join('')}
        ${total === 0 ? '<div class="ov-sev-bar-empty">No active findings</div>' : ''}
      </div>
      <ul class="ov-sev-legend">
        ${seg.map((s) => `
          <li>
            <span class="ov-sev-dot" style="background:${s.color}"></span>
            <span class="ov-sev-label">${s.label}</span>
            <span class="ov-sev-count">${s.value}</span>
            <span class="ov-sev-share">${total > 0 ? Math.round((s.value / maxWidth) * 100) : 0}%</span>
          </li>
        `).join('')}
      </ul>
    </section>
  `;
}

/* ---------- Pipeline snapshot (Zelyo-specific) ---------- */

function renderPipelineCard() {
  const p = _data.pipelineSnapshot || { scan: 0, correlate: 0, fix: 0, verify: 0 };
  const stages = [
    { id: 'scan', label: 'Scan', color: '#6366F1', count: p.scan },
    { id: 'correlate', label: 'Correlate', color: '#A855F7', count: p.correlate },
    { id: 'fix', label: 'Fix', color: '#22D3EE', count: p.fix },
    { id: 'verify', label: 'Verify', color: '#10B981', count: p.verify },
  ];
  const total = stages.reduce((a, b) => a + b.count, 0);
  return `
    <section class="ov-card">
      <div class="ov-card-head">
        <div>
          <div class="ov-card-title">Pipeline in flight</div>
          <div class="ov-card-sub">${total} events this session &middot; live</div>
        </div>
        <a href="#pipeline" class="ov-card-link">Open pipeline →</a>
      </div>
      <div class="ov-pipeline">
        ${stages.map((s) => `
          <div class="ov-pipeline-stage" style="--stage-color:${s.color}">
            <div class="ov-pipeline-dot"></div>
            <div class="ov-pipeline-count">${s.count}</div>
            <div class="ov-pipeline-label">${s.label}</div>
          </div>
        `).join('')}
      </div>
      <div class="ov-pipeline-note">
        Detect → Correlate → Fix → Verify. Every fix is a reviewable PR — Zelyo never mutates your cluster without human approval.
      </div>
    </section>
  `;
}

/* ---------- Top failing checks ---------- */

function renderTopChecksCard() {
  const items = _data.topFailingChecks || [];
  return `
    <section class="ov-card">
      <div class="ov-card-head">
        <div>
          <div class="ov-card-title">Top failing checks</div>
          <div class="ov-card-sub">Rules with the most violations across all scans</div>
        </div>
      </div>
      ${items.length === 0 ? '<div class="ov-empty">No failing checks.</div>' : `
        <ul class="ov-rank-list">
          ${items.map((i, idx) => renderRankRow(i, idx, items[0].count)).join('')}
        </ul>
      `}
    </section>
  `;
}

/* ---------- Top affected resource kinds ---------- */

function renderTopKindsCard() {
  const items = _data.topAffectedKinds || [];
  return `
    <section class="ov-card">
      <div class="ov-card-head">
        <div>
          <div class="ov-card-title">Top affected resource types</div>
          <div class="ov-card-sub">Kinds with the most findings — click to scope a scan</div>
        </div>
      </div>
      ${items.length === 0 ? '<div class="ov-empty">No findings yet.</div>' : `
        <ul class="ov-rank-list">
          ${items.map((i, idx) => renderRankRow(i, idx, items[0].count)).join('')}
        </ul>
      `}
    </section>
  `;
}

function renderRankRow(item, idx, maxCount) {
  const pct = Math.max(6, Math.round((item.count / Math.max(maxCount, 1)) * 100));
  const sev = (item.severity || 'medium').toLowerCase();
  return `
    <li class="ov-rank-row">
      <span class="ov-rank-idx">${idx + 1}</span>
      <div class="ov-rank-main">
        <div class="ov-rank-head">
          <span class="ov-rank-name">${escapeHTML(item.name)}</span>
          <span class="pipeline-sev pipeline-sev-${sev}">${sev}</span>
        </div>
        <div class="ov-rank-bar-track">
          <div class="ov-rank-bar-fill" style="width:${pct}%;background:var(--severity-${sev},var(--severity-medium))"></div>
        </div>
      </div>
      <span class="ov-rank-count">${item.count}</span>
    </li>
  `;
}

/* ---------- Compliance strip ---------- */

function renderComplianceStrip() {
  const fw = _data.frameworks || [];
  if (fw.length === 0) return '';
  return `
    <section class="ov-card">
      <div class="ov-card-head">
        <div>
          <div class="ov-card-title">Compliance by framework</div>
          <div class="ov-card-sub">Aggregated from the latest report of each scan</div>
        </div>
        <a href="#compliance" class="ov-card-link">Manage presets →</a>
      </div>
      <div class="ov-fw-grid">
        ${fw.map(renderFrameworkTile).join('')}
      </div>
    </section>
  `;
}

function renderFrameworkTile(f) {
  const pct = f.passRate || 0;
  const color = pct >= 90 ? 'var(--success)' : pct >= 70 ? 'var(--warning)' : 'var(--severity-critical)';
  const passed = (f.totalControls || 0) - (f.failedControls || 0);
  return `
    <div class="ov-fw-tile">
      <div class="ov-fw-name">${escapeHTML((f.framework || '').toUpperCase())}</div>
      <div class="ov-fw-pct" style="color:${color}">${pct}<span class="ov-fw-pct-unit">%</span></div>
      <div class="ov-fw-bar-track">
        <div class="ov-fw-bar-fill" style="width:${pct}%;background:${color}"></div>
      </div>
      <div class="ov-fw-stat">${passed}/${f.totalControls || 0} passed · ${f.failedControls || 0} failed</div>
    </div>
  `;
}

/* ---------- Cloud accounts by risk ---------- */

function renderCloudAccountsCard() {
  const accounts = _data.accountsByRisk || [];
  if (accounts.length === 0) return '';
  return `
    <section class="ov-card">
      <div class="ov-card-head">
        <div>
          <div class="ov-card-title">Cloud accounts by risk</div>
          <div class="ov-card-sub">Ranked by critical & high-severity findings</div>
        </div>
        <a href="#cloud" class="ov-card-link">View cloud security →</a>
      </div>
      <div class="ov-acct-grid">
        ${accounts.map(renderAccountTile).join('')}
      </div>
    </section>
  `;
}

function renderAccountTile(a) {
  return `
    <div class="ov-acct-tile">
      <div class="ov-acct-top">
        <span class="ov-acct-provider">${escapeHTML((a.provider || '').toUpperCase())}</span>
        <span class="ov-acct-id">${escapeHTML(a.accountId || '')}</span>
      </div>
      <div class="ov-acct-name">${escapeHTML(a.name)}</div>
      <div class="ov-acct-sev">
        <span class="ov-acct-chip ov-acct-chip-critical" title="Critical">${a.critical || 0}</span>
        <span class="ov-acct-chip ov-acct-chip-high" title="High">${a.high || 0}</span>
        <span class="ov-acct-chip ov-acct-chip-medium" title="Medium">${a.medium || 0}</span>
      </div>
      <div class="ov-acct-foot">
        <span>${(a.findingsCount || 0).toLocaleString()} findings</span>
        <span>${(a.resources || 0).toLocaleString()} resources</span>
      </div>
    </div>
  `;
}

/* ---------- Trend sparkline ---------- */

function renderTrendCard() {
  const pts = _data.findingsTrend || [];
  if (pts.length === 0) return '';
  const maxVal = Math.max(1, ...pts.map((p) => Math.max(p.new, p.resolved)));
  const w = 680;
  const h = 120;
  const padX = 16;
  const padY = 12;
  const stepX = (w - padX * 2) / Math.max(1, pts.length - 1);
  const y = (v) => h - padY - ((v / maxVal) * (h - padY * 2));
  const x = (i) => padX + i * stepX;
  const newLine = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(p.new).toFixed(1)}`).join(' ');
  const resolvedLine = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(p.resolved).toFixed(1)}`).join(' ');
  const newArea = `${newLine} L${x(pts.length - 1).toFixed(1)},${h - padY} L${x(0).toFixed(1)},${h - padY} Z`;
  const last = pts[pts.length - 1] || {};

  return `
    <section class="ov-card">
      <div class="ov-card-head">
        <div>
          <div class="ov-card-title">Findings trend · last 7 days</div>
          <div class="ov-card-sub">New findings vs. remediations that closed them</div>
        </div>
        <div class="ov-trend-legend">
          <span><span class="ov-trend-dot" style="background:var(--severity-critical)"></span> New (${last.new || 0})</span>
          <span><span class="ov-trend-dot" style="background:var(--success)"></span> Resolved (${last.resolved || 0})</span>
        </div>
      </div>
      <svg class="ov-trend-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
        <defs>
          <linearGradient id="ov-trend-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="var(--severity-critical)" stop-opacity="0.3"/>
            <stop offset="100%" stop-color="var(--severity-critical)" stop-opacity="0"/>
          </linearGradient>
        </defs>
        <path d="${newArea}" fill="url(#ov-trend-grad)"/>
        <path d="${newLine}" fill="none" stroke="var(--severity-critical)" stroke-width="1.6"/>
        <path d="${resolvedLine}" fill="none" stroke="var(--success)" stroke-width="1.6" stroke-dasharray="4,3"/>
      </svg>
    </section>
  `;
}

/* ---------- Helpers ---------- */

function escapeHTML(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

/* ---------- Lifecycle ---------- */

export function render(container) {
  _container = container;
  _container.innerHTML = `<div class="ov-page"><div class="page-loading"><div class="skeleton" style="height:96px;margin-bottom:16px"></div><div class="skeleton" style="height:400px"></div></div></div>`;
  load();
  bindSSE();
}

export function destroy() {
  _sseHandlers.forEach(({ t, h }) => offSSE(t, h));
  _sseHandlers = [];
  _container = null;
}
