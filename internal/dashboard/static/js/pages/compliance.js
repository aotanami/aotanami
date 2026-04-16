/*
Copyright 2026 Zelyo AI
Dashboard — Compliance Page Module
*/

const { fetchJSON, onSSE, offSSE } = window.ZelyoApp;

let _container = null;

/* ---------- SSE ---------- */

function handleComplianceRefresh() {
  loadCompliance();
}

/* ---------- Skeleton ---------- */

function renderSkeleton() {
  _container.innerHTML = `
    <div class="card skeleton" style="min-height:80px"></div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:var(--space-lg);margin-top:var(--space-lg)">
      ${Array(3).fill('<div class="card skeleton" style="min-height:240px"></div>').join('')}
    </div>
  `;
}

/* ---------- Progress ring SVG ---------- */

function progressRingSVG(pct, size) {
  const sz = size || 120;
  const strokeWidth = 8;
  const radius = (sz - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (pct / 100) * circumference;

  let color;
  if (pct >= 90) color = 'var(--color-success)';
  else if (pct >= 70) color = 'var(--color-warning)';
  else color = 'var(--color-critical)';

  return `
    <svg class="progress-ring" width="${sz}" height="${sz}" viewBox="0 0 ${sz} ${sz}">
      <circle
        class="progress-ring-bg"
        cx="${sz / 2}" cy="${sz / 2}" r="${radius}"
        fill="none"
        stroke="var(--color-surface-2)"
        stroke-width="${strokeWidth}"
      />
      <circle
        class="progress-ring-fill"
        cx="${sz / 2}" cy="${sz / 2}" r="${radius}"
        fill="none"
        stroke="${color}"
        stroke-width="${strokeWidth}"
        stroke-linecap="round"
        stroke-dasharray="${circumference}"
        stroke-dashoffset="${offset}"
        transform="rotate(-90 ${sz / 2} ${sz / 2})"
      />
      <text
        x="${sz / 2}" y="${sz / 2}"
        text-anchor="middle"
        dominant-baseline="central"
        class="progress-ring-text"
        fill="var(--color-text)"
        font-size="${sz * 0.22}px"
        font-weight="600"
      >${pct.toFixed(0)}%</text>
    </svg>
  `;
}

/* ---------- Overall progress bar ---------- */

function overallBar(pct) {
  let color;
  if (pct >= 90) color = 'var(--color-success)';
  else if (pct >= 70) color = 'var(--color-warning)';
  else color = 'var(--color-critical)';

  return `
    <div class="card compliance-overall">
      <div class="card-body">
        <div class="compliance-overall-header">
          <h3 class="card-title">Overall Compliance</h3>
          <span class="compliance-overall-pct" style="color:${color}">${pct.toFixed(1)}%</span>
        </div>
        <div class="progress-bar">
          <div class="progress-bar-fill" style="width:${pct}%;background:${color}"></div>
        </div>
      </div>
    </div>
  `;
}

/* ---------- Render ---------- */

function renderCompliance(data) {
  if (!_container) return;

  const frameworks = data.frameworks || [];
  const overall = data.overallPct ?? 0;

  if (frameworks.length === 0) {
    _container.innerHTML = `
      ${overallBar(overall)}
      <div class="card" style="margin-top:var(--space-lg)">
        <div class="card-body">
          <div class="empty-state">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:var(--space-md)">
              <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
            </svg>
            <div>No compliance data available.</div>
            <div style="font-size:var(--text-sm);margin-top:var(--space-xs);opacity:0.7">Run a scan with compliance frameworks enabled.</div>
          </div>
        </div>
      </div>
    `;
    return;
  }

  _container.innerHTML = `
    ${overallBar(overall)}
    <div class="compliance-grid" style="margin-top:var(--space-lg)">
      ${frameworks.map(fw => renderFrameworkCard(fw)).join('')}
    </div>
  `;
}

function renderFrameworkCard(fw) {
  const passRate = fw.passRate ?? 0;
  const total = fw.totalControls ?? 0;
  const failed = fw.failedControls ?? 0;
  const passed = Math.max(0, total - failed);
  const source = fw.source || 'unknown';

  return `
    <div class="card compliance-card">
      <div class="card-body compliance-card-body">
        <div class="compliance-card-ring">
          ${progressRingSVG(passRate, 110)}
        </div>
        <div class="compliance-card-info">
          <h4 class="compliance-card-name">${escapeHTML((fw.framework || '').toUpperCase())}</h4>
          <div class="compliance-card-stat">
            <span class="compliance-card-stat-value">${passed}</span>
            <span class="compliance-card-stat-label">of ${total} controls passed</span>
          </div>
          <div class="compliance-card-stat">
            <span class="compliance-card-stat-value compliance-card-stat-value--failed">${failed}</span>
            <span class="compliance-card-stat-label">failed</span>
          </div>
          <div class="compliance-card-source">
            <span class="source-badge">${escapeHTML(capitalize(source))}</span>
          </div>
        </div>
      </div>
    </div>
  `;
}

/* ---------- Data loading ---------- */

async function loadCompliance() {
  try {
    const data = await fetchJSON('/api/v1/compliance');
    renderCompliance(data);
  } catch (err) {
    if (_container) {
      _container.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">Failed to load compliance data: ${escapeHTML(err.message)}</div></div></div>`;
    }
  }
}

/* ---------- Helpers ---------- */

function capitalize(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/* ---------- Public API ---------- */

export function render(container) {
  _container = container;
  renderSkeleton();
  loadCompliance();

  onSSE('scan.updated', handleComplianceRefresh);
  onSSE('cloud.updated', handleComplianceRefresh);
}

export function destroy() {
  offSSE('scan.updated', handleComplianceRefresh);
  offSSE('cloud.updated', handleComplianceRefresh);
  _container = null;
}
