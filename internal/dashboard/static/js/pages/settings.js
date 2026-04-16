/*
Copyright 2026 Zelyo AI
Dashboard — Settings Page Module (read-only)
*/

const { fetchJSON, onSSE, offSSE } = window.ZelyoApp;

let _container = null;

/* ---------- SSE ---------- */

function handleConfigUpdated() {
  loadSettings();
}

/* ---------- Skeleton ---------- */

function renderSkeleton() {
  _container.innerHTML = `
    <div class="settings-section skeleton" style="min-height:260px"></div>
    <div class="settings-section skeleton" style="min-height:160px;margin-top:var(--space-lg)"></div>
    <div class="settings-section skeleton" style="min-height:160px;margin-top:var(--space-lg)"></div>
    <div class="settings-section skeleton" style="min-height:160px;margin-top:var(--space-lg)"></div>
    <div class="settings-section skeleton" style="min-height:120px;margin-top:var(--space-lg)"></div>
  `;
}

/* ---------- Badge helpers ---------- */

function modeBadge(mode) {
  const m = (mode || 'audit').toLowerCase();
  if (m === 'protect') return '<span class="phase-badge phase-active" style="background:var(--color-success-bg);color:var(--color-success)">Protect</span>';
  return '<span class="phase-badge" style="background:var(--color-info-bg);color:var(--color-info)">Audit</span>';
}

function keyStatusBadge(status) {
  const s = (status || '').toLowerCase();
  if (s === 'verified') return '<span class="phase-badge phase-active" style="background:var(--color-success-bg);color:var(--color-success)">Verified</span>';
  if (s === 'pending')  return '<span class="phase-badge phase-pending" style="background:var(--color-warning-bg);color:var(--color-warning)">Pending</span>';
  if (s === 'invalid')  return '<span class="phase-badge phase-error" style="background:var(--color-critical-bg);color:var(--color-critical)">Invalid</span>';
  return `<span class="phase-badge">${escapeHTML(status || '--')}</span>`;
}

function phaseBadge(phase) {
  const p = (phase || '').toLowerCase();
  return `<span class="phase-badge phase-${p}">${escapeHTML(phase || '--')}</span>`;
}

/* ---------- Section builder ---------- */

function section(title, content) {
  return `
    <div class="settings-section">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">${escapeHTML(title)}</h3>
        </div>
        <div class="card-body">
          ${content}
        </div>
      </div>
    </div>
  `;
}

function emptySection(msg) {
  return `<div class="empty-state">${escapeHTML(msg)}</div>`;
}

/* ---------- Render ---------- */

function renderSettings(data) {
  if (!_container) return;

  const token = data.tokenUsage || {};
  const notifications = data.notifications || [];
  const repos = data.gitopsRepos || [];
  const remediation = data.remediation || [];
  const monitoring = data.monitoring || [];

  _container.innerHTML = `
    <!-- Operator Configuration -->
    ${section('Operator Configuration', `
      <div class="settings-grid">
        <div class="settings-row">
          <span class="settings-label">Mode</span>
          <span class="settings-value">${modeBadge(data.mode)}</span>
        </div>
        <div class="settings-row">
          <span class="settings-label">Phase</span>
          <span class="settings-value">${phaseBadge(data.phase)}</span>
        </div>
        <div class="settings-row">
          <span class="settings-label">LLM Provider</span>
          <span class="settings-value">${escapeHTML(data.llmProvider || '--')}</span>
        </div>
        <div class="settings-row">
          <span class="settings-label">LLM Model</span>
          <span class="settings-value"><code class="model-code">${escapeHTML(data.llmModel || '--')}</code></span>
        </div>
        <div class="settings-row">
          <span class="settings-label">API Key Status</span>
          <span class="settings-value">${keyStatusBadge(data.llmKeyStatus)}</span>
        </div>
        <div class="settings-divider"></div>
        <div class="settings-row">
          <span class="settings-label">Tokens Today</span>
          <span class="settings-value settings-value--mono">${formatNumber(token.tokensToday ?? 0)}</span>
        </div>
        <div class="settings-row">
          <span class="settings-label">Tokens This Month</span>
          <span class="settings-value settings-value--mono">${formatNumber(token.tokensMonth ?? 0)}</span>
        </div>
        <div class="settings-row">
          <span class="settings-label">Estimated Cost</span>
          <span class="settings-value settings-value--mono">${escapeHTML(token.estimatedCost || '$0.00')}</span>
        </div>
      </div>
    `)}

    <!-- Notification Channels -->
    ${section('Notification Channels',
      notifications.length === 0
        ? emptySection('No notification channels configured')
        : `
      <table class="data-table">
        <thead>
          <tr><th>Name</th><th>Type</th><th>Phase</th></tr>
        </thead>
        <tbody>
          ${notifications.map(n => `
            <tr>
              <td>${escapeHTML(n.name)}</td>
              <td><span class="type-badge">${escapeHTML(capitalize(n.type))}</span></td>
              <td>${phaseBadge(n.phase)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      `
    )}

    <!-- GitOps Repositories -->
    ${section('GitOps Repositories',
      repos.length === 0
        ? emptySection('No GitOps repositories configured')
        : `
      <table class="data-table">
        <thead>
          <tr><th>Name</th><th>URL</th><th>Branch</th><th>Provider</th><th>Phase</th><th>Source Type</th></tr>
        </thead>
        <tbody>
          ${repos.map(r => `
            <tr>
              <td>${escapeHTML(r.name)}</td>
              <td><code class="url-code">${escapeHTML(r.url || '--')}</code></td>
              <td><code>${escapeHTML(r.branch || '--')}</code></td>
              <td>${escapeHTML(capitalize(r.provider))}</td>
              <td>${phaseBadge(r.phase)}</td>
              <td><span class="type-badge">${escapeHTML(r.sourceType || '--')}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      `
    )}

    <!-- Remediation Policies -->
    ${section('Remediation Policies',
      remediation.length === 0
        ? emptySection('No remediation policies configured')
        : `
      <table class="data-table">
        <thead>
          <tr><th>Name</th><th>GitOps Repo</th><th>Severity Filter</th><th>Dry Run</th><th>Phase</th></tr>
        </thead>
        <tbody>
          ${remediation.map(r => `
            <tr>
              <td>${escapeHTML(r.name)}</td>
              <td>${escapeHTML(r.gitopsRepo || '--')}</td>
              <td><span class="badge-${severityClass(r.severityFilter)}">${capitalize(r.severityFilter || '--')}</span></td>
              <td class="cell-center">${r.dryRun ? '<span class="check-icon" title="Yes">&#10003;</span>' : '<span class="dash-icon" title="No">&mdash;</span>'}</td>
              <td>${phaseBadge(r.phase)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      `
    )}

    <!-- Monitoring -->
    ${section('Monitoring',
      monitoring.length === 0
        ? emptySection('No monitoring configurations')
        : `
      <table class="data-table">
        <thead>
          <tr><th>Name</th><th>Phase</th><th>Events Processed</th></tr>
        </thead>
        <tbody>
          ${monitoring.map(m => `
            <tr>
              <td>${escapeHTML(m.name)}</td>
              <td>${phaseBadge(m.phase)}</td>
              <td class="cell-number">${formatNumber(m.eventsProcessed ?? 0)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
      `
    )}
  `;
}

/* ---------- Data loading ---------- */

async function loadSettings() {
  try {
    const data = await fetchJSON('/api/v1/settings');
    renderSettings(data);
  } catch (err) {
    if (_container) {
      _container.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">Failed to load settings: ${escapeHTML(err.message)}</div></div></div>`;
    }
  }
}

/* ---------- Helpers ---------- */

function severityClass(s) {
  const m = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' };
  return m[(s || '').toLowerCase()] || 'info';
}

function capitalize(s) {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : '';
}

function formatNumber(n) {
  return Number(n).toLocaleString();
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
  loadSettings();

  onSSE('config.updated', handleConfigUpdated);
}

export function destroy() {
  offSSE('config.updated', handleConfigUpdated);
  _container = null;
}
