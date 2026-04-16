/*
Copyright 2026 Zelyo AI
Dashboard — Cloud Page Module
*/

const { fetchJSON, onSSE, offSSE, formatTime } = window.ZelyoApp;

let _container = null;

/* ---------- SSE ---------- */

function handleCloudUpdated() {
  loadCloud();
}

/* ---------- Skeleton ---------- */

function renderSkeleton() {
  _container.innerHTML = `
    <div class="summary-bar skeleton" style="min-height:60px"></div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(380px,1fr));gap:var(--space-lg);margin-top:var(--space-lg)">
      ${Array(2).fill('<div class="account-card skeleton" style="min-height:300px"></div>').join('')}
    </div>
  `;
}

/* ---------- Provider badge ---------- */

function providerBadge(provider) {
  const p = (provider || '').toLowerCase();
  const colors = {
    aws:   { bg: '#FF9900', text: '#1a1a2e' },
    gcp:   { bg: '#4285F4', text: '#ffffff' },
    azure: { bg: '#0078D4', text: '#ffffff' },
  };
  const c = colors[p] || { bg: 'var(--color-surface-2)', text: 'var(--color-text)' };
  return `<span class="provider-badge" style="background:${c.bg};color:${c.text}">${(provider || 'Unknown').toUpperCase()}</span>`;
}

/* ---------- Render ---------- */

function renderCloud(data) {
  if (!_container) return;

  const accounts = data.accounts || [];

  _container.innerHTML = `
    <div class="summary-bar">
      <div class="summary-stat">
        <span class="summary-stat-number">${data.totalAccounts ?? 0}</span>
        <span class="summary-stat-label">Cloud Accounts</span>
      </div>
      <div class="summary-stat">
        <span class="summary-stat-number">${data.totalFindings ?? 0}</span>
        <span class="summary-stat-label">Total Cloud Findings</span>
      </div>
    </div>

    ${accounts.length === 0
      ? `
    <div class="card" style="margin-top:var(--space-lg)">
      <div class="card-body">
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;margin-bottom:var(--space-md)">
            <path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>
          </svg>
          <div>No cloud accounts configured</div>
        </div>
      </div>
    </div>
    `
      : `
    <div class="cloud-grid" style="margin-top:var(--space-lg)">
      ${accounts.map(a => renderAccountCard(a)).join('')}
    </div>
    `}
  `;
}

function renderAccountCard(account) {
  const phaseClass = (account.phase || '').toLowerCase();
  const findings = account.findingsSummary || {};
  const regions = account.regions || [];
  const categories = account.scanCategories || [];

  return `
    <div class="account-card">
      <div class="account-card-header">
        <div class="account-card-title">
          ${providerBadge(account.provider)}
          <h4 class="account-card-name">${escapeHTML(account.name)}</h4>
        </div>
        <span class="phase-badge phase-${phaseClass}">${account.phase || '--'}</span>
      </div>

      <div class="account-card-body">
        <div class="account-card-id">
          <span class="account-card-label">Account ID</span>
          <code class="account-id-code">${escapeHTML(account.accountId || '--')}</code>
        </div>

        <div class="account-card-severity">
          <span class="severity-count severity-count--critical" title="Critical">
            <span class="severity-dot-sm severity-dot-sm--critical"></span>
            ${findings.critical ?? 0}
          </span>
          <span class="severity-count severity-count--high" title="High">
            <span class="severity-dot-sm severity-dot-sm--high"></span>
            ${findings.high ?? 0}
          </span>
          <span class="severity-count severity-count--medium" title="Medium">
            <span class="severity-dot-sm severity-dot-sm--medium"></span>
            ${findings.medium ?? 0}
          </span>
          <span class="severity-count severity-count--low" title="Low">
            <span class="severity-dot-sm severity-dot-sm--low"></span>
            ${findings.low ?? 0}
          </span>
        </div>

        <div class="account-card-meta">
          <div class="account-card-stat">
            <span class="account-card-label">Resources Scanned</span>
            <span class="account-card-value">${account.resourcesScanned ?? 0}</span>
          </div>
          <div class="account-card-stat">
            <span class="account-card-label">Total Findings</span>
            <span class="account-card-value">${account.findingsCount ?? 0}</span>
          </div>
          <div class="account-card-stat">
            <span class="account-card-label">Last Scan</span>
            <span class="account-card-value">${account.lastScanTime ? formatTime(account.lastScanTime) : 'Never'}</span>
          </div>
        </div>

        <div class="account-card-tags">
          <div class="account-card-tag-group">
            <span class="account-card-label">Regions</span>
            <div class="tag-list">
              ${regions.map(r => `<span class="region-tag">${escapeHTML(r)}</span>`).join('')}
              ${regions.length === 0 ? '<span class="tag-empty">--</span>' : ''}
            </div>
          </div>
          <div class="account-card-tag-group">
            <span class="account-card-label">Scan Categories</span>
            <div class="tag-list">
              ${categories.map(c => `<span class="category-tag">${escapeHTML(c.toUpperCase())}</span>`).join('')}
              ${categories.length === 0 ? '<span class="tag-empty">--</span>' : ''}
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}

/* ---------- Data loading ---------- */

async function loadCloud() {
  try {
    const data = await fetchJSON('/api/v1/cloud');
    renderCloud(data);
  } catch (err) {
    if (_container) {
      _container.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">Failed to load cloud accounts: ${escapeHTML(err.message)}</div></div></div>`;
    }
  }
}

/* ---------- Helpers ---------- */

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

/* ---------- Public API ---------- */

export function render(container) {
  _container = container;
  renderSkeleton();
  loadCloud();

  onSSE('cloud.updated', handleCloudUpdated);
}

export function destroy() {
  offSSE('cloud.updated', handleCloudUpdated);
  _container = null;
}
