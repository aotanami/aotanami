/*
Copyright 2026 Zelyo AI
Dashboard — Overview Page Module
*/

const { fetchJSON, onSSE, offSSE, formatTime, renderDonutChart } = window.ZelyoApp;

let _container = null;
let _activityItems = [];
const MAX_ACTIVITY = 50;

/* ---------- SSE handlers ---------- */

function handleOverviewRefresh() {
  loadOverview();
}

function handleActivityEvent(e) {
  const detail = e.detail || e;
  const entry = {
    timestamp: detail.timestamp || new Date().toISOString(),
    type: detail.type || 'info',
    description: describeEvent(detail),
  };

  _activityItems.unshift(entry);
  if (_activityItems.length > MAX_ACTIVITY) {
    _activityItems = _activityItems.slice(0, MAX_ACTIVITY);
  }
  renderActivityList();
}

function describeEvent(evt) {
  const t = evt.type || '';
  const d = evt.data || {};

  if (t === 'policy.updated')  return `Policy "${d.name || 'unknown'}" updated`;
  if (t === 'scan.updated')    return `Scan "${d.name || 'unknown'}" ${d.phase || 'updated'}`;
  if (t === 'cloud.updated')   return `Cloud account "${d.name || 'unknown'}" scan ${d.phase || 'updated'}`;
  if (t === 'config.updated')  return 'Operator configuration changed';
  if (t === 'overview.refresh') return 'Dashboard data refreshed';
  return `Event: ${t}`;
}

function eventIcon(type) {
  if (type.startsWith('policy'))  return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
  if (type.startsWith('scan'))    return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';
  if (type.startsWith('cloud'))   return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>';
  if (type.startsWith('config'))  return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>';
  return '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
}

/* ---------- Score color ---------- */

function scoreColor(score) {
  if (score >= 80) return 'var(--color-success)';
  if (score >= 60) return 'var(--color-warning)';
  return 'var(--color-critical)';
}

function scoreClass(score) {
  if (score >= 80) return 'score-good';
  if (score >= 60) return 'score-warn';
  return 'score-bad';
}

/* ---------- Skeleton ---------- */

function renderSkeleton() {
  _container.innerHTML = `
    <div class="kpi-grid">
      ${Array(6).fill('<div class="kpi-card skeleton" style="min-height:110px"></div>').join('')}
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--space-lg);margin-top:var(--space-lg)">
      <div class="card skeleton" style="min-height:280px"></div>
      <div class="card skeleton" style="min-height:280px"></div>
    </div>
    <div class="card skeleton" style="min-height:220px;margin-top:var(--space-lg)"></div>
  `;
}

/* ---------- Render overview ---------- */

function renderOverview(data) {
  if (!_container) return;

  const sc = data.securityScore ?? 0;

  _container.innerHTML = `
    <!-- Row 1: KPI Cards -->
    <div class="kpi-grid">
      <div class="kpi-card kpi-card--score">
        <div class="kpi-label">Security Score</div>
        <div class="kpi-value ${scoreClass(sc)}" style="color:${scoreColor(sc)}">
          ${sc}<span class="kpi-unit">/ 100</span>
        </div>
        <div class="kpi-bar">
          <div class="kpi-bar-fill" style="width:${sc}%;background:${scoreColor(sc)}"></div>
        </div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">Total Violations</div>
        <div class="kpi-value">${data.totalViolations ?? 0}</div>
        <div class="kpi-severity-dots">
          <span class="severity-dot badge-critical" title="Critical">${data.criticalViolations ?? 0}</span>
          <span class="severity-dot badge-high" title="High">${data.highViolations ?? 0}</span>
          <span class="severity-dot badge-medium" title="Medium">${data.mediumViolations ?? 0}</span>
        </div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">Active Policies</div>
        <div class="kpi-value">${data.activePolicies ?? 0}<span class="kpi-unit">/ ${data.totalPolicies ?? 0}</span></div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">Cluster Scans</div>
        <div class="kpi-value">${data.totalScans ?? 0}</div>
        <div class="kpi-sub">${data.totalFindings ?? 0} findings</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">Cloud Accounts</div>
        <div class="kpi-value">${data.cloudAccounts ?? 0}</div>
        <div class="kpi-sub">${data.cloudFindings ?? 0} findings</div>
      </div>

      <div class="kpi-card">
        <div class="kpi-label">Compliance</div>
        <div class="kpi-value">${(data.compliancePct ?? 0).toFixed(1)}<span class="kpi-unit">%</span></div>
        <div class="kpi-bar">
          <div class="kpi-bar-fill" style="width:${data.compliancePct ?? 0}%;background:${scoreColor(data.compliancePct ?? 0)}"></div>
        </div>
      </div>
    </div>

    <!-- Row 2: Charts & Summary -->
    <div class="overview-row2">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Severity Distribution</h3>
        </div>
        <div class="card-body">
          <div id="overview-donut" class="chart-container" style="display:flex;align-items:center;justify-content:center;min-height:220px"></div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Operator Summary</h3>
        </div>
        <div class="card-body">
          <div class="summary-stats">
            <div class="summary-stat-row">
              <span class="summary-stat-label">Operator Mode</span>
              <span class="phase-badge phase-${(data.operatorMode || 'audit').toLowerCase()}">${capitalize(data.operatorMode || 'audit')}</span>
            </div>
            <div class="summary-stat-row">
              <span class="summary-stat-label">Operator Phase</span>
              <span class="phase-badge phase-${(data.operatorPhase || 'Active').toLowerCase()}">${data.operatorPhase || 'Active'}</span>
            </div>
            <div class="summary-stat-row">
              <span class="summary-stat-label">Running Scans</span>
              <span class="summary-stat-value">${data.runningScans ?? 0}</span>
            </div>
            <div class="summary-stat-row">
              <span class="summary-stat-label">Completed Scans</span>
              <span class="summary-stat-value">${data.completedScans ?? 0}</span>
            </div>
            <div class="summary-stat-row">
              <span class="summary-stat-label">Active Incidents</span>
              <span class="summary-stat-value">${data.activeIncidents ?? 0}</span>
            </div>
            <div class="summary-stat-row">
              <span class="summary-stat-label">Last Scan</span>
              <span class="summary-stat-value">${data.lastScanTime ? formatTime(data.lastScanTime) : 'Never'}</span>
            </div>
            <div class="summary-stat-row">
              <span class="summary-stat-label">Updated</span>
              <span class="summary-stat-value">${data.updatedAt ? formatTime(data.updatedAt) : '--'}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Row 3: Recent Activity -->
    <div class="card">
      <div class="card-header">
        <h3 class="card-title">Recent Activity</h3>
      </div>
      <div class="card-body">
        <div id="overview-activity" class="activity-feed"></div>
      </div>
    </div>
  `;

  /* Donut chart */
  const donutEl = _container.querySelector('#overview-donut');
  const crit  = data.criticalViolations ?? 0;
  const high  = data.highViolations ?? 0;
  const med   = data.mediumViolations ?? 0;
  const total = data.totalViolations ?? 0;
  const low   = Math.max(0, total - crit - high - med);

  if (total > 0) {
    renderDonutChart(donutEl, [
      { label: 'Critical', value: crit, color: 'var(--color-critical)' },
      { label: 'High',     value: high, color: 'var(--color-high)' },
      { label: 'Medium',   value: med,  color: 'var(--color-warning)' },
      { label: 'Low',      value: low,  color: 'var(--color-info)' },
    ]);
  } else {
    donutEl.innerHTML = '<div class="empty-state">No violations detected</div>';
  }

  renderActivityList();
}

/* ---------- Activity list ---------- */

function renderActivityList() {
  const el = _container && _container.querySelector('#overview-activity');
  if (!el) return;

  if (_activityItems.length === 0) {
    el.innerHTML = '<div class="empty-state">Listening for live events&hellip;</div>';
    return;
  }

  el.innerHTML = _activityItems.map(item => `
    <div class="activity-item">
      <span class="activity-icon">${eventIcon(item.type)}</span>
      <span class="activity-text">${escapeHTML(item.description)}</span>
      <span class="activity-time">${formatTime(item.timestamp)}</span>
    </div>
  `).join('');
}

/* ---------- Data loading ---------- */

async function loadOverview() {
  try {
    const data = await fetchJSON('/api/v1/overview');
    renderOverview(data);
  } catch (err) {
    if (_container) {
      _container.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">Failed to load overview: ${escapeHTML(err.message)}</div></div></div>`;
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
  _activityItems = [];
  renderSkeleton();
  loadOverview();

  onSSE('overview.refresh', handleOverviewRefresh);
  onSSE('policy.updated',   handleActivityEvent);
  onSSE('scan.updated',     handleActivityEvent);
  onSSE('cloud.updated',    handleActivityEvent);
  onSSE('config.updated',   handleActivityEvent);
}

export function destroy() {
  offSSE('overview.refresh', handleOverviewRefresh);
  offSSE('policy.updated',   handleActivityEvent);
  offSSE('scan.updated',     handleActivityEvent);
  offSSE('cloud.updated',    handleActivityEvent);
  offSSE('config.updated',   handleActivityEvent);
  _container = null;
  _activityItems = [];
}
