/*
Copyright 2026 Zelyo AI
Dashboard — Scans Page Module
*/

const { fetchJSON, onSSE, offSSE, formatTime } = window.ZelyoApp;

let _container = null;
let _expandedScan = null;
let _reportData = null;

/* ---------- SSE ---------- */

function handleScanUpdated() {
  loadScans();
}

/* ---------- Skeleton ---------- */

function renderSkeleton() {
  _container.innerHTML = `
    <div class="summary-bar skeleton" style="min-height:60px"></div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:var(--space-lg);margin-top:var(--space-lg)">
      ${Array(3).fill('<div class="scan-card skeleton" style="min-height:200px"></div>').join('')}
    </div>
  `;
}

/* ---------- Cron to human-readable ---------- */

function cronToHuman(cron) {
  if (!cron) return '--';
  const parts = cron.split(/\s+/);
  if (parts.length < 5) return cron;

  const [min, hour, dom, mon, dow] = parts;

  if (dom === '*' && mon === '*' && dow === '*') {
    if (hour === '*' && min.startsWith('*/')) return `Every ${min.slice(2)} minutes`;
    if (hour === '*') return `At minute ${min} every hour`;
    if (min === '0' && hour.startsWith('*/')) return `Every ${hour.slice(2)} hours`;
    if (min === '0') return `Daily at ${hour.padStart(2, '0')}:00`;
    return `Daily at ${hour.padStart(2, '0')}:${min.padStart(2, '0')}`;
  }
  if (dow !== '*' && dom === '*' && mon === '*') {
    const days = { 0: 'Sun', 1: 'Mon', 2: 'Tue', 3: 'Wed', 4: 'Thu', 5: 'Fri', 6: 'Sat' };
    const dayName = days[dow] || dow;
    return `${dayName} at ${hour.padStart(2, '0')}:${min.padStart(2, '0')}`;
  }

  return cron;
}

/* ---------- Render ---------- */

function renderScans(data) {
  if (!_container) return;

  const scans = data.scans || [];

  _container.innerHTML = `
    <div class="summary-bar">
      <div class="summary-stat">
        <span class="summary-stat-number">${data.totalScans ?? 0}</span>
        <span class="summary-stat-label">Total Scans</span>
      </div>
      <div class="summary-stat">
        <span class="summary-stat-number">${data.runningScans ?? 0}</span>
        <span class="summary-stat-label">Running</span>
      </div>
      <div class="summary-stat">
        <span class="summary-stat-number">${data.totalFindings ?? 0}</span>
        <span class="summary-stat-label">Total Findings</span>
      </div>
    </div>

    ${scans.length === 0
      ? '<div class="card" style="margin-top:var(--space-lg)"><div class="card-body"><div class="empty-state">No scans configured</div></div></div>'
      : `
    <div class="scan-grid" style="margin-top:var(--space-lg)">
      ${scans.map(s => renderScanCard(s)).join('')}
    </div>
    `}

    <div id="scans-report-panel"></div>
  `;

  /* Attach click handlers to scan cards */
  _container.querySelectorAll('.scan-card[data-report]').forEach(card => {
    card.addEventListener('click', () => {
      const reportName = card.dataset.report;
      const ns = card.dataset.ns || 'zelyo-system';
      if (_expandedScan === reportName) {
        _expandedScan = null;
        _reportData = null;
        clearReportPanel();
        card.classList.remove('scan-card--active');
      } else {
        _container.querySelectorAll('.scan-card--active').forEach(c => c.classList.remove('scan-card--active'));
        _expandedScan = reportName;
        card.classList.add('scan-card--active');
        loadReport(reportName, ns);
      }
    });
  });
}

function renderScanCard(scan) {
  const isRunning = (scan.phase || '').toLowerCase() === 'running';
  const phaseClass = (scan.phase || '').toLowerCase();
  const hasReport = scan.lastReportName && scan.lastReportName.length > 0;

  return `
    <div class="scan-card ${hasReport ? 'scan-card--clickable' : ''} ${_expandedScan === scan.lastReportName ? 'scan-card--active' : ''}"
         ${hasReport ? `data-report="${escapeAttr(scan.lastReportName)}" data-ns="${escapeAttr(scan.namespace)}"` : ''}>
      <div class="scan-card-header">
        <h4 class="scan-card-name">${escapeHTML(scan.name)}</h4>
        <span class="phase-badge phase-${phaseClass} ${isRunning ? 'pulse' : ''}">${scan.phase || '--'}</span>
      </div>
      <div class="scan-card-body">
        <div class="scan-card-stat">
          <span class="scan-card-stat-label">Schedule</span>
          <span class="scan-card-stat-value">${cronToHuman(scan.schedule)}</span>
        </div>
        <div class="scan-card-stat">
          <span class="scan-card-stat-label">Findings</span>
          <span class="scan-card-stat-value scan-card-stat-value--lg">${scan.findingsCount ?? 0}</span>
        </div>
        <div class="scan-card-stat">
          <span class="scan-card-stat-label">Scanners</span>
          <span class="scan-card-stat-value">${scan.scannerCount ?? 0}</span>
        </div>
        <div class="scan-card-stat">
          <span class="scan-card-stat-label">Last Completed</span>
          <span class="scan-card-stat-value">${scan.completedAt ? formatTime(scan.completedAt) : 'Never'}</span>
        </div>
      </div>
      <div class="scan-card-scanners">
        ${(scan.scanners || []).slice(0, 6).map(s => `<span class="scanner-tag">${escapeHTML(s)}</span>`).join('')}
        ${(scan.scanners || []).length > 6 ? `<span class="scanner-tag scanner-tag--more">+${scan.scanners.length - 6} more</span>` : ''}
      </div>
      ${hasReport ? '<div class="scan-card-footer">Click to view findings</div>' : ''}
    </div>
  `;
}

/* ---------- Report panel ---------- */

function clearReportPanel() {
  const panel = _container && _container.querySelector('#scans-report-panel');
  if (panel) panel.innerHTML = '';
}

async function loadReport(name, namespace) {
  const panel = _container && _container.querySelector('#scans-report-panel');
  if (!panel) return;

  panel.innerHTML = `
    <div class="card" style="margin-top:var(--space-lg)">
      <div class="card-body"><div class="skeleton" style="height:200px"></div></div>
    </div>
  `;

  try {
    const data = await fetchJSON(`/api/v1/reports/${encodeURIComponent(name)}?namespace=${encodeURIComponent(namespace)}`);
    _reportData = data;
    renderReportPanel(panel, data);
  } catch (err) {
    panel.innerHTML = `
      <div class="card" style="margin-top:var(--space-lg)">
        <div class="card-body"><div class="empty-state">Failed to load report: ${escapeHTML(err.message)}</div></div>
      </div>
    `;
  }
}

function renderReportPanel(panel, data) {
  const findings = data.findings || [];
  const summary = data.summary || {};

  panel.innerHTML = `
    <div class="card" style="margin-top:var(--space-lg)">
      <div class="card-header">
        <h3 class="card-title">Report: ${escapeHTML(data.name)}</h3>
        <div class="report-summary-badges">
          <span class="badge-critical">${summary.critical ?? 0} Critical</span>
          <span class="badge-high">${summary.high ?? 0} High</span>
          <span class="badge-medium">${summary.medium ?? 0} Medium</span>
          <span class="badge-low">${summary.low ?? 0} Low</span>
        </div>
      </div>
      <div class="card-body card-body--table">
        ${findings.length === 0
          ? '<div class="empty-state">No findings in this report</div>'
          : `
        <table class="data-table">
          <thead>
            <tr>
              <th>Severity</th>
              <th>Category</th>
              <th>Title</th>
              <th>Resource</th>
              <th>Remediated</th>
            </tr>
          </thead>
          <tbody>
            ${findings.map(f => `
              <tr>
                <td><span class="badge-${severityClass(f.severity)}">${capitalize(f.severity)}</span></td>
                <td>${escapeHTML(f.category || '--')}</td>
                <td>
                  <span class="finding-title">${escapeHTML(f.title)}</span>
                  ${f.description ? `<span class="finding-desc">${escapeHTML(f.description)}</span>` : ''}
                  ${f.recommendation ? `<span class="finding-rec">${escapeHTML(f.recommendation)}</span>` : ''}
                </td>
                <td><code class="resource-code">${escapeHTML(f.resource || '--')}</code></td>
                <td class="cell-center">${f.remediated ? '<span class="check-icon" title="Yes">&#10003;</span>' : '<span class="dash-icon" title="No">&mdash;</span>'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        `}
      </div>
    </div>
  `;
}

/* ---------- Data loading ---------- */

async function loadScans() {
  try {
    const data = await fetchJSON('/api/v1/scans');
    renderScans(data);
  } catch (err) {
    if (_container) {
      _container.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">Failed to load scans: ${escapeHTML(err.message)}</div></div></div>`;
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

function escapeHTML(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ---------- Public API ---------- */

export function render(container) {
  _container = container;
  _expandedScan = null;
  _reportData = null;
  renderSkeleton();
  loadScans();

  onSSE('scan.updated', handleScanUpdated);
}

export function destroy() {
  offSSE('scan.updated', handleScanUpdated);
  _container = null;
  _expandedScan = null;
  _reportData = null;
}
