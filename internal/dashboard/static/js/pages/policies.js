/*
Copyright 2026 Zelyo AI
Dashboard — Policies Page Module
*/

const { fetchJSON, onSSE, offSSE, formatTime } = window.ZelyoApp;

let _container = null;
let _sortField = 'violationCount';
let _sortAsc = false;

/* ---------- SSE ---------- */

function handlePolicyUpdated() {
  loadPolicies();
}

/* ---------- Skeleton ---------- */

function renderSkeleton() {
  _container.innerHTML = `
    <div class="summary-bar skeleton" style="min-height:60px"></div>
    <div class="card skeleton" style="min-height:400px;margin-top:var(--space-lg)"></div>
  `;
}

/* ---------- Sorting ---------- */

function sortPolicies(policies, field, asc) {
  return [...policies].sort((a, b) => {
    let va = a[field];
    let vb = b[field];

    if (typeof va === 'string') va = va.toLowerCase();
    if (typeof vb === 'string') vb = vb.toLowerCase();

    if (va < vb) return asc ? -1 : 1;
    if (va > vb) return asc ? 1 : -1;
    return 0;
  });
}

function onHeaderClick(field) {
  if (_sortField === field) {
    _sortAsc = !_sortAsc;
  } else {
    _sortField = field;
    _sortAsc = field === 'name';
  }
  loadPolicies();
}

/* ---------- Render ---------- */

function renderPolicies(data) {
  if (!_container) return;

  const policies = sortPolicies(data.policies || [], _sortField, _sortAsc);

  const sortIndicator = (field) => {
    if (_sortField !== field) return '';
    return _sortAsc ? ' &#9650;' : ' &#9660;';
  };

  _container.innerHTML = `
    <div class="summary-bar">
      <div class="summary-stat">
        <span class="summary-stat-number">${data.totalPolicies ?? 0}</span>
        <span class="summary-stat-label">Total Policies</span>
      </div>
      <div class="summary-stat">
        <span class="summary-stat-number">${data.activePolicies ?? 0}</span>
        <span class="summary-stat-label">Active</span>
      </div>
      <div class="summary-stat">
        <span class="summary-stat-number">${data.totalViolations ?? 0}</span>
        <span class="summary-stat-label">Total Violations</span>
      </div>
    </div>

    <div class="card" style="margin-top:var(--space-lg)">
      <div class="card-header">
        <h3 class="card-title">Security Policies</h3>
      </div>
      <div class="card-body card-body--table">
        ${policies.length === 0
          ? '<div class="empty-state">No policies found</div>'
          : `
        <table class="data-table">
          <thead>
            <tr>
              <th class="sortable" data-sort="name">Name${sortIndicator('name')}</th>
              <th class="sortable" data-sort="severity">Severity${sortIndicator('severity')}</th>
              <th class="sortable" data-sort="phase">Phase${sortIndicator('phase')}</th>
              <th class="sortable" data-sort="violationCount">Violations${sortIndicator('violationCount')}</th>
              <th class="sortable" data-sort="ruleCount">Rules${sortIndicator('ruleCount')}</th>
              <th>Schedule</th>
              <th class="sortable" data-sort="lastEvaluated">Last Evaluated${sortIndicator('lastEvaluated')}</th>
              <th>Auto-Remediate</th>
            </tr>
          </thead>
          <tbody>
            ${policies.map(p => `
              <tr>
                <td class="cell-name">
                  <span class="resource-name">${escapeHTML(p.name)}</span>
                  <span class="resource-ns">${escapeHTML(p.namespace)}</span>
                </td>
                <td><span class="badge-${severityClass(p.severity)}">${capitalize(p.severity)}</span></td>
                <td><span class="phase-badge phase-${(p.phase || '').toLowerCase()}">${p.phase || '--'}</span></td>
                <td class="cell-number">${p.violationCount ?? 0}</td>
                <td class="cell-number">${p.ruleCount ?? 0}</td>
                <td><code class="schedule-code">${escapeHTML(p.schedule || '--')}</code></td>
                <td>${p.lastEvaluated ? formatTime(p.lastEvaluated) : 'Never'}</td>
                <td class="cell-center">${p.autoRemediate ? '<span class="check-icon" title="Enabled">&#10003;</span>' : '<span class="dash-icon" title="Disabled">&mdash;</span>'}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        `}
      </div>
    </div>
  `;

  /* Attach sort handlers */
  _container.querySelectorAll('.sortable').forEach(th => {
    th.style.cursor = 'pointer';
    th.addEventListener('click', () => onHeaderClick(th.dataset.sort));
  });
}

/* ---------- Data loading ---------- */

async function loadPolicies() {
  try {
    const data = await fetchJSON('/api/v1/policies');
    renderPolicies(data);
  } catch (err) {
    if (_container) {
      _container.innerHTML = `<div class="card"><div class="card-body"><div class="empty-state">Failed to load policies: ${escapeHTML(err.message)}</div></div></div>`;
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

/* ---------- Public API ---------- */

export function render(container) {
  _container = container;
  _sortField = 'violationCount';
  _sortAsc = false;
  renderSkeleton();
  loadPolicies();

  onSSE('policy.updated', handlePolicyUpdated);
}

export function destroy() {
  offSSE('policy.updated', handlePolicyUpdated);
  _container = null;
}
