/**
 * Zelyo Operator Dashboard — SPA Router, SSE Client, Chart Utils
 */

// --- Fetch helper ---
async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

// --- SSE Client ---
const sseHandlers = {};
let sseSource = null;

function initSSE() {
  if (sseSource) return;
  sseSource = new EventSource('/api/v1/events');
  sseSource.onmessage = (e) => {
    try {
      const event = JSON.parse(e.data);
      dispatchSSE(event.type, event);
    } catch (_) { /* ignore parse errors */ }
  };
  const eventTypes = [
    'policy.updated', 'scan.updated', 'cloud.updated', 'config.updated', 'overview.refresh',
    // Pipeline events (emitted by internal/events bus).
    'scan.started', 'scan.completed', 'finding.detected', 'report.created',
    'correlation.grouped', 'remediation.drafted', 'pr.opened', 'pr.merged',
    'finding.resolved',
    'config.pr.drafted', 'config.applied',
  ];
  // Only these events are important enough to warrant a toast. The rest
  // stream into the Pipeline view and don't need to interrupt the user.
  const TOAST_WHITELIST = new Set([
    'pr.merged',
    'config.pr.drafted',
    'config.applied',
  ]);
  eventTypes.forEach(type => {
    sseSource.addEventListener(type, (e) => {
      try {
        const data = JSON.parse(e.data);
        dispatchSSE(type, data);
        if (TOAST_WHITELIST.has(type)) showToast(type, data);
      } catch (_) { /* ignore */ }
    });
  });
}

function dispatchSSE(type, data) {
  const handlers = sseHandlers[type];
  if (handlers) handlers.forEach(h => h(data));
}

function onSSE(type, handler) {
  if (!sseHandlers[type]) sseHandlers[type] = [];
  sseHandlers[type].push(handler);
}

function offSSE(type, handler) {
  if (!sseHandlers[type]) return;
  sseHandlers[type] = sseHandlers[type].filter(h => h !== handler);
}

// --- Toast notifications ---
const TOAST_MAX = 3;
const TOAST_DUR = 2600;

function showToast(type, payload) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  // Cap concurrent toasts — drop oldest.
  while (container.children.length >= TOAST_MAX) {
    container.firstChild.remove();
  }

  const info = describeToast(type, payload);
  const toast = document.createElement('div');
  toast.className = `toast toast-${info.tone}`;
  toast.innerHTML = `
    <span class="toast-dot"></span>
    <div class="toast-body">
      <div class="toast-title">${escapeAttr(info.title)}</div>
      ${info.detail ? `<div class="toast-detail">${escapeAttr(info.detail)}</div>` : ''}
    </div>
    <button class="toast-close" aria-label="Dismiss">${toastCloseIcon()}</button>
    <span class="toast-progress"></span>
  `;
  container.appendChild(toast);

  const close = () => {
    if (toast._closed) return;
    toast._closed = true;
    toast.classList.add('toast-exit');
    setTimeout(() => toast.remove(), 180);
  };
  toast.querySelector('.toast-close').addEventListener('click', close);

  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(close, TOAST_DUR);
}

function describeToast(type, payload) {
  // SSE envelope: { type, data: <events.Event>, timestamp }.
  const ev = (payload && payload.data) || {};
  const title = ev.title || humanizeType(type);
  const detail = ev.detail || '';
  let tone = 'info';
  if (type === 'pr.merged' || ev.level === 'success') tone = 'success';
  else if (type === 'config.applied' || ev.level === 'warning') tone = 'warn';
  else if (ev.level === 'error') tone = 'error';
  return { title, detail, tone };
}

function humanizeType(type) {
  return type.replace(/\./g, ' · ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function toastCloseIcon() {
  return '<svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><path d="M1 1l8 8M9 1l-8 8"/></svg>';
}

function escapeAttr(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

// --- Time formatting ---
function formatTime(isoString) {
  if (!isoString) return '--';
  const date = new Date(isoString);
  const now = new Date();
  const diff = Math.floor((now - date) / 1000);
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatDateTime(isoString) {
  if (!isoString) return '--';
  return new Date(isoString).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

// --- Badge helpers ---
function severityBadge(level) {
  if (!level) return '';
  return `<span class="badge badge-${level}">${level}</span>`;
}

function phaseBadge(phase) {
  if (!phase) return '';
  const cls = phase.toLowerCase();
  const pulse = cls === 'running' ? ' pulse' : '';
  return `<span class="phase-badge phase-${cls}${pulse}">${phase}</span>`;
}

// --- SVG Chart utilities ---

function renderDonutChart(container, segments, opts = {}) {
  const size = opts.size || 160;
  const stroke = opts.stroke || 20;
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const total = segments.reduce((s, seg) => s + seg.value, 0);

  let html = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">`;
  // Background ring
  html += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--bg-elevated)" stroke-width="${stroke}"/>`;

  if (total > 0) {
    let offset = 0;
    segments.forEach(seg => {
      const pct = seg.value / total;
      const dashLen = pct * circumference;
      const dashOffset = -offset * circumference + circumference * 0.25;
      html += `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${seg.color}" stroke-width="${stroke}" stroke-dasharray="${dashLen} ${circumference - dashLen}" stroke-dashoffset="${dashOffset}" style="transition: stroke-dasharray 0.6s ease"/>`;
      offset += pct;
    });
  }

  // Center text
  if (opts.centerText !== undefined) {
    html += `<text x="${cx}" y="${cy - 6}" text-anchor="middle" fill="var(--text)" font-size="24" font-weight="700">${opts.centerText}</text>`;
    if (opts.centerLabel) {
      html += `<text x="${cx}" y="${cy + 14}" text-anchor="middle" fill="var(--text-secondary)" font-size="11">${opts.centerLabel}</text>`;
    }
  }
  html += '</svg>';
  container.innerHTML = html;
}

function renderBarChart(container, items) {
  const maxVal = Math.max(...items.map(i => i.value), 1);
  let html = '<div class="bar-chart">';
  items.forEach(item => {
    const pct = (item.value / maxVal) * 100;
    html += `
      <div class="bar-row">
        <span class="bar-label">${item.label}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%;background:${item.color}"></div>
        </div>
        <span class="bar-value">${item.value}</span>
      </div>`;
  });
  html += '</div>';
  container.innerHTML = html;
}

function renderProgressRing(container, pct, opts = {}) {
  const size = opts.size || 80;
  const stroke = opts.stroke || 6;
  const r = (size - stroke) / 2;
  const cx = size / 2;
  const cy = size / 2;
  const circumference = 2 * Math.PI * r;
  const dashLen = (pct / 100) * circumference;
  const color = pct >= 90 ? 'var(--success)' : pct >= 70 ? 'var(--severity-medium)' : 'var(--severity-critical)';

  container.innerHTML = `
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="var(--bg-elevated)" stroke-width="${stroke}"/>
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${color}" stroke-width="${stroke}"
        stroke-dasharray="${dashLen} ${circumference - dashLen}" stroke-dashoffset="${circumference * 0.25}"
        stroke-linecap="round" style="transition: stroke-dasharray 0.6s ease"/>
      <text x="${cx}" y="${cy + 5}" text-anchor="middle" fill="var(--text)" font-size="16" font-weight="700">${Math.round(pct)}%</text>
    </svg>`;
}

// --- Number formatting ---
function formatNumber(n) {
  if (n === null || n === undefined) return '0';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return n.toString();
}

// --- Router ---
const routes = {
  'overview':   () => import('./pages/overview.js'),
  'pipeline':   () => import('./pages/pipeline.js'),
  'policies':   () => import('./pages/policies.js'),
  'scans':      () => import('./pages/scans.js'),
  'cloud':      () => import('./pages/cloud.js'),
  'compliance': () => import('./pages/compliance.js'),
  'settings':   () => import('./pages/settings.js'),
};

let currentPage = null;

async function navigate() {
  const hash = location.hash.slice(1).split('/')[0] || 'overview';
  const loader = routes[hash];
  if (!loader) {
    location.hash = '#overview';
    return;
  }

  // Destroy previous page
  if (currentPage && currentPage.destroy) {
    currentPage.destroy();
  }

  // Update nav
  document.querySelectorAll('.sidebar-nav a').forEach(a => {
    a.classList.toggle('active', a.dataset.page === hash);
  });

  const content = document.getElementById('content');
  content.innerHTML = '<div class="page-loading"><div class="skeleton" style="width:200px;height:32px;margin-bottom:24px"></div><div class="kpi-grid"><div class="skeleton" style="height:120px"></div><div class="skeleton" style="height:120px"></div><div class="skeleton" style="height:120px"></div></div></div>';

  try {
    const module = await loader();
    currentPage = module;
    content.innerHTML = '';
    module.render(content);
  } catch (err) {
    content.innerHTML = `<div class="empty-state"><div class="empty-state-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--severity-critical)" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg></div><h3>Failed to load page</h3><p>${err.message}</p></div>`;
  }
}

// --- Expose globals for page modules ---
window.ZelyoApp = {
  fetchJSON,
  onSSE,
  offSSE,
  formatTime,
  formatDateTime,
  formatNumber,
  severityBadge,
  phaseBadge,
  renderDonutChart,
  renderBarChart,
  renderProgressRing,
  showToast,
};

// --- Init ---
window.addEventListener('hashchange', navigate);
window.addEventListener('DOMContentLoaded', () => {
  if (!location.hash) location.hash = '#overview';
  navigate();
  initSSE();
});
