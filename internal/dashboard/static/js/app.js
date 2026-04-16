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
  const eventTypes = ['policy.updated', 'scan.updated', 'cloud.updated', 'config.updated', 'overview.refresh', 'report.created'];
  eventTypes.forEach(type => {
    sseSource.addEventListener(type, (e) => {
      try {
        const data = JSON.parse(e.data);
        dispatchSSE(type, data);
        showToast(type, data);
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
function showToast(type, data) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  const label = type.replace('.', ' ').replace(/\b\w/g, l => l.toUpperCase());
  toast.innerHTML = `<span class="toast-icon">${getEventIcon(type)}</span><span class="toast-text">${label}</span>`;
  container.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('show'));
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function getEventIcon(type) {
  if (type.startsWith('policy')) return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
  if (type.startsWith('scan')) return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>';
  if (type.startsWith('cloud')) return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/></svg>';
  return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
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
