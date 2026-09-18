/**
 * Shared utilities: toast notifications, pagination, formatters, helpers.
 */

// ── Toast Notifications ───────────────────────────────────────────────
const toast = {
  _container: null,

  _getContainer() {
    if (!this._container) {
      this._container = document.getElementById('toast-container');
      if (!this._container) {
        this._container = document.createElement('div');
        this._container.id = 'toast-container';
        document.body.appendChild(this._container);
      }
    }
    return this._container;
  },

  show(type, title, message, duration = 4000) {
    const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `
      <div class="toast-icon">${icons[type] || 'ℹ️'}</div>
      <div class="toast-body">
        <div class="toast-title">${title}</div>
        ${message ? `<div class="toast-message">${message}</div>` : ''}
      </div>`;
    this._getContainer().appendChild(el);
    setTimeout(() => {
      el.classList.add('exit');
      setTimeout(() => el.remove(), 300);
    }, duration);
  },

  success: (title, msg, dur) => toast.show('success', title, msg, dur),
  error: (title, msg, dur) => toast.show('error', title, msg, dur),
  warning: (title, msg, dur) => toast.show('warning', title, msg, dur),
  info: (title, msg, dur) => toast.show('info', title, msg, dur),
};

// ── Formatters ────────────────────────────────────────────────────────
const fmt = {
  number(n) {
    if (n === null || n === undefined) return '—';
    return Number(n).toLocaleString();
  },
  percent(n, decimals = 1) {
    if (n === null || n === undefined) return '—';
    return `${Number(n * 100).toFixed(decimals)}%`;
  },
  percentDirect(n, decimals = 1) {
    if (n === null || n === undefined) return '—';
    return `${Number(n).toFixed(decimals)}%`;
  },
  datetime(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString('en-IN', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
      });
    } catch { return iso; }
  },
  date(iso) {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleDateString('en-IN', {
        day: '2-digit', month: 'short', year: 'numeric',
      });
    } catch { return iso; }
  },
  confidence(v) {
    if (v === null || v === undefined) return '—';
    return `${(v * 100).toFixed(1)}%`;
  },
  severity(s) {
    const map = {
      CRITICAL: '<span class="badge badge-critical">CRITICAL</span>',
      HIGH:     '<span class="badge badge-high">HIGH</span>',
      MEDIUM:   '<span class="badge badge-medium">MEDIUM</span>',
      LOW:      '<span class="badge badge-low">LOW</span>',
    };
    return map[s] || `<span class="badge badge-neutral">${s || '—'}</span>`;
  },
  prediction(p) {
    if (p === 'BENIGN') return '<span class="badge badge-success">BENIGN</span>';
    return `<span class="badge badge-critical">${p}</span>`;
  },
  status(s) {
    const map = {
      NEW:          '<span class="badge badge-info">NEW</span>',
      ACTIVE:       '<span class="badge badge-high">ACTIVE</span>',
      ACKNOWLEDGED: '<span class="badge badge-warning">ACKNOWLEDGED</span>',
      RESOLVED:     '<span class="badge badge-success">RESOLVED</span>',
      TRAINED:      '<span class="badge badge-info">TRAINED</span>',
      ACTIVE:       '<span class="badge badge-success">ACTIVE</span>',
      ARCHIVED:     '<span class="badge badge-neutral">ARCHIVED</span>',
      FAILED:       '<span class="badge badge-critical">FAILED</span>',
    };
    return map[s] || `<span class="badge badge-neutral">${s || '—'}</span>`;
  },
  truncate(s, n = 20) {
    if (!s) return '—';
    return s.length > n ? s.substring(0, n) + '…' : s;
  },
};

// ── Pagination ────────────────────────────────────────────────────────
function buildPagination(containerId, { page, pages, total, per_page }, onPageChange) {
  const container = document.getElementById(containerId);
  if (!container) return;
  if (pages <= 1) { container.innerHTML = ''; return; }

  const start = (page - 1) * per_page + 1;
  const end = Math.min(page * per_page, total);

  let html = `<span class="pagination-info">Showing ${fmt.number(start)}–${fmt.number(end)} of ${fmt.number(total)}</span>`;
  html += `<button class="page-btn" ${page <= 1 ? 'disabled' : ''} onclick="(${onPageChange.toString()})(${page - 1})">‹</button>`;

  const range = pageRange(page, pages);
  for (const p of range) {
    if (p === '...') {
      html += `<span class="page-btn" style="cursor:default">…</span>`;
    } else {
      html += `<button class="page-btn ${p === page ? 'active' : ''}" onclick="(${onPageChange.toString()})(${p})">${p}</button>`;
    }
  }
  html += `<button class="page-btn" ${page >= pages ? 'disabled' : ''} onclick="(${onPageChange.toString()})(${page + 1})">›</button>`;
  container.innerHTML = html;
}

function pageRange(current, total, delta = 2) {
  const range = [];
  const left = current - delta;
  const right = current + delta + 1;
  let last;
  for (let i = 1; i <= total; i++) {
    if (i === 1 || i === total || (i >= left && i < right)) {
      if (last && i - last > 1) range.push('...');
      range.push(i);
      last = i;
    }
  }
  return range;
}

// ── Loading helpers ───────────────────────────────────────────────────
function setLoading(id, loading) {
  const el = document.getElementById(id);
  if (!el) return;
  if (loading) {
    el.dataset.origText = el.innerHTML;
    el.innerHTML = '<span class="loading-spinner"></span>';
    el.disabled = true;
  } else {
    el.innerHTML = el.dataset.origText || el.innerHTML;
    el.disabled = false;
  }
}

function showTableLoading(tbodyId, cols = 6) {
  const el = document.getElementById(tbodyId);
  if (!el) return;
  el.innerHTML = Array(5).fill(
    `<tr>${Array(cols).fill(`<td><div class="skeleton" style="height:18px;width:80%;border-radius:4px"></div></td>`).join('')}</tr>`
  ).join('');
}

function showEmpty(tbodyId, message = 'No records found', cols = 6) {
  const el = document.getElementById(tbodyId);
  if (!el) return;
  el.innerHTML = `<tr><td colspan="${cols}" class="text-center" style="padding:40px;color:var(--text-muted)">${message}</td></tr>`;
}

// ── Chart Defaults ────────────────────────────────────────────────────
const CHART_COLORS = {
  teal: '#00d4b4',
  blue: '#0088ff',
  red: '#ef4444',
  orange: '#f59e0b',
  green: '#10b981',
  purple: '#7c3aed',
  pink: '#ec4899',
  yellow: '#eab308',
};

const CHART_PALETTE = Object.values(CHART_COLORS);

function chartDefaults() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#94a3b8', font: { family: 'Inter', size: 12 }, boxWidth: 12, padding: 16 }
      },
      tooltip: {
        backgroundColor: '#0d1e35',
        borderColor: '#1e3a5f',
        borderWidth: 1,
        titleColor: '#e2e8f0',
        bodyColor: '#94a3b8',
        padding: 12,
      }
    },
    scales: {
      x: {
        ticks: { color: '#475569', font: { family: 'Inter', size: 11 } },
        grid: { color: 'rgba(30, 58, 95, 0.5)' },
      },
      y: {
        ticks: { color: '#475569', font: { family: 'Inter', size: 11 } },
        grid: { color: 'rgba(30, 58, 95, 0.5)' },
        beginAtZero: true,
      }
    }
  };
}

// ── Active nav item ───────────────────────────────────────────────────
function setActiveNav() {
  const current = window.location.pathname.split('/').pop() || 'dashboard.html';
  document.querySelectorAll('.nav-item').forEach(link => {
    const href = link.getAttribute('href') || '';
    if (href === current || href.endsWith(current)) {
      link.classList.add('active');
    }
  });
}

// ── Modal helpers ─────────────────────────────────────────────────────
function openModal(id) {
  const m = document.getElementById(id);
  if (m) { m.classList.remove('hidden'); m.style.display = 'flex'; }
}

function closeModal(id) {
  const m = document.getElementById(id);
  if (m) { m.classList.add('hidden'); m.style.display = 'none'; }
}

// Close modal on overlay click
document.addEventListener('click', (e) => {
  if (e.target.classList.contains('modal-overlay')) {
    e.target.classList.add('hidden');
    e.target.style.display = 'none';
  }
});

// ── Misc ──────────────────────────────────────────────────────────────
function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function debounce(fn, ms = 300) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

document.addEventListener('DOMContentLoaded', setActiveNav);
