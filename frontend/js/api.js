/**
 * Centralised API client for all NIDS backend requests.
 * All fetch calls go through here — handles auth headers, errors, logging.
 */

const API_BASE = 'http://localhost:5000';

const api = {
  _token: null,

  setToken(token) {
    this._token = token;
    if (token) {
      localStorage.setItem('nids_token', token);
    } else {
      localStorage.removeItem('nids_token');
    }
  },

  getToken() {
    if (!this._token) {
      this._token = localStorage.getItem('nids_token');
    }
    return this._token;
  },

  _headers(extra = {}) {
    const h = { 'Content-Type': 'application/json', ...extra };
    const t = this.getToken();
    if (t) h['Authorization'] = `Bearer ${t}`;
    return h;
  },

  async _request(method, path, body = null, opts = {}) {
    const url = `${API_BASE}${path}`;
    const options = {
      method,
      headers: this._headers(opts.headers || {}),
    };
    if (body && !(body instanceof FormData)) {
      options.body = JSON.stringify(body);
    } else if (body instanceof FormData) {
      // Remove Content-Type so browser sets multipart/form-data boundary
      delete options.headers['Content-Type'];
      options.body = body;
    }

    try {
      const resp = await fetch(url, options);

      // Handle 401 globally — but ONLY redirect to login if /auth/me itself fails.
      // Parallel requests (e.g. dashboard trends + summary via Promise.all) can
      // legitimately get 401 from one of them due to race conditions; clearing the
      // session in that case incorrectly logs the user out.
      if (resp.status === 401) {
        const isAuthCheck = path === '/auth/me';
        const data401 = await resp.json().catch(() => ({}));
        if (isAuthCheck) {
          auth.clearSession();
          if (!window.location.pathname.includes('index.html') && window.location.pathname !== '/') {
            window.location.href = 'index.html';
          }
        }
        return { success: false, message: data401.message || 'Session expired. Please log in again.' };
      }

      const data = await resp.json();
      return data;
    } catch (err) {
      console.error(`API error [${method} ${path}]:`, err);
      return {
        success: false,
        message: 'Network error. Please check if the backend server is running.',
        error: { code: 'NETWORK_ERROR' }
      };
    }
  },

  get: (path, opts) => api._request('GET', path, null, opts),
  post: (path, body, opts) => api._request('POST', path, body, opts),
  put: (path, body, opts) => api._request('PUT', path, body, opts),
  delete: (path, opts) => api._request('DELETE', path, null, opts),

  // File upload helper
  async upload(path, formData) {
    const url = `${API_BASE}${path}`;
    const headers = {};
    const t = this.getToken();
    if (t) headers['Authorization'] = `Bearer ${t}`;
    try {
      const resp = await fetch(url, { method: 'POST', headers, body: formData });
      if (resp.status === 401) {
        auth.clearSession();
        window.location.href = 'index.html';
        return { success: false, message: 'Session expired.' };
      }
      // Check if response is JSON or blob (for file downloads)
      const contentType = resp.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        return await resp.json();
      }
      return resp; // Return raw response for downloads
    } catch (err) {
      return { success: false, message: 'Upload failed: ' + err.message };
    }
  },

  // Download helper — triggers file download from API
  async download(path, filename) {
    const url = `${API_BASE}${path}`;
    const t = this.getToken();
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${t}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });
      if (!resp.ok) {
        toast.error('Download failed', 'Server returned an error.');
        return;
      }
      const blob = await resp.blob();
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
    } catch (err) {
      toast.error('Download failed', err.message);
    }
  },

  // Endpoints
  auth: {
    login: (u, p) => api.post('/auth/login', { username: u, password: p }),
    logout: () => api.post('/auth/logout'),
    me: () => api.get('/auth/me'),
    register: (d) => api.post('/auth/register', d),
    changePassword: (d) => api.post('/auth/change-password', d),
  },
  dashboard: {
    summary: () => api.get('/dashboard/summary'),
    trends: () => api.get('/dashboard/trends'),
    topIps: () => api.get('/dashboard/top-ips'),
  },
  datasets: {
    list: () => api.get('/datasets'),
    get: (id) => api.get(`/datasets/${id}`),
    delete: (id) => api.delete(`/datasets/${id}`),
    upload: (fd) => api.upload('/datasets/upload', fd),
    validate: (id) => api.post(`/datasets/${id}/validate`),
  },
  models: {
    list: () => api.get('/models'),
    active: () => api.get('/models/active'),
    get: (id) => api.get(`/models/${id}`),
    train: (d) => api.post('/models/train', d),
    compare: (d) => api.post('/models/compare', d),
    activate: (id) => api.post(`/models/${id}/activate`),
    delete: (id) => api.delete(`/models/${id}`),
    types: () => api.get('/models/types'),
    evaluate: (id, d) => api.post(`/models/evaluate/${id}`, d),
    features: () => api.get('/features'),
  },
  predict: {
    single: (d) => api.post('/predict', d),
    batch: (fd) => api.upload('/predict/batch', fd),
  },
  network: {
    interfaces: () => api.get('/network/interfaces'),
    startCapture: (iface) => api.post('/network/capture/start', { interface: iface }),
    stopCapture: () => api.post('/network/capture/stop'),
    captureStatus: () => api.get('/network/capture/status'),
    events: (limit = 50, since = 0) => api.get(`/network/capture/events?limit=${limit}&since=${since}`),
    injectTestFlow: (d) => api.post('/network/capture/inject-test-flow', d),
  },
  detections: {
    list: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return api.get(`/detections${q ? '?' + q : ''}`);
    },
    get: (id) => api.get(`/detections/${id}`),
  },
  alerts: {
    list: (params = {}) => {
      const q = new URLSearchParams(params).toString();
      return api.get(`/alerts${q ? '?' + q : ''}`);
    },
    get: (id) => api.get(`/alerts/${id}`),
    acknowledge: (id) => api.post(`/alerts/${id}/acknowledge`),
    resolve: (id, note) => api.post(`/alerts/${id}/resolve`, { note }),
    addNote: (id, note) => api.post(`/alerts/${id}/notes`, { note }),
    summary: () => api.get('/alerts/summary'),
  },
  analytics: {
    overview: () => api.get('/analytics/overview'),
    attacks: () => api.get('/analytics/attacks'),
    severity: () => api.get('/analytics/severity'),
    protocols: () => api.get('/analytics/protocols'),
    trends: (days) => api.get(`/analytics/trends?days=${days || 7}`),
    topIps: (limit) => api.get(`/analytics/top-ips?limit=${limit || 10}`),
  },
  reports: {
    preview: () => api.get('/reports/preview'),
    downloadJson: () => {
      api.downloadReport('json');
    },
    downloadCsv: () => {
      api.downloadReport('csv');
    },
    downloadPdf: () => {
      api.downloadReport('pdf');
    },
  },
  admin: {
    users: (params = {}) => api.get('/admin/users?' + new URLSearchParams(params)),
    deleteUser: (id) => api.delete(`/admin/users/${id}`),
    toggleUser: (id) => api.post(`/admin/users/${id}/toggle-active`),
    auditLogs: (params = {}) => api.get('/admin/audit-logs?' + new URLSearchParams(params)),
    systemStats: () => api.get('/admin/system-stats'),
    settings: () => api.get('/admin/settings'),
    updateSettings: (d) => api.post('/admin/settings', d),
  },

  // Report download
  async downloadReport(format) {
    const token = this.getToken();
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const extensions = { json: 'json', csv: 'csv', pdf: 'pdf' };
    const ext = extensions[format] || format;
    const filename = `nids_report_${ts}.${ext}`;
    const mimes = { json: 'application/json', csv: 'text/csv', pdf: 'application/pdf' };

    try {
      const resp = await fetch(`${API_BASE}/reports/generate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ format }),
      });
      if (!resp.ok) {
        toast.error('Download failed', `Server error: ${resp.status}`);
        return;
      }
      const blob = await resp.blob();
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
      toast.success('Report downloaded', filename);
    } catch (err) {
      toast.error('Download failed', err.message);
    }
  }
};
