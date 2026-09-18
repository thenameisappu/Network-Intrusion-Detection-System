/**
 * Authentication state management.
 * Maintains user session across pages.
 */

const auth = {
  _user: null,

  init() {
    // Restore user from localStorage
    const stored = localStorage.getItem('nids_user');
    if (stored) {
      try { this._user = JSON.parse(stored); } catch {}
    }
    api._token = localStorage.getItem('nids_token');
  },

  setUser(user) {
    this._user = user;
    localStorage.setItem('nids_user', JSON.stringify(user));
  },

  getUser() { return this._user; },

  isLoggedIn() {
    return !!(this._user && api.getToken());
  },

  isAdmin() {
    return this._user?.role === 'admin';
  },

  clearSession() {
    this._user = null;
    api.setToken(null);
    localStorage.removeItem('nids_user');
    localStorage.removeItem('nids_token');
  },

  /** Call on every protected page load */
  async requireAuth(redirectTo = 'index.html') {
    this.init();
    if (!this.isLoggedIn()) {
      window.location.href = redirectTo;
      return null;
    }
    // Verify token is still valid
    const resp = await api.auth.me();
    if (!resp.success) {
      this.clearSession();
      window.location.href = redirectTo;
      return null;
    }
    // Refresh user data
    this.setUser(resp.data);
    return resp.data;
  },

  /** Render user info in sidebar */
  renderUserInfo() {
    const user = this.getUser();
    if (!user) return;
    const nameEl = document.getElementById('sidebar-user-name');
    const roleEl = document.getElementById('sidebar-user-role');
    const avatarEl = document.getElementById('sidebar-user-avatar');
    if (nameEl) nameEl.textContent = user.full_name || user.username;
    if (roleEl) roleEl.textContent = user.role;
    if (avatarEl) avatarEl.textContent = (user.full_name || user.username)[0].toUpperCase();

    // Hide admin-only nav items for non-admins
    if (!this.isAdmin()) {
      document.querySelectorAll('.admin-only').forEach(el => el.style.display = 'none');
    }
  },

  async logout() {
    await api.auth.logout();
    this.clearSession();
    window.location.href = 'index.html';
  }
};

// Logout button handler (attached on DOMContentLoaded)
document.addEventListener('DOMContentLoaded', () => {
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => auth.logout());
  }
});
