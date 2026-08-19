/**
 * DDoS IP Monitoring & Notification Tool - Frontend Application Logic
 */

// Application State
const state = {
  token: localStorage.getItem('ddos_auth_token') || null,
  isAuthenticated: false,
  isSetup: true,
  currentPage: 'mapping', // 'mapping' | 'logs' | 'admin'
  monitoredIps: [],
  prefixes: [],
  logs: [],
  logsPagination: { page: 1, limit: 25, total: 0, total_pages: 1 },
  logsStats: null,
  monitorStatus: null,
  settings: {},
  filterLogs: { ip: '', network_range: '', status: '' },
  searchIpQuery: '',
  pollingInterval: null
};

// API Client Helper
async function api(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  if (state.token) {
    headers['Authorization'] = `Bearer ${state.token}`;
  }

  try {
    const res = await fetch(path, { ...options, headers });
    if (res.status === 401 && path !== '/api/auth/login' && path !== '/api/auth/status') {
      logout();
      showToast('Session expired. Please log in again.', 'warning');
      throw new Error('Unauthorized');
    }

    const contentType = res.headers.get('content-type') || '';
    let data;
    if (contentType.includes('application/json')) {
      data = await res.json();
    } else {
      const rawText = await res.text();
      const cleanMsg = rawText.replace(/<[^>]*>?/gm, '').trim();
      throw new Error(cleanMsg ? `Server error (${res.status}): ${cleanMsg.substring(0, 100)}` : `HTTP ${res.status} ${res.statusText}`);
    }

    if (!res.ok) {
      throw new Error(data.error || 'Request failed');
    }
    return data;
  } catch (err) {
    throw err;
  }
}


// Toast Notifications
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <div style="display:flex; align-items:center; gap:8px;">
      <span>${type === 'success' ? '✅' : type === 'danger' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️'}</span>
      <span>${message}</span>
    </div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Init Check
async function initApp() {
  try {
    const authStatus = await api('/api/auth/status');
    state.isSetup = authStatus.is_setup;
    state.isAuthenticated = authStatus.authenticated;

    if (!state.isSetup) {
      renderSetupView();
      return;
    }

    if (!state.isAuthenticated) {
      renderLoginView();
      return;
    }

    // Authenticated
    renderMainApp();
    await loadInitialData();
    startStatusPolling();
  } catch (err) {
    console.error('Init error:', err);
    renderLoginView();
  }
}

function logout() {
  state.token = null;
  state.isAuthenticated = false;
  localStorage.removeItem('ddos_auth_token');
  if (state.pollingInterval) clearInterval(state.pollingInterval);
  renderLoginView();
  showToast('Logged out successfully.', 'info');
}

// ----------------------------------------------------------------------
// Views: Setup & Login
// ----------------------------------------------------------------------

function renderSetupView() {
  const root = document.getElementById('app-container');
  root.innerHTML = `
    <div class="auth-wrapper">
      <div class="auth-card">
        <div class="auth-header">
          <div class="auth-logo">🛡️</div>
          <h2>Initial Admin Setup</h2>
          <p>Create a secure password to initialize the DDoS Notification Tool.</p>
        </div>

        <form id="setup-form" onsubmit="handleSetupSubmit(event)">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label" for="setup-password">Admin Password</label>
            <input type="password" id="setup-password" class="form-input" required placeholder="Enter new password" oninput="checkPasswordStrength(this.value)">
          </div>

          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label" for="setup-confirm">Confirm Password</label>
            <input type="password" id="setup-confirm" class="form-input" required placeholder="Confirm password">
          </div>

          <div class="password-rules" style="margin-bottom: 20px;">
            <p>Password Requirements:</p>
            <div id="rule-length" class="rule-item"><span>•</span> Minimum 6 characters</div>
            <div id="rule-digit" class="rule-item"><span>•</span> At least one number (0-9)</div>
            <div id="rule-special" class="rule-item"><span>•</span> At least one special character (!@#$%^&*)</div>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%;">
            Complete Setup & Sign In
          </button>
        </form>
      </div>
    </div>
  `;
}

function checkPasswordStrength(val) {
  const rLength = document.getElementById('rule-length');
  const rDigit = document.getElementById('rule-digit');
  const rSpecial = document.getElementById('rule-special');

  if (!rLength) return;

  if (val.length >= 6) rLength.classList.add('valid');
  else rLength.classList.remove('valid');

  if (/\d/.test(val)) rDigit.classList.add('valid');
  else rDigit.classList.remove('valid');

  if (/[!@#$%^&*(),.?":{}|<>_\-\\\/+=~`\[\]]/.test(val)) rSpecial.classList.add('valid');
  else rSpecial.classList.remove('valid');
}

async function handleSetupSubmit(e) {
  e.preventDefault();
  const pwd = document.getElementById('setup-password').value;
  const confirm = document.getElementById('setup-confirm').value;

  if (pwd !== confirm) {
    showToast('Passwords do not match.', 'danger');
    return;
  }

  try {
    const res = await api('/api/auth/setup', {
      method: 'POST',
      body: JSON.stringify({ password: pwd, confirmPassword: confirm })
    });
    state.token = res.token;
    state.isAuthenticated = true;
    localStorage.setItem('ddos_auth_token', res.token);
    showToast('Admin setup completed successfully!', 'success');
    renderMainApp();
    await loadInitialData();
    startStatusPolling();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

function renderLoginView() {
  const root = document.getElementById('app-container');
  root.innerHTML = `
    <div class="auth-wrapper">
      <div class="auth-card">
        <div class="auth-header">
          <div class="auth-logo">🛡️</div>
          <h2>Imperva DDoS Alert Console</h2>
          <p>Sign in with your admin password to manage monitored IPs and alert settings.</p>
        </div>

        <form id="login-form" onsubmit="handleLoginSubmit(event)">
          <div class="form-group" style="margin-bottom: 20px;">
            <label class="form-label" for="login-password">Admin Password</label>
            <input type="password" id="login-password" class="form-input" required placeholder="Enter password" autofocus>
          </div>

          <button type="submit" class="btn btn-primary" style="width: 100%;">
            Sign In
          </button>
        </form>
      </div>
    </div>
  `;
}

async function handleLoginSubmit(e) {
  e.preventDefault();
  const pwd = document.getElementById('login-password').value;

  try {
    const res = await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ password: pwd })
    });
    state.token = res.token;
    state.isAuthenticated = true;
    localStorage.setItem('ddos_auth_token', res.token);
    showToast('Login successful!', 'success');
    renderMainApp();
    await loadInitialData();
    startStatusPolling();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// ----------------------------------------------------------------------
// Main Application Layout & Navigation
// ----------------------------------------------------------------------

function renderMainApp() {
  const root = document.getElementById('app-container');
  root.innerHTML = `
    <header class="top-navbar">
      <div class="brand-section">
        <div class="brand-logo">🛡️</div>
        <div class="brand-info">
          <h1>DDoS IP Monitor</h1>
          <p>Imperva Incapsula Mitigation Notification System</p>
        </div>
      </div>

      <nav class="nav-links">
        <button class="nav-btn ${state.currentPage === 'mapping' ? 'active' : ''}" onclick="switchPage('mapping')">
          <span>🌐</span> IP Mapping & Prefixes
        </button>
        <button class="nav-btn ${state.currentPage === 'logs' ? 'active' : ''}" onclick="switchPage('logs')">
          <span>📜</span> Event Logs
          <span id="nav-log-badge" class="nav-badge" style="display:none;">0</span>
        </button>
        <button class="nav-btn ${state.currentPage === 'admin' ? 'active' : ''}" onclick="switchPage('admin')">
          <span>⚙️</span> Admin Settings
        </button>
      </nav>

      <div class="header-status-area">
        <div class="status-pill" id="header-status-pill" title="Monitoring status">
          <div class="status-indicator" id="header-status-dot"></div>
          <span id="header-status-text">Loading...</span>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="triggerManualScan()" title="Trigger immediate scan">
          ⚡ Scan Now
        </button>
        <button class="btn btn-icon" onclick="logout()" title="Sign out">
          🚪
        </button>
      </div>
    </header>

    <main class="main-content" id="main-content-view">
      <!-- Active view rendered here -->
    </main>

    <!-- Modal Container -->
    <div id="modal-container"></div>
  `;

  renderCurrentPage();
}

function switchPage(page) {
  state.currentPage = page;
  document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
  const activeBtn = Array.from(document.querySelectorAll('.nav-btn')).find(b => b.getAttribute('onclick')?.includes(page));
  if (activeBtn) activeBtn.classList.add('active');
  renderCurrentPage();
}

function renderCurrentPage() {
  const container = document.getElementById('main-content-view');
  if (!container) return;

  if (state.currentPage === 'mapping') {
    renderIpMappingPage(container);
  } else if (state.currentPage === 'logs') {
    renderLogsPage(container);
  } else if (state.currentPage === 'admin') {
    renderAdminPage(container);
  }
}

// ----------------------------------------------------------------------
// Data Fetching & Polling
// ----------------------------------------------------------------------

async function loadInitialData() {
  await Promise.all([
    fetchPrefixes(),
    fetchMonitoredIps(),
    fetchMonitorStatus(),
    fetchSettings()
  ]);
  updateHeaderStatus();
}

async function fetchPrefixes() {
  try {
    const data = await api('/api/prefixes');
    state.prefixes = data.prefixes || [];
  } catch (err) {
    console.error('Error fetching prefixes:', err);
  }
}

async function fetchMonitoredIps() {
  try {
    const data = await api(`/api/ips${state.searchIpQuery ? `?search=${encodeURIComponent(state.searchIpQuery)}` : ''}`);
    state.monitoredIps = data.ips || [];
  } catch (err) {
    console.error('Error fetching IPs:', err);
  }
}

async function fetchLogs() {
  try {
    const query = new URLSearchParams({
      page: state.logsPagination.page,
      limit: state.logsPagination.limit,
      ip: state.filterLogs.ip || '',
      network_range: state.filterLogs.network_range || '',
      status: state.filterLogs.status || ''
    });
    const [logsData, statsData] = await Promise.all([
      api(`/api/logs?${query.toString()}`),
      api('/api/logs/stats')
    ]);
    state.logs = logsData.logs || [];
    state.logsPagination = logsData.pagination;
    state.logsStats = statsData;

    const badge = document.getElementById('nav-log-badge');
    if (badge && statsData.total_events > 0) {
      badge.style.display = 'inline-block';
      badge.textContent = statsData.total_events;
    }
  } catch (err) {
    console.error('Error fetching logs:', err);
  }
}

async function fetchMonitorStatus() {
  try {
    state.monitorStatus = await api('/api/monitor/status');
    updateHeaderStatus();
  } catch (err) {
    console.error('Error fetching monitor status:', err);
  }
}

async function fetchSettings() {
  try {
    state.settings = await api('/api/settings');
  } catch (err) {
    console.error('Error fetching settings:', err);
  }
}

function updateHeaderStatus() {
  const dot = document.getElementById('header-status-dot');
  const text = document.getElementById('header-status-text');
  if (!dot || !text || !state.monitorStatus) return;

  const s = state.monitorStatus;
  dot.className = 'status-indicator';

  if (s.is_checking) {
    dot.classList.add('active');
    text.textContent = 'Checking Prefixes...';
  } else if (s.running) {
    dot.classList.add('active');
    text.textContent = `Monitoring (${s.interval_seconds}s)`;
  } else if (s.last_error) {
    dot.classList.add('error');
    text.textContent = 'Monitor Error';
  } else {
    dot.classList.add('stopped');
    text.textContent = 'Monitoring Paused';
  }
}

function startStatusPolling() {
  if (state.pollingInterval) clearInterval(state.pollingInterval);
  state.pollingInterval = setInterval(async () => {
    if (state.isAuthenticated) {
      await fetchMonitorStatus();
      if (state.currentPage === 'logs') {
        await fetchLogs();
        renderCurrentPage();
      }
    }
  }, 10000);
}

async function triggerManualScan() {
  try {
    showToast('Executing DDoS check cycle...', 'info');
    await api('/api/monitor/check-now', { method: 'POST' });
    showToast('Check cycle finished!', 'success');
    await fetchMonitorStatus();
    if (state.currentPage === 'logs') {
      await fetchLogs();
      renderCurrentPage();
    }
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// ----------------------------------------------------------------------
// Page: IP Mapping & Network Prefixes
// ----------------------------------------------------------------------

function renderIpMappingPage(container) {
  const totalIps = state.monitoredIps.length;
  const totalPrefixes = state.prefixes.length;

  container.innerHTML = `
    <div class="page-header">
      <div class="page-title-group">
        <h2>IP Mapping & Protected Prefixes</h2>
        <p>Manage the list of monitored IPs and assign them to protected network prefixes.</p>
      </div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm" onclick="syncPrefixesFromImperva()">
          🔄 Sync Prefixes (${totalPrefixes})
        </button>
        <button class="btn btn-secondary btn-sm" onclick="openCsvImportModal()">
          📥 Import CSV
        </button>
        <a href="/api/ips/export-csv" class="btn btn-secondary btn-sm" download>
          📤 Export CSV
        </a>
        <button class="btn btn-primary btn-sm" onclick="openAddIpModal()">
          ➕ Add Monitored IP
        </button>
      </div>
    </div>

    <!-- Summary Metrics -->
    <div class="metrics-grid">
      <div class="metric-card highlight-primary">
        <div class="metric-header">
          <span>MONITORED IPS</span>
          <span>🎯</span>
        </div>
        <div class="metric-value">${totalIps}</div>
        <div class="metric-subtitle">Target IPs tracked for DDoS blocking</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span>PROTECTED PREFIXES</span>
          <span>🌐</span>
        </div>
        <div class="metric-value">${totalPrefixes}</div>
        <div class="metric-subtitle">BGP network ranges synced from Imperva</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span>MONITORING STATUS</span>
          <span>⚡</span>
        </div>
        <div class="metric-value" style="font-size: 20px;">
          ${state.monitorStatus?.running ? '<span style="color:var(--success)">Active</span>' : '<span style="color:var(--warning)">Paused</span>'}
        </div>
        <div class="metric-subtitle">Check interval: ${state.monitorStatus?.interval_seconds || 60}s</div>
      </div>
    </div>

    <!-- Protected Prefixes Collapsible Bar -->
    <div class="card" style="margin-bottom: 20px;">
      <div class="card-header" style="padding: 12px 20px;">
        <h3><span>🌐</span> Incapsula Protected Network Prefixes (${totalPrefixes})</h3>
        <button class="btn btn-secondary btn-sm" onclick="syncPrefixesFromImperva()">
          🔄 Sync Now
        </button>
      </div>
      <div class="card-body" style="padding: 16px 20px;">
        ${totalPrefixes === 0 ? `
          <div style="color:var(--text-muted); font-size:13px;">
            No protected network prefixes synced yet. Click <strong>Sync Prefixes</strong> or configure API credentials in <a href="javascript:void(0)" onclick="switchPage('admin')">Admin Settings</a>.
          </div>
        ` : `
          <div class="chip-list">
            ${state.prefixes.map(p => `
              <span class="badge badge-primary badge-mono" title="Prefix ID: ${p.id}">
                ${p.prefix} <span style="opacity:0.6; font-size:10px;">(#${p.id})</span>
              </span>
            `).join('')}
          </div>
        `}
      </div>
    </div>

    <!-- Monitored IP Table Card -->
    <div class="card">
      <div class="card-header">
        <div>
          <h3><span>📋</span> Monitored IP List (${totalIps})</h3>
          <p>When any of these IPs are detected in top-table blocked stats, email alerts and logs are triggered.</p>
        </div>
        <div class="search-box">
          <span class="search-icon">🔍</span>
          <input type="text" class="search-input" placeholder="Search IP or description..." value="${state.searchIpQuery}" oninput="handleIpSearch(this.value)">
        </div>
      </div>

      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Description / Hostname</th>
              <th>Assigned Network Prefixes</th>
              <th>Date Added</th>
              <th style="text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${state.monitoredIps.length === 0 ? `
              <tr>
                <td colspan="5" class="table-empty">
                  <div class="table-empty-icon">🛡️</div>
                  <div style="font-weight:600; color:var(--text-primary); margin-bottom:4px;">No Monitored IPs Found</div>
                  <div>Add an IP address or import a CSV list to start monitoring for DDoS blocking.</div>
                </td>
              </tr>
            ` : state.monitoredIps.map(ip => `
              <tr>
                <td class="table-ip-cell">${ip.ip_address}</td>
                <td>${ip.description || '<span style="color:var(--text-muted); font-style:italic;">No description</span>'}</td>
                <td>
                  <div class="chip-list">
                    ${(ip.assigned_prefixes && ip.assigned_prefixes.includes('*')) ? `
                      <span class="badge badge-success">All Prefixes (*)</span>
                    ` : (ip.assigned_prefixes || []).map(pr => `
                      <span class="badge badge-primary badge-mono">${pr}</span>
                    `).join('')}
                  </div>
                </td>
                <td style="color:var(--text-muted); font-size:12px;">${ip.created_at || 'N/A'}</td>
                <td style="text-align: right;">
                  <button class="btn btn-secondary btn-sm" onclick="openEditIpModal(${ip.id})" style="margin-right: 6px;">
                    ✏️ Edit
                  </button>
                  <button class="btn btn-danger-outline btn-sm" onclick="deleteIp(${ip.id}, '${ip.ip_address}')">
                    🗑️ Delete
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function handleIpSearch(query) {
  state.searchIpQuery = query;
  fetchMonitoredIps().then(() => {
    const tableBody = document.querySelector('.data-table tbody');
    if (tableBody) {
      renderIpMappingPage(document.getElementById('main-content-view'));
    }
  });
}

async function syncPrefixesFromImperva() {
  try {
    showToast('Syncing protected network prefixes from Imperva API...', 'info');
    const res = await api('/api/prefixes/sync', { method: 'POST' });
    showToast(res.message, 'success');
    await fetchPrefixes();
    renderCurrentPage();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// Add/Edit IP Modal
function openAddIpModal() {
  openIpModal(null);
}

function openEditIpModal(ipId) {
  const item = state.monitoredIps.find(i => i.id === ipId);
  if (!item) return;
  openIpModal(item);
}

function openIpModal(ipItem) {
  const isEdit = !!ipItem;
  const modalContainer = document.getElementById('modal-container');

  const assigned = ipItem ? (ipItem.assigned_prefixes || ['*']) : ['*'];
  const isAll = assigned.includes('*');

  modalContainer.innerHTML = `
    <div class="modal-overlay" onclick="if(event.target === this) closeModal()">
      <div class="modal-content">
        <div class="modal-header">
          <h3>${isEdit ? 'Edit Monitored IP' : 'Add New Monitored IP'}</h3>
          <button class="btn-icon" onclick="closeModal()">✕</button>
        </div>
        <form onsubmit="handleIpFormSubmit(event, ${isEdit ? ipItem.id : 'null'})">
          <div class="modal-body">
            <div class="form-group" style="margin-bottom: 16px;">
              <label class="form-label" for="modal-ip-address">IP Address</label>
              <input type="text" id="modal-ip-address" class="form-input mono" required placeholder="e.g. 195.128.248.33" value="${ipItem ? ipItem.ip_address : ''}">
              <span class="form-hint">IPv4 or IPv6 address to track in DDoS mitigation top-table.</span>
            </div>

            <div class="form-group" style="margin-bottom: 16px;">
              <label class="form-label" for="modal-ip-desc">Description / Server Name</label>
              <input type="text" id="modal-ip-desc" class="form-input" placeholder="e.g. Production Web Gateway 01" value="${ipItem ? (ipItem.description || '') : ''}">
            </div>

            <div class="form-group">
              <label class="form-label">Assign to Protected Network Prefixes</label>
              <div class="prefix-selector-box">
                <label class="prefix-checkbox-label">
                  <input type="checkbox" id="prefix-all" value="*" ${isAll ? 'checked' : ''} onchange="toggleAllPrefixes(this.checked)">
                  <strong>All Protected Prefixes (*)</strong>
                </label>
                <hr style="border:none; border-top:1px solid var(--border-subtle);">
                ${state.prefixes.map(p => `
                  <label class="prefix-checkbox-label">
                    <input type="checkbox" name="prefix-item" value="${p.prefix}" ${!isAll && (assigned.includes(p.prefix) || assigned.includes(p.id)) ? 'checked' : ''} onchange="onIndividualPrefixChange()">
                    <span class="badge badge-mono">${p.prefix}</span> <span style="font-size:11px; color:var(--text-muted);">(ID: ${p.id})</span>
                  </label>
                `).join('')}
                ${state.prefixes.length === 0 ? '<div style="font-size:12px; color:var(--text-muted);">No synced prefixes available. Defaulting to all prefixes (*).</div>' : ''}
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button type="submit" class="btn btn-primary">${isEdit ? 'Save Changes' : 'Add Monitored IP'}</button>
          </div>
        </form>
      </div>
    </div>
  `;
}

function toggleAllPrefixes(checked) {
  const checkboxes = document.querySelectorAll('input[name="prefix-item"]');
  checkboxes.forEach(cb => {
    cb.disabled = checked;
    if (checked) cb.checked = false;
  });
}

function onIndividualPrefixChange() {
  const allBox = document.getElementById('prefix-all');
  if (allBox) allBox.checked = false;
}

async function handleIpFormSubmit(e, ipId) {
  e.preventDefault();
  const ipAddress = document.getElementById('modal-ip-address').value.trim();
  const desc = document.getElementById('modal-ip-desc').value.trim();

  const allBox = document.getElementById('prefix-all');
  let selectedPrefixes = ['*'];

  if (!allBox || !allBox.checked) {
    const checked = Array.from(document.querySelectorAll('input[name="prefix-item"]:checked')).map(cb => cb.value);
    selectedPrefixes = checked.length > 0 ? checked : ['*'];
  }

  try {
    if (ipId) {
      await api(`/api/ips/${ipId}`, {
        method: 'PUT',
        body: JSON.stringify({ ip_address: ipAddress, description: desc, assigned_prefixes: selectedPrefixes })
      });
      showToast('Monitored IP updated successfully.', 'success');
    } else {
      await api('/api/ips', {
        method: 'POST',
        body: JSON.stringify({ ip_address: ipAddress, description: desc, assigned_prefixes: selectedPrefixes })
      });
      showToast('Monitored IP added successfully.', 'success');
    }
    closeModal();
    await fetchMonitoredIps();
    renderCurrentPage();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function deleteIp(id, ip) {
  if (!confirm(`Are you sure you want to remove ${ip} from DDoS monitoring?`)) return;
  try {
    await api(`/api/ips/${id}`, { method: 'DELETE' });
    showToast(`Removed ${ip} from monitoring.`, 'info');
    await fetchMonitoredIps();
    renderCurrentPage();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// CSV Import Modal
function openCsvImportModal() {
  const modalContainer = document.getElementById('modal-container');
  modalContainer.innerHTML = `
    <div class="modal-overlay" onclick="if(event.target === this) closeModal()">
      <div class="modal-content modal-lg">
        <div class="modal-header">
          <h3>Import Monitored IPs from CSV</h3>
          <button class="btn-icon" onclick="closeModal()">✕</button>
        </div>
        <div class="modal-body">
          <p style="color:var(--text-muted); margin-bottom:14px;">
            Upload or paste a CSV list with format: <code>IP, Description</code> or <code>IP, Description, Prefixes (separated by ;)</code>.
          </p>

          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">Upload File (.csv)</label>
            <input type="file" id="csv-file-input" accept=".csv,text/csv,text/plain" class="form-input" onchange="handleCsvFileSelected(event)">
          </div>

          <div class="form-group">
            <label class="form-label">Or Paste CSV Text</label>
            <textarea id="csv-text-area" class="form-textarea mono" rows="6" placeholder="195.128.248.33, Production Gateway 01\n172.110.223.73, API Server Cluster\n93.123.109.23, DNS Server Primary, 142.198.93.0/24;45.223.249.0/24"></textarea>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
          <button type="button" class="btn btn-primary" onclick="submitCsvImport()">Import IPs</button>
        </div>
      </div>
    </div>
  `;
}

function handleCsvFileSelected(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('csv-text-area').value = e.target.result;
  };
  reader.readAsText(file);
}

async function submitCsvImport() {
  const text = document.getElementById('csv-text-area').value;
  if (!text.trim()) {
    showToast('Please provide CSV content to import.', 'warning');
    return;
  }

  try {
    const res = await api('/api/ips/import-csv', {
      method: 'POST',
      body: JSON.stringify({ csv_text: text })
    });
    showToast(res.message, 'success');
    if (res.errors && res.errors.length > 0) {
      showToast(`Notice: ${res.errors.length} rows had errors.`, 'warning');
    }
    closeModal();
    await fetchMonitoredIps();
    renderCurrentPage();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

function closeModal() {
  const modalContainer = document.getElementById('modal-container');
  if (modalContainer) modalContainer.innerHTML = '';
}

// ----------------------------------------------------------------------
// Page: Event Logs & Audit
// ----------------------------------------------------------------------

async function renderLogsPage(container) {
  await fetchLogs();

  const stats = state.logsStats || { total_events: 0, unique_ips: 0, peak_bandwidth: '0 bps' };

  container.innerHTML = `
    <div class="page-header">
      <div class="page-title-group">
        <h2>DDoS Mitigation Blocking Logs</h2>
        <p>Real-time audit log of all monitored IPs actively blocked under Imperva DDoS mitigation rules.</p>
      </div>
      <div class="page-actions">
        <button class="btn btn-secondary btn-sm" onclick="triggerSimulation()">
          🧪 Simulate Block Event (Test Alert)
        </button>
        <a href="/api/logs/export-csv" class="btn btn-secondary btn-sm" download>
          📤 Export Logs CSV
        </a>
        <button class="btn btn-danger-outline btn-sm" onclick="clearAllLogs()">
          🗑️ Clear Logs
        </button>
      </div>
    </div>

    <!-- Metrics Cards -->
    <div class="metrics-grid">
      <div class="metric-card highlight-danger">
        <div class="metric-header">
          <span>TOTAL BLOCK EVENTS</span>
          <span>🚨</span>
        </div>
        <div class="metric-value">${stats.total_events}</div>
        <div class="metric-subtitle">Intersections logged by monitoring engine</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span>UNIQUE MONITORED IPS BLOCKED</span>
          <span>🎯</span>
        </div>
        <div class="metric-value">${stats.unique_ips}</div>
        <div class="metric-subtitle">Distinct target IPs under attack</div>
      </div>

      <div class="metric-card highlight-danger">
        <div class="metric-header">
          <span>PEAK MITIGATED BANDWIDTH</span>
          <span>📈</span>
        </div>
        <div class="metric-value">${stats.peak_bandwidth}</div>
        <div class="metric-subtitle">Highest attack volume detected</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span>EMAIL NOTIFICATIONS SENT</span>
          <span>✉️</span>
        </div>
        <div class="metric-value">${stats.emails_sent || 0}</div>
        <div class="metric-subtitle">Dispatched via configured SMTP</div>
      </div>
    </div>

    <!-- Logs Toolbar & Filters -->
    <div class="card">
      <div class="card-header" style="padding: 14px 20px;">
        <div class="toolbar" style="margin-bottom:0; width:100%;">
          <div style="display:flex; gap:10px; flex-wrap:wrap; flex:1;">
            <div class="search-box" style="min-width:200px; max-width:280px;">
              <span class="search-icon">🔍</span>
              <input type="text" class="search-input" placeholder="Filter by IP..." value="${state.filterLogs.ip}" oninput="state.filterLogs.ip = this.value; debounceFetchLogs();">
            </div>

            <select class="form-select" style="width: auto; min-width: 180px;" onchange="state.filterLogs.network_range = this.value; fetchLogs().then(() => renderCurrentPage());">
              <option value="">All Network Ranges</option>
              ${state.prefixes.map(p => `
                <option value="${p.prefix}" ${state.filterLogs.network_range === p.prefix ? 'selected' : ''}>${p.prefix}</option>
              `).join('')}
            </select>

            <select class="form-select" style="width: auto; min-width: 160px;" onchange="state.filterLogs.status = this.value; fetchLogs().then(() => renderCurrentPage());">
              <option value="">All Statuses</option>
              <option value="Sent" ${state.filterLogs.status === 'Sent' ? 'selected' : ''}>Email Sent</option>
              <option value="Cooldown Suppressed" ${state.filterLogs.status === 'Cooldown Suppressed' ? 'selected' : ''}>Cooldown Suppressed</option>
              <option value="Failed" ${state.filterLogs.status === 'Failed' ? 'selected' : ''}>Failed</option>
            </select>
          </div>

          <button class="btn btn-secondary btn-sm" onclick="fetchLogs().then(() => renderCurrentPage());">
            🔄 Refresh
          </button>
        </div>
      </div>

      <div class="table-container">
        <table class="data-table">
          <thead>
            <tr>
              <th>Timestamp (UTC)</th>
              <th>Blocked Source IP</th>
              <th>Description</th>
              <th>Network Range</th>
              <th>Peak Bandwidth</th>
              <th>Notification Status</th>
            </tr>
          </thead>
          <tbody>
            ${state.logs.length === 0 ? `
              <tr>
                <td colspan="6" class="table-empty">
                  <div class="table-empty-icon">✅</div>
                  <div style="font-weight:600; color:var(--text-primary); margin-bottom:4px;">No Blocking Events Recorded</div>
                  <div>None of your monitored IPs are currently flagged as blocked under Imperva DDoS protection.</div>
                </td>
              </tr>
            ` : state.logs.map(log => `
              <tr>
                <td style="font-family:var(--font-mono); font-size:12.5px; white-space:nowrap;">${log.timestamp}</td>
                <td class="table-ip-cell">
                  <span style="color:var(--danger); font-weight:700;">${log.source_ip}</span>
                </td>
                <td>${log.description || '<span style="color:var(--text-muted);">N/A</span>'}</td>
                <td><span class="badge badge-mono badge-primary">${log.network_range}</span></td>
                <td class="table-bandwidth-cell" title="${log.bandwidth_bps} bps">${log.bandwidth_human}</td>
                <td>
                  ${log.notification_status === 'Sent' ? `
                    <span class="badge badge-success">✉️ Email Sent</span>
                  ` : log.notification_status === 'Cooldown Suppressed' ? `
                    <span class="badge badge-warning" title="Alert suppressed because notification was sent recently within cooldown window">⏳ Cooldown</span>
                  ` : `
                    <span class="badge badge-danger" title="${log.notification_status}">⚠️ ${log.notification_status}</span>
                  `}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <!-- Pagination Footer -->
      <div style="padding: 12px 20px; display: flex; align-items: center; justify-content: space-between; border-top: 1px solid var(--border-subtle); background: #f8fafc; font-size: 13px;">
        <span style="color: var(--text-muted);">
          Showing ${state.logs.length} of ${state.logsPagination.total} event(s)
        </span>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-secondary btn-sm" ${state.logsPagination.page <= 1 ? 'disabled' : ''} onclick="changeLogsPage(${state.logsPagination.page - 1})">
            ◀ Previous
          </button>
          <span style="display:flex; align-items:center; padding:0 8px; font-weight:600;">
            Page ${state.logsPagination.page} / ${state.logsPagination.total_pages}
          </span>
          <button class="btn btn-secondary btn-sm" ${state.logsPagination.page >= state.logsPagination.total_pages ? 'disabled' : ''} onclick="changeLogsPage(${state.logsPagination.page + 1})">
            Next ▶
          </button>
        </div>
      </div>
    </div>
  `;
}

let searchTimer;
function debounceFetchLogs() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(async () => {
    await fetchLogs();
    renderCurrentPage();
  }, 400);
}

function changeLogsPage(page) {
  state.logsPagination.page = page;
  fetchLogs().then(() => renderCurrentPage());
}

async function triggerSimulation() {
  try {
    showToast('Triggering DDoS block simulation test...', 'info');
    const res = await api('/api/monitor/simulate', { method: 'POST' });
    showToast('Simulation complete! Event logged and email dispatched.', 'success');
    await fetchLogs();
    renderCurrentPage();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function clearAllLogs() {
  if (!confirm('Are you sure you want to permanently clear all DDoS blocking event logs?')) return;
  try {
    await api('/api/logs', { method: 'DELETE' });
    showToast('Blocking logs cleared.', 'info');
    await fetchLogs();
    renderCurrentPage();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// ----------------------------------------------------------------------
// Page: Admin Settings
// ----------------------------------------------------------------------

function renderAdminPage(container) {
  const s = state.settings || {};

  container.innerHTML = `
    <div class="page-header">
      <div class="page-title-group">
        <h2>Admin Configuration & Integrations</h2>
        <p>Configure Imperva API credentials, SMTP mail server, monitoring frequency, and security passwords.</p>
      </div>
      <div class="page-actions">
        <button class="btn btn-primary" onclick="saveAllSettings()">
          💾 Save All Settings
        </button>
      </div>
    </div>

    <!-- Imperva Account API Settings -->
    <div class="card">
      <div class="card-header">
        <div>
          <h3><span>🔑</span> 1. Imperva / Incapsula Account API Credentials</h3>
          <p>Used to fetch protected network prefixes and query infrastructure top-table mitigation stats.</p>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="testImpervaCredentials()">
          🧪 Test Credentials
        </button>
      </div>
      <div class="card-body">
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label" for="cfg-account-id">Imperva Account ID</label>
            <input type="text" id="cfg-account-id" class="form-input mono" placeholder="e.g. 2042665" value="${s.account_id || ''}">
            <span class="form-hint">Numeric account ID in your Imperva Cloud Security console.</span>
          </div>

          <div class="form-group">
            <label class="form-label" for="cfg-api-id">API ID (x-API-Id)</label>
            <input type="text" id="cfg-api-id" class="form-input mono" placeholder="e.g. 938472" value="${s.api_id || ''}">
          </div>

          <div class="form-group full-width">
            <label class="form-label" for="cfg-api-key">
              <span>API Key (x-API-Key)</span>
              ${s.has_api_key ? '<span class="badge badge-success">Configured</span>' : '<span class="badge badge-warning">Not set</span>'}
            </label>
            <input type="password" id="cfg-api-key" class="form-input mono" placeholder="Enter or update API key" value="${s.api_key || ''}">
          </div>
        </div>

        <div id="api-test-result" style="margin-top: 16px; display: none;"></div>
      </div>
    </div>

    <!-- Email (SMTP) Alert Settings -->
    <div class="card">
      <div class="card-header">
        <div>
          <h3><span>✉️</span> 2. Email & SMTP Notification Settings</h3>
          <p>Configure mail server delivery and notification template when monitored IPs are blocked.</p>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="testSmtpEmail()">
          📤 Send Test Email
        </button>
      </div>
      <div class="card-body">
        <div class="form-grid" style="margin-bottom: 20px;">
          <div class="form-group">
            <label class="form-label" for="cfg-smtp-host">SMTP Server Host</label>
            <input type="text" id="cfg-smtp-host" class="form-input" placeholder="e.g. smtp.gmail.com or mail.internal.net" value="${s.smtp_host || ''}">
          </div>

          <div class="form-group">
            <label class="form-label" for="cfg-smtp-port">Port</label>
            <input type="number" id="cfg-smtp-port" class="form-input" placeholder="587" value="${s.smtp_port || '587'}">
          </div>

          <div class="form-group">
            <label class="form-label" for="cfg-smtp-encryption">Encryption</label>
            <select id="cfg-smtp-encryption" class="form-select">
              <option value="tls" ${s.smtp_encryption === 'tls' ? 'selected' : ''}>TLS / STARTTLS (Port 587)</option>
              <option value="ssl" ${s.smtp_encryption === 'ssl' ? 'selected' : ''}>SSL (Port 465)</option>
              <option value="none" ${s.smtp_encryption === 'none' ? 'selected' : ''}>None / Unencrypted (Port 25)</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label" for="cfg-smtp-user">SMTP Username</label>
            <input type="text" id="cfg-smtp-user" class="form-input" placeholder="username@example.com" value="${s.smtp_user || ''}">
          </div>

          <div class="form-group">
            <label class="form-label" for="cfg-smtp-pass">
              <span>SMTP Password</span>
              ${s.has_smtp_pass ? '<span class="badge badge-success">Saved</span>' : ''}
            </label>
            <input type="password" id="cfg-smtp-pass" class="form-input" placeholder="Enter password (leave blank to keep existing)" value="">
          </div>

          <div class="form-group">
            <label class="form-label" for="cfg-smtp-sender">Sender Address (From)</label>
            <input type="text" id="cfg-smtp-sender" class="form-input" placeholder="ddos-alerts@imperva-monitor.local" value="${s.smtp_sender || ''}">
          </div>

          <div class="form-group full-width">
            <label class="form-label" for="cfg-smtp-recipients">Recipient Email(s)</label>
            <input type="text" id="cfg-smtp-recipients" class="form-input" placeholder="soc-team@company.com, admin@company.com" value="${s.smtp_recipients || ''}">
            <span class="form-hint">Separate multiple email addresses with commas.</span>
          </div>
        </div>

        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="cfg-email-subject">Email Subject Template</label>
          <input type="text" id="cfg-email-subject" class="form-input" value="${escapeHtml(s.email_subject_template || '')}">
          <div class="template-helpers">
            <span style="font-size:12px; color:var(--text-muted); align-self:center;">Insert Tag:</span>
            <button type="button" class="tag-btn" onclick="insertTag('cfg-email-subject', '{count}')">{count}</button>
            <button type="button" class="tag-btn" onclick="insertTag('cfg-email-subject', '{account_id}')">{account_id}</button>
            <button type="button" class="tag-btn" onclick="insertTag('cfg-email-subject', '{ip_list}')">{ip_list}</button>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label" for="cfg-email-body">Email HTML Body Template</label>
          <textarea id="cfg-email-body" class="form-textarea mono" rows="8">${escapeHtml(s.email_body_template || '')}</textarea>
          <div class="template-helpers">
            <span style="font-size:12px; color:var(--text-muted); align-self:center;">Insert Tag:</span>
            <button type="button" class="tag-btn" onclick="insertTag('cfg-email-body', '{event_rows}')">{event_rows}</button>
            <button type="button" class="tag-btn" onclick="insertTag('cfg-email-body', '{table}')">{table}</button>
            <button type="button" class="tag-btn" onclick="insertTag('cfg-email-body', '{count}')">{count}</button>
            <button type="button" class="tag-btn" onclick="insertTag('cfg-email-body', '{account_id}')">{account_id}</button>
            <button type="button" class="tag-btn" onclick="insertTag('cfg-email-body', '{timestamp}')">{timestamp}</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Monitoring Engine Settings -->
    <div class="card">
      <div class="card-header">
        <div>
          <h3><span>⚡</span> 3. DDoS Mitigation Monitoring Interval & Engine</h3>
          <p>Set background check frequency for Imperva top-table API (<code>https://my.imperva.com/api/v1/infra/top-table</code>).</p>
        </div>
      </div>
      <div class="card-body">
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label" for="cfg-monitoring-enabled">Monitoring Engine State</label>
            <select id="cfg-monitoring-enabled" class="form-select">
              <option value="true" ${s.monitoring_enabled === 'true' ? 'selected' : ''}>Active (Running background scanner)</option>
              <option value="false" ${s.monitoring_enabled !== 'true' ? 'selected' : ''}>Paused (Disabled)</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label" for="cfg-monitoring-interval">Check Interval (Seconds)</label>
            <input type="number" id="cfg-monitoring-interval" class="form-input" min="10" max="3600" value="${s.monitoring_interval_seconds || '60'}">
            <span class="form-hint">Recommended: 30 to 120 seconds.</span>
          </div>

          <div class="form-group">
            <label class="form-label" for="cfg-cooldown">Alert Cooldown Window (Minutes)</label>
            <input type="number" id="cfg-cooldown" class="form-input" min="1" max="1440" value="${s.cooldown_minutes || '15'}">
            <span class="form-hint">Prevents duplicate alert emails for the same ongoing block.</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Security: Change Admin Password -->
    <div class="card">
      <div class="card-header">
        <div>
          <h3><span>🔒</span> 4. Security & Admin Password</h3>
          <p>Update your admin dashboard access password.</p>
        </div>
      </div>
      <div class="card-body">
        <form onsubmit="handleChangePassword(event)" style="max-width: 480px;">
          <div class="form-group" style="margin-bottom: 14px;">
            <label class="form-label" for="pwd-current">Current Password</label>
            <input type="password" id="pwd-current" class="form-input" required placeholder="Enter current password">
          </div>

          <div class="form-group" style="margin-bottom: 14px;">
            <label class="form-label" for="pwd-new">New Password</label>
            <input type="password" id="pwd-new" class="form-input" required placeholder="Min 6 chars, with number & special char" oninput="checkPasswordStrength(this.value)">
          </div>

          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label" for="pwd-confirm">Confirm New Password</label>
            <input type="password" id="pwd-confirm" class="form-input" required placeholder="Re-enter new password">
          </div>

          <div class="password-rules" style="margin-bottom: 16px;">
            <p>Password Policy:</p>
            <div id="rule-length" class="rule-item"><span>•</span> Minimum 6 characters</div>
            <div id="rule-digit" class="rule-item"><span>•</span> At least one number (0-9)</div>
            <div id="rule-special" class="rule-item"><span>•</span> At least one special character (!@#$%^&*)</div>
          </div>

          <button type="submit" class="btn btn-secondary">
            Update Admin Password
          </button>
        </form>
      </div>
    </div>
  `;
}

function insertTag(textareaId, tag) {
  const el = document.getElementById(textareaId);
  if (!el) return;
  const start = el.selectionStart || 0;
  const end = el.selectionEnd || 0;
  const text = el.value;
  el.value = text.substring(0, start) + tag + text.substring(end);
  el.focus();
  el.setSelectionRange(start + tag.length, start + tag.length);
}

function escapeHtml(text) {
  return (text || '')
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function saveAllSettings() {
  const updates = {
    account_id: document.getElementById('cfg-account-id').value.trim(),
    api_id: document.getElementById('cfg-api-id').value.trim(),
    api_key: document.getElementById('cfg-api-key').value.trim(),
    smtp_host: document.getElementById('cfg-smtp-host').value.trim(),
    smtp_port: document.getElementById('cfg-smtp-port').value.trim(),
    smtp_encryption: document.getElementById('cfg-smtp-encryption').value,
    smtp_user: document.getElementById('cfg-smtp-user').value.trim(),
    smtp_sender: document.getElementById('cfg-smtp-sender').value.trim(),
    smtp_recipients: document.getElementById('cfg-smtp-recipients').value.trim(),
    email_subject_template: document.getElementById('cfg-email-subject').value,
    email_body_template: document.getElementById('cfg-email-body').value,
    monitoring_enabled: document.getElementById('cfg-monitoring-enabled').value,
    monitoring_interval_seconds: document.getElementById('cfg-monitoring-interval').value.trim(),
    cooldown_minutes: document.getElementById('cfg-cooldown').value.trim()
  };

  const smtpPass = document.getElementById('cfg-smtp-pass').value;
  if (smtpPass) {
    updates.smtp_pass = smtpPass;
  } else {
    updates.keep_existing_smtp_pass = true;
  }

  try {
    const res = await api('/api/settings', {
      method: 'POST',
      body: JSON.stringify(updates)
    });
    state.settings = res.settings;
    showToast('All settings saved successfully!', 'success');
    await fetchMonitorStatus();
    updateHeaderStatus();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function testImpervaCredentials() {
  const accountId = document.getElementById('cfg-account-id').value.trim();
  const apiId = document.getElementById('cfg-api-id').value.trim();
  const apiKey = document.getElementById('cfg-api-key').value.trim();

  const resultContainer = document.getElementById('api-test-result');
  if (resultContainer) {
    resultContainer.style.display = 'block';
    resultContainer.innerHTML = '<span style="color:var(--primary);">Verifying credentials with Imperva API...</span>';
  }

  try {
    const res = await api('/api/settings/test-credentials', {
      method: 'POST',
      body: JSON.stringify({ account_id: accountId, api_id: apiId, api_key: apiKey })
    });
    showToast(res.message, 'success');
    if (resultContainer) {
      resultContainer.innerHTML = `
        <div style="background:#ecfdf5; border:1px solid #a7f3d0; color:#059669; padding:12px; border-radius:8px; font-size:13px;">
          <strong>✅ Success:</strong> ${res.message}
        </div>
      `;
    }
    await fetchPrefixes();
  } catch (err) {
    showToast(err.message, 'danger');
    if (resultContainer) {
      resultContainer.innerHTML = `
        <div style="background:#fef2f2; border:1px solid #fecaca; color:#dc2626; padding:12px; border-radius:8px; font-size:13px;">
          <strong>❌ Verification Failed:</strong> ${err.message}
        </div>
      `;
    }
  }
}

async function testSmtpEmail() {
  const recipient = prompt('Enter recipient email address to send test alert to:', state.settings.smtp_recipients || '');
  if (!recipient) return;

  try {
    showToast('Sending test alert email...', 'info');
    const res = await api('/api/settings/test-email', {
      method: 'POST',
      body: JSON.stringify({
        smtp_host: document.getElementById('cfg-smtp-host').value.trim(),
        smtp_port: document.getElementById('cfg-smtp-port').value.trim(),
        smtp_encryption: document.getElementById('cfg-smtp-encryption').value,
        smtp_user: document.getElementById('cfg-smtp-user').value.trim(),
        smtp_pass: document.getElementById('cfg-smtp-pass').value || state.settings.smtp_pass,
        smtp_sender: document.getElementById('cfg-smtp-sender').value.trim(),
        recipientEmail: recipient
      })
    });
    showToast(res.message, 'success');
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function handleChangePassword(e) {
  e.preventDefault();
  const currentPassword = document.getElementById('pwd-current').value;
  const newPassword = document.getElementById('pwd-new').value;
  const confirmPassword = document.getElementById('pwd-confirm').value;

  if (newPassword !== confirmPassword) {
    showToast('New passwords do not match.', 'danger');
    return;
  }

  try {
    const res = await api('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword, confirmPassword })
    });
    showToast(res.message, 'success');
    document.getElementById('pwd-current').value = '';
    document.getElementById('pwd-new').value = '';
    document.getElementById('pwd-confirm').value = '';
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// ----------------------------------------------------------------------
// Bootstrap
// ----------------------------------------------------------------------
window.addEventListener('DOMContentLoaded', () => {
  initApp();
});
