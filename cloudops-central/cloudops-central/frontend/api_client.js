/**
 * CloudOps Central — Frontend API Client v3.0
 * Multi-cloud: AWS + Azure + GCP
 *
 * Security fixes applied:
 *  - API_BASE is a fixed constant, never user-controlled (SSRF fix)
 *  - No credentials stored in source code
 *  - Token stored in sessionStorage only (cleared on tab close)
 *  - All fetch calls go through the api() helper with auth headers
 */

// Fixed base URL — never interpolate user input here (SSRF prevention)
const API_BASE = "http://127.0.0.1:8000";
let AUTH_TOKEN = null;

// ── HTTP helper ───────────────────────────────────────────────────────────────
async function api(method, path, body = null, requiresAuth = true) {
  const headers = { "Content-Type": "application/json" };
  if (requiresAuth && AUTH_TOKEN) {
    headers["Authorization"] = `Bearer ${AUTH_TOKEN}`;
  }
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  const res = await fetch(`${API_BASE}${path}`, opts);

  if (res.status === 401) {
    AUTH_TOKEN = null;
    if (typeof doLogout === "function") doLogout();
    throw new Error("Session expired. Please sign in again.");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `API error ${res.status}`);
  }
  return res.json();
}

// ── Auth ──────────────────────────────────────────────────────────────────────
async function doLoginAPI(username, password) {
  const res = await fetch(`${API_BASE}/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ username, password }),
  });
  if (!res.ok) throw new Error("Invalid credentials");
  const data = await res.json();
  AUTH_TOKEN = data.access_token;
  try { sessionStorage.setItem("cloudops_token", AUTH_TOKEN); } catch (e) {}
  return data;
}

function loadStoredToken() {
  try {
    const stored = sessionStorage.getItem("cloudops_token");
    if (stored) { AUTH_TOKEN = stored; return true; }
  } catch (e) {}
  return false;
}

function clearToken() {
  AUTH_TOKEN = null;
  try { sessionStorage.removeItem("cloudops_token"); } catch (e) {}
}

// ── Accounts (multi-cloud) ────────────────────────────────────────────────────
async function fetchAccounts(region = null, provider = null) {
  const params = new URLSearchParams();
  if (region && region !== "all") params.set("region", region);
  if (provider && provider !== "all") params.set("provider", provider);
  const qs = params.toString() ? `?${params}` : "";
  const data = await api("GET", `/accounts${qs}`);
  return data.accounts;
}

async function fetchAccountDetail(accountId) {
  return api("GET", `/accounts/${accountId}`);
}

async function fetchAccountCosts(accountId) {
  return api("GET", `/accounts/${accountId}/costs`);
}

async function fetchAllAlarms() {
  return api("GET", "/alarms");
}

async function fetchAccountAlarms(accountId) {
  return api("GET", `/accounts/${accountId}/alarms`);
}

async function fetchProviders() {
  return api("GET", "/providers", null, false);
}

// ── Admin: Onboarding ─────────────────────────────────────────────────────────
async function onboardAccountAPI(formData) {
  return api("POST", "/admin/accounts/onboard", formData);
}

async function removeAccountAPI(accountId) {
  return api("DELETE", `/admin/accounts/${accountId}`);
}

// ── Admin: Users ──────────────────────────────────────────────────────────────
async function fetchUsers() {
  return api("GET", "/admin/users");
}

async function createUserAPI(payload) {
  return api("POST", "/admin/users", payload);
}

async function deleteUserAPI(username) {
  return api("DELETE", `/admin/users/${username}`);
}

// ── Alarms ────────────────────────────────────────────────────────────────────
async function createAlarmAPI(accountId, payload) {
  return api("POST", `/accounts/${accountId}/alarms/create`, payload);
}

async function deleteAlarmAPI(accountId, alarmName) {
  return api("DELETE", `/accounts/${accountId}/alarms/${encodeURIComponent(alarmName)}`);
}

async function listAllAlarmsAPI(accountId) {
  return api("GET", `/accounts/${accountId}/alarms/list`);
}

// ── Metrics ───────────────────────────────────────────────────────────────────
async function fetchEC2PerInstanceMetrics(accountId, timeRange = "6h") {
  return api("GET", `/accounts/${accountId}/metrics/EC2/per-instance?time_range=${timeRange}`);
}

// ── Charts: render API response into Chart.js ─────────────────────────────────
function renderChartsFromAPI(charts, accentColor = "#38b6ff") {
  const grid = document.getElementById("svc-charts-grid");
  if (!grid) return;
  Object.values(svcCharts || {}).forEach((c) => { try { c.destroy(); } catch (e) {} });
  if (typeof svcCharts !== "undefined") svcCharts = {};

  grid.innerHTML = charts.map((c) => `
    <div class="chart-card">
      <div class="chart-title">${c.title}
        <span class="chart-value-badge">${c.latest}${c.unit}</span>
      </div>
      <canvas id="apichart-${c.id}"></canvas>
    </div>`).join("");

  setTimeout(() => {
    charts.forEach((c) => {
      const ctx = document.getElementById(`apichart-${c.id}`);
      if (!ctx || !c.data.length) return;
      const maxVal = Math.max(...c.data);
      const color = c.title.toLowerCase().includes("error") || c.title.toLowerCase().includes("5xx")
        ? "#ff4d6a"
        : c.title.toLowerCase().includes("cpu") && maxVal > 70 ? "#ff4d6a"
        : c.title.toLowerCase().includes("cpu") && maxVal > 50 ? "#f0c040"
        : accentColor;

      if (typeof svcCharts !== "undefined") {
        svcCharts[c.id] = new Chart(ctx, {
          type: "line",
          data: {
            labels: c.labels,
            datasets: [{ data: c.data, borderColor: color, borderWidth: 2, fill: true,
              backgroundColor: color + "18", tension: 0.4, pointRadius: 3,
              pointBackgroundColor: color, pointBorderColor: "transparent", pointHoverRadius: 5 }],
          },
          options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false },
              tooltip: { backgroundColor: "#0d1117", borderColor: "#1e2d3d", borderWidth: 1,
                titleColor: "#6b8299", bodyColor: "#c9d8e8",
                titleFont: { family: "JetBrains Mono", size: 10 },
                bodyFont: { family: "JetBrains Mono", size: 11 } } },
            scales: {
              x: { grid: { color: "#1e2d3d" }, ticks: { color: "#3d5a73", font: { family: "JetBrains Mono", size: 9 }, maxTicksLimit: 7 } },
              y: { grid: { color: "#1e2d3d" }, ticks: { color: "#3d5a73", font: { family: "JetBrains Mono", size: 9 } }, beginAtZero: true },
            },
          },
        });
      }
    });
  }, 50);
}

// ── Polling ───────────────────────────────────────────────────────────────────
let pollingInterval = null;

function startPolling(intervalMs = 30000) {
  stopPolling();
  pollingInterval = setInterval(async () => {
    try {
      const overviewPage = document.getElementById("page-overview");
      if (overviewPage && overviewPage.classList.contains("active")) {
        if (typeof renderOverview === "function") await renderOverview();
      }
      if (typeof checkAppAlerts === "function") await checkAppAlerts();
    } catch (e) {
      console.warn("Polling error:", e);
    }
  }, intervalMs);
}

function stopPolling() {
  if (pollingInterval) { clearInterval(pollingInterval); pollingInterval = null; }
}

// ── Provider helpers ──────────────────────────────────────────────────────────
const PROVIDER_META = {
  aws:   { icon: "☁️",  color: "#ff9900", label: "AWS",   bgColor: "rgba(255,153,0,0.1)"   },
  azure: { icon: "🔷", color: "#0078d4", label: "Azure", bgColor: "rgba(0,120,212,0.1)"   },
  gcp:   { icon: "🌈", color: "#4285f4", label: "GCP",   bgColor: "rgba(66,133,244,0.1)"  },
};

function providerBadge(provider) {
  const m = PROVIDER_META[provider] || PROVIDER_META.aws;
  return `<span style="display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:4px;
    background:${m.bgColor};color:${m.color};font-family:var(--font-mono);font-size:9px;font-weight:700;
    border:1px solid ${m.color}33">${m.icon} ${m.label}</span>`;
}
