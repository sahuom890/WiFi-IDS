/**
 * main.js — Client-side interactivity for the Wi-Fi IDS dashboard.
 *
 * Handles:
 *  - Start / Stop monitoring (API calls)
 *  - Polling /api/alerts every 3 seconds
 *  - Updating stat cards and alert table
 *  - Logs page: search, filter, CSV export
 */

// =====================================================================
//  State
// =====================================================================
let pollInterval = null;     // setInterval ID for alert polling
let lastAlertId  = 0;        // Track newest alert to detect new rows
let allLogs      = [];       // Cache for the Logs page

// =====================================================================
//  Status helpers
// =====================================================================

/**
 * Update the UI status indicators (nav dot + dashboard badge).
 */
function setStatusUI(running, simulation) {
    // Navigation dot
    const navDot  = document.getElementById("nav-dot");
    const navText = document.getElementById("nav-status-text");
    if (navDot && navText) {
        navDot.className  = "status-dot " + (running ? "online" : "offline");
        navText.textContent = running ? "Monitoring" : "Offline";
    }

    // Dashboard controls
    const dot   = document.getElementById("status-dot");
    const text  = document.getElementById("status-text");
    const mode  = document.getElementById("mode-badge");
    const start = document.getElementById("btn-start");
    const stop  = document.getElementById("btn-stop");

    if (dot)   dot.className = "status-dot " + (running ? "online" : "offline");
    if (text)  text.textContent = running ? "Running" : "Stopped";
    if (mode)  mode.textContent = simulation ? "Mode: Simulation" : "Mode: Live Capture";
    if (start) start.disabled = running;
    if (stop)  stop.disabled  = !running;
}

/**
 * Fetch the current system status from the API.
 */
async function fetchStatus() {
    try {
        const res  = await fetch("/api/status");
        const data = await res.json();
        setStatusUI(data.running, data.simulation);
    } catch (e) {
        console.error("Status fetch failed:", e);
    }
}

// =====================================================================
//  Dashboard — Start / Stop
// =====================================================================

async function startMonitoring() {
    try {
        const res  = await fetch("/api/start", { method: "POST" });
        const data = await res.json();
        setStatusUI(data.running, true);
        startPolling();
    } catch (e) {
        console.error("Start failed:", e);
    }
}

async function stopMonitoring() {
    try {
        const res  = await fetch("/api/stop", { method: "POST" });
        const data = await res.json();
        setStatusUI(data.running, true);
        // Keep polling a little so we see the last alerts
    } catch (e) {
        console.error("Stop failed:", e);
    }
}

// =====================================================================
//  Dashboard — Alert polling
// =====================================================================

function startPolling() {
    if (pollInterval) return; // already polling
    pollInterval = setInterval(fetchAlerts, 3000);
    fetchAlerts(); // immediate first call
}

function stopPolling() {
    clearInterval(pollInterval);
    pollInterval = null;
}

/**
 * Fetch latest alerts and update the dashboard table + stats.
 */
async function fetchAlerts() {
    try {
        const res    = await fetch("/api/alerts");
        const alerts = await res.json();
        renderAlerts(alerts);
        updateStats(alerts);
    } catch (e) {
        console.error("Alert fetch failed:", e);
    }
}

/**
 * Build an attack-type badge span.
 */
function attackBadge(type) {
    let cls = "badge-deauth";
    if (type.includes("Suspicious")) cls = "badge-suspicious";
    if (type.includes("Brute"))      cls = "badge-brute";
    return `<span class="attack-badge ${cls}">${type}</span>`;
}

/**
 * Render alert rows into the dashboard table.
 */
function renderAlerts(alerts) {
    const tbody = document.getElementById("alerts-body");
    if (!tbody) return;

    if (alerts.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No alerts yet — start monitoring to begin packet analysis.</td></tr>`;
        return;
    }

    const newestId = alerts[0].id;
    const isNew    = newestId > lastAlertId;
    lastAlertId    = newestId;

    tbody.innerHTML = alerts.map((a, i) => `
        <tr class="${isNew && i === 0 ? 'row-new' : ''}">
            <td>${a.id}</td>
            <td>${a.timestamp}</td>
            <td>${a.source_mac}</td>
            <td>${attackBadge(a.attack_type)}</td>
            <td>${a.details || '—'}</td>
        </tr>
    `).join("");
}

/**
 * Update stat cards based on current alerts.
 */
function updateStats(alerts) {
    const total = alerts.length;
    const deauth = alerts.filter(a => a.attack_type.includes("Deauth")).length;
    const susMAC = alerts.filter(a => a.attack_type.includes("Suspicious")).length;
    const brute  = alerts.filter(a => a.attack_type.includes("Brute")).length;

    const el = id => document.getElementById(id);
    if (el("stat-total"))      el("stat-total").textContent      = total;
    if (el("stat-deauth"))     el("stat-deauth").textContent     = deauth;
    if (el("stat-suspicious")) el("stat-suspicious").textContent = susMAC;
    if (el("stat-brute"))      el("stat-brute").textContent      = brute;
}

// =====================================================================
//  Dashboard — Clear alerts
// =====================================================================

async function clearAlerts() {
    if (!confirm("Delete all alerts from the database?")) return;
    try {
        await fetch("/api/alerts/clear", { method: "POST" });
        lastAlertId = 0;
        fetchAlerts();
    } catch (e) {
        console.error("Clear failed:", e);
    }
}

// =====================================================================
//  Logs page
// =====================================================================

/**
 * Fetch every alert for the Logs page.
 */
async function fetchAllLogs() {
    try {
        const res  = await fetch("/api/alerts/all");
        allLogs    = await res.json();
        renderLogs(allLogs);
    } catch (e) {
        console.error("Log fetch failed:", e);
    }
}

/**
 * Render rows into the logs table (with optional filtered list).
 */
function renderLogs(logs) {
    const tbody = document.getElementById("logs-body");
    const count = document.getElementById("log-count");
    if (!tbody) return;

    if (logs.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="5">No logs found.</td></tr>`;
        if (count) count.textContent = "";
        return;
    }

    tbody.innerHTML = logs.map(a => `
        <tr>
            <td>${a.id}</td>
            <td>${a.timestamp}</td>
            <td>${a.source_mac}</td>
            <td>${attackBadge(a.attack_type)}</td>
            <td>${a.details || '—'}</td>
        </tr>
    `).join("");

    if (count) count.textContent = `Showing ${logs.length} record(s)`;
}

/**
 * Filter the logs table based on search text and type selector.
 */
function filterLogs() {
    const query  = (document.getElementById("log-search")?.value || "").toLowerCase();
    const type   = document.getElementById("log-filter")?.value || "all";

    const filtered = allLogs.filter(a => {
        const matchType = type === "all" || a.attack_type === type;
        const matchText =
            a.source_mac.toLowerCase().includes(query) ||
            a.attack_type.toLowerCase().includes(query) ||
            (a.details || "").toLowerCase().includes(query);
        return matchType && matchText;
    });

    renderLogs(filtered);
}

/**
 * Export the currently displayed logs as a CSV file download.
 */
function exportCSV() {
    const rows   = document.querySelectorAll("#logs-table tbody tr:not(.empty-row)");
    if (rows.length === 0) { alert("No logs to export."); return; }

    let csv = "ID,Timestamp,Source MAC,Attack Type,Details\n";
    allLogs.forEach(a => {
        csv += `${a.id},"${a.timestamp}","${a.source_mac}","${a.attack_type}","${a.details || ''}"\n`;
    });

    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href     = url;
    link.download = "wifi_ids_logs.csv";
    link.click();
    URL.revokeObjectURL(url);
}

// =====================================================================
//  Init
// =====================================================================

document.addEventListener("DOMContentLoaded", () => {
    fetchStatus();

    // If on the dashboard page, start polling immediately
    if (document.getElementById("alerts-body")) {
        startPolling();
    }
});
