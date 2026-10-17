function getApiUrl() {
    if (window.location.protocol === "file:") {
        return "http://127.0.0.1:8000";
    }
    const host = window.location.hostname;
    if (!host || host === "localhost" || host === "127.0.0.1") {
        return "http://127.0.0.1:8000";
    }
    return `http://${host}:8000`;
}

const API_URL = getApiUrl();

// Chart instances
let charts = {};

function initCharts() {
    if (typeof Chart === "undefined") {
        console.warn("Chart.js library not loaded yet.");
        return;
    }

    if (charts.rssi) {
        return; // Already initialized
    }

    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: "#1e293b",
                titleColor: "#e2e8f0",
                bodyColor: "#e2e8f0",
                borderColor: "#475569",
                borderWidth: 1
            }
        },
        scales: {
            x: {
                grid: { color: "#1e293b" },
                ticks: { color: "#64748b", maxTicksLimit: 6 }
            },
            y: {
                grid: { color: "#1e293b" },
                ticks: { color: "#64748b" }
            }
        }
    };

    // 1. RSSI
    const ctxRssi = document.getElementById("rssiChart");
    if (ctxRssi) {
        charts.rssi = new Chart(ctxRssi, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "RSSI (dBm)",
                    data: [],
                    borderColor: "#38bdf8",
                    backgroundColor: "rgba(56, 189, 248, 0.1)",
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 2
                }]
            },
            options: commonOptions
        });
    }

    // 2. Packet Rate
    const ctxPacket = document.getElementById("packetRateChart");
    if (ctxPacket) {
        charts.packetRate = new Chart(ctxPacket, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Packet Rate",
                    data: [],
                    borderColor: "#a855f7",
                    backgroundColor: "rgba(168, 85, 247, 0.1)",
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 2
                }]
            },
            options: commonOptions
        });
    }

    // 3. Request Rate
    const ctxRequest = document.getElementById("requestRateChart");
    if (ctxRequest) {
        charts.requestRate = new Chart(ctxRequest, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Request Rate",
                    data: [],
                    borderColor: "#ec4899",
                    backgroundColor: "rgba(236, 72, 153, 0.1)",
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 2
                }]
            },
            options: commonOptions
        });
    }

    // 4. Free Heap
    const ctxHeap = document.getElementById("heapChart");
    if (ctxHeap) {
        charts.heap = new Chart(ctxHeap, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Free Heap (bytes)",
                    data: [],
                    borderColor: "#10b981",
                    backgroundColor: "rgba(16, 185, 129, 0.1)",
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 2
                }]
            },
            options: commonOptions
        });
    }

    // 5. Anomaly Score
    const ctxAnomaly = document.getElementById("anomalyChart");
    if (ctxAnomaly) {
        charts.anomaly = new Chart(ctxAnomaly, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Anomaly Score",
                    data: [],
                    borderColor: "#f59e0b",
                    backgroundColor: "rgba(245, 158, 11, 0.1)",
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 3
                }]
            },
            options: commonOptions
        });
    }

    // 6. Detection Status (1 for NORMAL, -1 for ANOMALY/THREAT)
    const ctxStatus = document.getElementById("statusChart");
    if (ctxStatus) {
        charts.status = new Chart(ctxStatus, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Status",
                    data: [],
                    borderColor: "#64748b",
                    borderWidth: 2,
                    stepped: true,
                    pointRadius: 4,
                    pointBackgroundColor: []
                }]
            },
            options: {
                ...commonOptions,
                scales: {
                    ...commonOptions.scales,
                    y: {
                        ticks: {
                            callback: function(value) {
                                if (value === 1) return "NORMAL";
                                if (value === -1) return "ANOMALY";
                                return "";
                            },
                            color: "#94a3b8"
                        },
                        min: -1.5,
                        max: 1.5
                    }
                }
            }
        });
    }
}

function ensureCharts() {
    if (!charts.rssi && typeof Chart !== "undefined") {
        initCharts();
    }
}

function updateCharts(events) {
    ensureCharts();
    if (typeof Chart === "undefined" || !charts.rssi) return;

    if (!events || events.length === 0) {
        return;
    }

    // Events arrive in descending order (latest first); reverse for chronological left-to-right plotting
    const chronoEvents = [...events].reverse();

    const labels = chronoEvents.map(e => {
        if (!e.timestamp) return "";
        const parts = e.timestamp.split(" ");
        if (parts.length > 1) {
            return parts[1].split(".")[0];
        }
        return e.timestamp.slice(11, 19);
    });

    // 1. RSSI
    charts.rssi.data.labels = labels;
    charts.rssi.data.datasets[0].data = chronoEvents.map(e => e.rssi ?? -28);
    charts.rssi.update("none");

    // 2. Packet Rate
    charts.packetRate.data.labels = labels;
    charts.packetRate.data.datasets[0].data = chronoEvents.map(e => e.packet_rate ?? 0.2);
    charts.packetRate.update("none");

    // 3. Request Rate
    charts.requestRate.data.labels = labels;
    charts.requestRate.data.datasets[0].data = chronoEvents.map(e => e.request_rate ?? 0.2);
    charts.requestRate.update("none");

    // 4. Free Heap
    charts.heap.data.labels = labels;
    charts.heap.data.datasets[0].data = chronoEvents.map(e => e.free_heap ?? 49000);
    charts.heap.update("none");

    // 5. Anomaly Score
    charts.anomaly.data.labels = labels;
    charts.anomaly.data.datasets[0].data = chronoEvents.map(e => e.anomaly_score ?? 0.18);
    charts.anomaly.data.datasets[0].pointBackgroundColor = chronoEvents.map(e => ((e.anomaly_score !== null && e.anomaly_score < 0) ? "#ef4444" : "#f59e0b"));
    charts.anomaly.data.datasets[0].pointRadius = chronoEvents.map(e => ((e.anomaly_score !== null && e.anomaly_score < 0) ? 5 : 2));
    charts.anomaly.update("none");

    // 6. Status (Alert markers highlighted)
    charts.status.data.labels = labels;
    charts.status.data.datasets[0].data = chronoEvents.map(e => (e.event_type === "NORMAL" ? 1 : -1));
    charts.status.data.datasets[0].pointBackgroundColor = chronoEvents.map(e => (e.event_type === "NORMAL" ? "#22c55e" : "#ef4444"));
    charts.status.data.datasets[0].pointRadius = chronoEvents.map(e => (e.event_type === "NORMAL" ? 3 : 6));
    charts.status.update("none");
}

async function loadTelemetry() {
    try {
        const response = await fetch(`${API_URL}/api/devices/latest`);
        if (!response.ok) {
            throw new Error("Backend unavailable");
        }

        const data = await response.json();
        if (data.status === "no_data") {
            return;
        }

        // Connection
        document.getElementById("connectionDot").style.background = "#22c55e";
        document.getElementById("connectionText").textContent = "Backend Online";

        // Device
        document.getElementById("deviceId").textContent = data.device_id ?? "--";
        document.getElementById("mac").textContent = data.mac ?? "--";
        document.getElementById("ip").textContent = data.ip ?? "--";
        document.getElementById("firmware").textContent = data.firmware ?? "--";

        // Telemetry
        document.getElementById("rssi").textContent = data.rssi ?? "--";
        document.getElementById("heap").textContent = data.free_heap ?? "--";
        document.getElementById("uptime").textContent = data.uptime ?? "--";
        document.getElementById("packets").textContent = data.packet_count ?? "--";
        document.getElementById("requests").textContent = data.request_count ?? "--";

        // Security & ML
        const secEl = document.getElementById("securityStatus");
        const secVal = (data.security_status ?? "--").toUpperCase();
        secEl.textContent = secVal;
        secEl.style.color = secVal === "TRUSTED" ? "#22c55e" : (secVal === "--" ? "#e2e8f0" : "#ef4444");

        const fwEl = document.getElementById("firmwareStatus");
        const fwVal = (data.firmware_status ?? "--").toUpperCase();
        fwEl.textContent = fwVal;
        fwEl.style.color = fwVal === "VALID" ? "#22c55e" : (fwVal === "--" ? "#e2e8f0" : "#ef4444");

        const mlEl = document.getElementById("mlStatus");
        const mlVal = (data.ml_detection ?? "--").toUpperCase();
        mlEl.textContent = mlVal;
        mlEl.style.color = mlVal === "NORMAL" ? "#22c55e" : (mlVal === "--" ? "#e2e8f0" : "#ef4444");

        const threatEl = document.getElementById("threat");
        const threatVal = (data.threat ?? "--").toUpperCase();
        threatEl.textContent = threatVal;
        threatEl.style.color = threatVal === "NONE" ? "#22c55e" : (threatVal === "--" ? "#e2e8f0" : "#ef4444");

        // Firmware MD5 & Timestamps
        document.getElementById("firmwareMd5").textContent = data.firmware_md5 ?? "--";
        document.getElementById("timestamp").textContent = data.timestamp ?? "--";

        // Behavior Monitoring
        document.getElementById("packetRate").textContent =
            (data.packet_rate ?? "--").toFixed ? Number(data.packet_rate ?? 0).toFixed(2) : "--";
        document.getElementById("requestRate").textContent =
            (data.request_rate ?? "--").toFixed ? Number(data.request_rate ?? 0).toFixed(2) : "--";
        document.getElementById("heapChange").textContent = data.heap_change ?? "--";
        document.getElementById("rssiChange").textContent = data.rssi_change ?? "--";
        document.getElementById("reboot").textContent =
            data.uptime_gap === 1 ? "YES" : (data.uptime_gap === 0 ? "NO" : "--");
        document.getElementById("anomalyScore").textContent =
            (data.anomaly_score ?? "--").toFixed ? Number(data.anomaly_score ?? 0).toFixed(3) : "--";

        document.getElementById("lastRefresh").textContent = new Date().toLocaleTimeString();
    } catch (error) {
        console.error("Telemetry fetch error:", error);
        document.getElementById("connectionDot").style.background = "#ef4444";
        document.getElementById("connectionText").textContent = "Backend Offline";
    }
}

async function loadHistory() {
    try {
        const response = await fetch(`${API_URL}/api/history?limit=100`);
        if (!response.ok) return;

        const raw = await response.json();
        const events = Array.isArray(raw) ? raw : (raw.events || []);

        const tbody = document.getElementById("historyTableBody");
        if (tbody) {
            if (events.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #94a3b8; padding: 20px;">Waiting for telemetry...</td></tr>`;
            } else {
                tbody.innerHTML = events.slice(0, 30).map(event => {
                    const timeStr = event.timestamp ? event.timestamp.split(".")[0] : "--";
                    const secBadge = (event.security_status === "trusted") ? "normal" : "danger";
                    const fwBadge = (event.firmware_status === "valid") ? "normal" : "warn";
                    const mlBadge = (event.ml_detection === "NORMAL") ? "normal" : "danger";
                    const threatBadge = (event.threat === "NONE") ? "normal" : "danger";
                    const eventBadge = (event.event_type === "NORMAL") ? "normal" : (event.event_type === "FIRMWARE_TAMPERED" ? "warn" : "danger");

                    return `
                        <tr>
                            <td>${timeStr}</td>
                            <td>${event.device_id || "--"}</td>
                            <td><span class="badge ${secBadge}">${(event.security_status || "--").toUpperCase()}</span></td>
                            <td><span class="badge ${fwBadge}">${(event.firmware_status || "--").toUpperCase()}</span></td>
                            <td><span class="badge ${mlBadge}">${(event.ml_detection || "--").toUpperCase()}</span></td>
                            <td><span class="badge ${threatBadge}">${(event.threat || "--").toUpperCase()}</span></td>
                            <td>${event.anomaly_score !== null && event.anomaly_score !== undefined ? Number(event.anomaly_score).toFixed(3) : "--"}</td>
                            <td><span class="badge ${eventBadge}">${(event.event_type || "--").toUpperCase()}</span></td>
                        </tr>
                    `;
                }).join("");
            }
        }

        updateCharts(events);
    } catch (error) {
        console.error("History fetch error:", error);
    }
}

async function loadSummary() {
    try {
        const response = await fetch(`${API_URL}/api/history/summary`);
        if (!response.ok) return;

        const summary = await response.json();

        const elTotal = document.getElementById("sumTotal");
        const elNormal = document.getElementById("sumNormal");
        const elAnomalies = document.getElementById("sumAnomalies");
        const elTampered = document.getElementById("sumTampered");
        const elRogue = document.getElementById("sumRogue");

        if (elTotal) elTotal.textContent = summary.total_events ?? 0;
        if (elNormal) elNormal.textContent = summary.normal_events ?? 0;
        if (elAnomalies) elAnomalies.textContent = summary.anomaly_events ?? 0;
        if (elTampered) elTampered.textContent = summary.firmware_tampered ?? 0;
        if (elRogue) elRogue.textContent = summary.rogue_devices ?? 0;
    } catch (error) {
        console.error("Summary fetch error:", error);
    }
}

async function triggerSimulation(type) {
    const box = document.getElementById("simResultBox");
    const badge = document.getElementById("simResultBadge");
    const elType = document.getElementById("simResultType");
    const elDetection = document.getElementById("simResultDetection");
    const elThreat = document.getElementById("simResultThreat");
    const elScore = document.getElementById("simResultScore");
    const elSecurity = document.getElementById("simResultSecurity");
    const elFirmware = document.getElementById("simResultFirmware");

    // Show loading state immediately
    if (box) box.style.display = "block";
    if (badge) {
        badge.className = "badge warn";
        badge.textContent = "RUNNING...";
    }
    if (elType) elType.textContent = type.replace("_", " ").toUpperCase();
    if (elDetection) elDetection.textContent = "Evaluating ML model...";
    if (elThreat) elThreat.textContent = "Analyzing pipeline...";
    if (elScore) elScore.textContent = "...";
    if (elSecurity) elSecurity.textContent = "...";
    if (elFirmware) elFirmware.textContent = "...";

    try {
        const response = await fetch(`${API_URL}/api/simulate/${type}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (!response.ok) {
            throw new Error(`Simulation failed with HTTP status ${response.status}`);
        }

        const data = await response.json();

        const simType = (data.simulation_type || data.type || type).replace("_", " ").toUpperCase();
        const detection = (data.detection || data.ml_detection || "NORMAL").toUpperCase();
        const threat = (data.threat || "NONE").toUpperCase();
        const score = data.anomaly_score !== undefined ? Number(data.anomaly_score).toFixed(3) : "0.000";
        const security = (data.security_status || "trusted").toUpperCase();
        const firmware = (data.firmware_status || "valid").toUpperCase();

        if (elType) elType.textContent = simType;

        if (elDetection) {
            elDetection.textContent = detection;
            elDetection.style.color = (detection === "NORMAL") ? "#22c55e" : "#ef4444";
        }
        if (elThreat) {
            elThreat.textContent = threat;
            elThreat.style.color = (threat === "NONE") ? "#22c55e" : "#ef4444";
        }
        if (elScore) {
            elScore.textContent = score;
            elScore.style.color = Number(score) < 0 ? "#ef4444" : "#22c55e";
        }
        if (elSecurity) {
            elSecurity.textContent = security;
            elSecurity.style.color = (security === "TRUSTED") ? "#22c55e" : "#ef4444";
        }
        if (elFirmware) {
            elFirmware.textContent = firmware;
            elFirmware.style.color = (firmware === "VALID") ? "#22c55e" : "#ef4444";
        }

        if (badge) {
            const isAnomaly = (detection === "ANOMALY") || (threat !== "NONE") || (security === "SUSPICIOUS");
            badge.className = isAnomaly ? "badge danger" : "badge normal";
            badge.textContent = isAnomaly ? (threat !== "NONE" ? threat : "ANOMALY") : "NORMAL";
        }

        // Refresh all data components
        await refreshDashboard();
    } catch (error) {
        console.error("Simulation error:", error);
        if (badge) {
            badge.className = "badge danger";
            badge.textContent = "ERROR";
        }
        if (elDetection) elDetection.textContent = "ERROR";
        if (elThreat) elThreat.textContent = "REQUEST FAILED";
    }
}

async function loadAlerts() {
    try {
        const response = await fetch(`${API_URL}/api/alerts?limit=50`);
        if (!response.ok) return;

        const alerts = await response.json();
        const tbody = document.getElementById("alertsTableBody");
        if (!tbody) return;

        if (!alerts || alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #94a3b8; padding: 20px;">No security alerts detected. System operating normally.</td></tr>`;
            return;
        }

        tbody.innerHTML = alerts.map(a => {
            const timeStr = a.timestamp ? a.timestamp.split(".")[0] : "--";
            const sev = (a.severity || "LOW").toUpperCase();
            const sevClass = sev === "CRITICAL" ? "sev-critical" :
                             sev === "HIGH" ? "sev-high" :
                             sev === "MEDIUM" ? "sev-medium" : "sev-low";

            const scoreStr = a.anomaly_score !== null && a.anomaly_score !== undefined
                ? Number(a.anomaly_score).toFixed(3)
                : "--";

            return `
                <tr>
                    <td><span class="sev-badge ${sevClass}">${sev}</span></td>
                    <td><strong>${a.alert_type || "--"}</strong></td>
                    <td>${a.threat || "--"}</td>
                    <td>${a.device_id || "--"}</td>
                    <td>${scoreStr}</td>
                    <td>${timeStr}</td>
                    <td style="max-width: 280px; font-size: 13px; color: #cbd5e1;">${a.description || "--"}</td>
                    <td><span class="status-active">${a.status || "ACTIVE"}</span></td>
                </tr>
            `;
        }).join("");
    } catch (error) {
        console.error("Alerts fetch error:", error);
    }
}

async function loadAlertStats() {
    try {
        const response = await fetch(`${API_URL}/api/alerts/stats`);
        if (!response.ok) return;

        const stats = await response.json();
        const elTotal = document.getElementById("alertSumTotal");
        const elCrit = document.getElementById("alertSumCritical");
        const elHigh = document.getElementById("alertSumHigh");
        const elMed = document.getElementById("alertSumMedium");
        const elLow = document.getElementById("alertSumLow");

        if (elTotal) elTotal.textContent = stats.total_alerts ?? 0;
        if (elCrit) elCrit.textContent = stats.critical_count ?? 0;
        if (elHigh) elHigh.textContent = stats.high_count ?? 0;
        if (elMed) elMed.textContent = stats.medium_count ?? 0;
        if (elLow) elLow.textContent = stats.low_count ?? 0;
    } catch (error) {
        console.error("Alert stats fetch error:", error);
    }
}

async function refreshDashboard() {
    await Promise.allSettled([
        loadTelemetry(),
        loadHistory(),
        loadSummary(),
        loadAlerts(),
        loadAlertStats()
    ]);
}

function startDashboard() {
    ensureCharts();
    refreshDashboard();
    setInterval(refreshDashboard, 2000);
}

// Ensure execution even if DOMContentLoaded already fired
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startDashboard);
} else {
    startDashboard();
}

