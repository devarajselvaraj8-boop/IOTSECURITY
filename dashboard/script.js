/**
 * IoT Cybersecurity Monitoring Center - Core Frontend Logic
 * High-stability, non-destructive real-time telemetry pipeline with zero layout shift.
 */

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
const IS_DEV = false;

function logDev(...args) {
    if (IS_DEV) {
        console.log("[IoT]", ...args);
    }
}

// Global State
let activeDeviceId = "ESP8266-01";
let registeredDevices = [];
let charts = {};
let lastChartTimestamp = null;
let lastHistorySignature = "";
let lastAlertsSignature = "";
let isPollingActive = false;

// Concurrency & in-flight guards (prevent overlapping requests)
let isTelemetryLoading = false;
let isFleetLoading = false;
let isHistoryLoading = false;
let isAlertsLoading = false;
let isHealthLoading = false;
let lastFleetSignature = "";
let lastTimelineSignature = "";

// Request abort controllers for concurrency stability
let telemetryAbortController = null;
let historyAbortController = null;
let alertsAbortController = null;

function getAuthHeaders() {
    return { "Content-Type": "application/json" };
}

// =========================================================================
// Backend Health Verification
// =========================================================================

async function checkBackendHealth() {
    if (isHealthLoading) return;
    isHealthLoading = true;

    const dot = document.getElementById("connectionDot");
    const txt = document.getElementById("connectionText");

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);

        const response = await fetch(`${API_URL}/api/health`, {
            signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (response.ok) {
            if (dot) dot.style.background = "#22c55e";
            if (txt) txt.textContent = "Backend Online";
            return true;
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (err) {
        if (dot) dot.style.background = "#ef4444";
        if (txt) txt.textContent = "Backend Offline";
        return false;
    } finally {
        isHealthLoading = false;
    }
}

// =========================================================================
// Multi-Device Management & Switching
// =========================================================================

function getRiskBadge(score, level) {
    const lvl = (level || "LOW").toUpperCase();
    let badgeClass = "risk-low";
    if (lvl === "MEDIUM") badgeClass = "risk-medium";
    else if (lvl === "HIGH") badgeClass = "risk-high";
    else if (lvl === "CRITICAL") badgeClass = "risk-critical";

    return `<span class="badge ${badgeClass}">${score} (${lvl})</span>`;
}

async function loadDeviceList() {
    if (isFleetLoading) return;
    isFleetLoading = true;

    try {
        const response = await fetch(`${API_URL}/api/devices`, {
            headers: getAuthHeaders()
        });
        if (!response.ok) return;

        const devices = await response.json();
        registeredDevices = devices;

        const currentSignature = JSON.stringify(devices) + "_" + activeDeviceId;
        const fleetChanged = currentSignature !== lastFleetSignature;

        // 1. Update Header Switcher & Sim Target Dropdown STABLY (only if options change)
        const selector = document.getElementById("deviceSelector");
        const simSelector = document.getElementById("simTargetDevice");
        const currentDeviceIds = devices.map(d => d.device_id);

        if (selector) {
            const existingOptions = Array.from(selector.options).map(o => o.value);
            const optionsChanged = existingOptions.join(",") !== currentDeviceIds.join(",");

            if (optionsChanged || selector.options.length === 0) {
                selector.innerHTML = devices.map(d => {
                    const label = `${d.device_id} (${d.identity_status || (d.is_registered ? "REGISTERED" : "UNREGISTERED")})`;
                    return `<option value="${d.device_id}">${label}</option>`;
                }).join("");
            }

            if (currentDeviceIds.includes(activeDeviceId)) {
                selector.value = activeDeviceId;
            } else if (devices.length > 0) {
                activeDeviceId = devices[0].device_id;
                selector.value = activeDeviceId;
            }
        }

        if (simSelector) {
            const existingSimOpts = Array.from(simSelector.options).map(o => o.value);
            if (existingSimOpts.join(",") !== currentDeviceIds.join(",")) {
                simSelector.innerHTML = devices.map(d => {
                    return `<option value="${d.device_id}">${d.device_id}</option>`;
                }).join("");
            }
            if (currentDeviceIds.includes(activeDeviceId)) {
                simSelector.value = activeDeviceId;
            }
        }

        // 2. Update Device Fleet Overview Table only when content changed
        if (fleetChanged) {
            lastFleetSignature = currentSignature;
            const tbody = document.getElementById("fleetTableBody");
            if (tbody) {
                if (devices.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="10" style="text-align: center; color: #94a3b8; padding: 18px;">No devices detected or registered.</td></tr>`;
                } else {
                    tbody.innerHTML = devices.map(d => {
                        const isActive = d.device_id === activeDeviceId;
                        const identityBadge = d.is_registered ? `<span class="badge normal">REGISTERED</span>` : `<span class="badge danger">UNREGISTERED (ROGUE)</span>`;
                        const fwBadge = (d.firmware_status || "").toUpperCase() === "VALID" ? `<span class="badge normal">VALID</span>` : `<span class="badge warn">${(d.firmware_status || "--").toUpperCase()}</span>`;
                        const mlBadge = (d.ml_detection || d.ml_status || "").toUpperCase() === "NORMAL" ? `<span class="badge normal">NORMAL</span>` : `<span class="badge danger">${(d.ml_detection || d.ml_status || "--").toUpperCase()}</span>`;

                        const secUpper = (d.security_status || "--").toUpperCase();
                        let secClass = "danger";
                        if (secUpper === "TRUSTED") secClass = "normal";
                        else if (secUpper === "MONITORING" || secUpper === "RECOVERING") secClass = "warn";
                        const secBadge = `<span class="badge ${secClass}">${secUpper}</span>`;

                        const riskBadge = getRiskBadge(d.risk_score ?? 0, d.risk_level ?? "LOW");
                        const lastSeen = d.last_seen ? d.last_seen.split(".")[0] : "--";

                        return `
                            <tr class="${isActive ? "active-row" : ""}">
                                <td><strong>${d.device_id}</strong> ${isActive ? "⭐" : ""}</td>
                                <td><code>${d.mac || "--"}</code></td>
                                <td>${d.ip || "--"}</td>
                                <td>${identityBadge}</td>
                                <td>${fwBadge}</td>
                                <td>${mlBadge}</td>
                                <td>${secBadge}</td>
                                <td>${riskBadge}</td>
                                <td style="font-size: 11px; color: #94a3b8;">${lastSeen}</td>
                                <td>
                                    <button class="btn-table-action" onclick="selectDevice('${d.device_id}')">
                                        ${isActive ? "Selected" : "Monitor"}
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join("");
                }
            }
        }

        // 3. Update Registered Devices inside Device Management Modal
        const regTbody = document.getElementById("registeredDevicesTableBody");
        if (regTbody) {
            const regOnly = devices.filter(d => d.is_registered);
            if (regOnly.length === 0) {
                regTbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #94a3b8; padding: 14px;">No devices registered in database.</td></tr>`;
            } else {
                regTbody.innerHTML = regOnly.map(d => {
                    return `
                        <tr>
                            <td><strong>${d.device_id}</strong></td>
                            <td><code>${d.mac || "--"}</code></td>
                            <td>${d.firmware_version || d.firmware || "1.0.0"}</td>
                            <td>${d.registered_at ? d.registered_at.split(".")[0] : "--"}</td>
                            <td>
                                <button class="btn-danger" onclick="handleUnregisterDevice('${d.device_id}')">Unregister</button>
                            </td>
                        </tr>
                    `;
                }).join("");
            }
        }

    } catch (err) {
        logDev("Device list fetch error:", err);
    } finally {
        isFleetLoading = false;
    }
}

function selectDevice(deviceId) {
    if (!deviceId) return;
    activeDeviceId = deviceId;
    logDev("Selected device changed to:", activeDeviceId);

    const selector = document.getElementById("deviceSelector");
    if (selector && selector.value !== deviceId) selector.value = deviceId;

    const simSelector = document.getElementById("simTargetDevice");
    if (simSelector && simSelector.value !== deviceId) simSelector.value = deviceId;

    const targetBadge = document.getElementById("targetDeviceBadge");
    if (targetBadge) targetBadge.textContent = deviceId;

    const filterName = document.getElementById("filterDeviceName");
    if (filterName) filterName.textContent = deviceId;

    const chartName = document.getElementById("chartDeviceName");
    if (chartName) chartName.textContent = deviceId;

    // Abort pending telemetry request to avoid stale responses
    if (telemetryAbortController) {
        telemetryAbortController.abort();
    }

    // Refresh telemetry and history for this device immediately
    loadTelemetry();
    loadHistory();
    loadSummary();
    loadAlerts();
    loadAlertStats();
    loadDeviceList();
}

function onDeviceSelectorChange(deviceId) {
    selectDevice(deviceId);
}

// Device Modal Controls
function openDeviceModal() {
    const modal = document.getElementById("deviceModal");
    loadDeviceList();
    if (modal) modal.style.display = "flex";
}

function closeDeviceModal() {
    const modal = document.getElementById("deviceModal");
    if (modal) modal.style.display = "none";
}

async function handleRegisterDevice(event) {
    if (event) event.preventDefault();
    const idInput = document.getElementById("regDeviceId");
    const macInput = document.getElementById("regMac");
    const ipInput = document.getElementById("regIp");
    const fwInput = document.getElementById("regFirmware");
    const md5Input = document.getElementById("regMd5");

    const payload = {
        device_id: idInput.value.trim(),
        mac: macInput.value.trim(),
        ip: ipInput.value.trim() || null,
        firmware_version: fwInput.value.trim() || "1.0.0",
        expected_firmware_md5: md5Input.value.trim() || "7e324de5695029e84b0f91b7e6ef4050"
    };

    try {
        const response = await fetch(`${API_URL}/api/devices/register`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify(payload)
        });

        const data = await response.json();
        if (response.ok && (data.success || data.status === "registered" || data.status === "updated")) {
            idInput.value = "";
            macInput.value = "";
            ipInput.value = "";
            await loadDeviceList();
            alert(`Device ${payload.device_id} registered successfully.`);
        } else {
            alert(data.detail || data.message || "Device registration failed.");
        }
    } catch (err) {
        alert("Error registering device. Ensure backend is running.");
    }
}

async function handleUnregisterDevice(deviceId) {
    if (!confirm(`Are you sure you want to unregister device "${deviceId}"? It will be treated as an UNREGISTERED / ROGUE device if observed.`)) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/api/devices/${encodeURIComponent(deviceId)}`, {
            method: "DELETE",
            headers: getAuthHeaders()
        });

        const data = await response.json();
        if (response.ok && (data.success || data.status === "deleted")) {
            await loadDeviceList();
            await loadTelemetry();
        } else {
            alert(data.detail || "Failed to unregister device.");
        }
    } catch (err) {
        alert("Error communicating with server.");
    }
}

// =========================================================================
// Real-Time Charts (Chart.js In-Place Dataset Updates)
// =========================================================================

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
                    label: "Decision Score",
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

    // 6. Detection Status (1 for NORMAL, -1 for ANOMALY)
    const ctxStatus = document.getElementById("statusChart");
    if (ctxStatus) {
        charts.status = new Chart(ctxStatus, {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Observation",
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
                            callback: function (value) {
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
    if (typeof Chart === "undefined" || !charts.rssi || !events || events.length === 0) {
        return;
    }

    const latestTimestamp = events[0] ? events[0].timestamp : null;
    if (latestTimestamp && latestTimestamp === lastChartTimestamp) {
        return;
    }
    lastChartTimestamp = latestTimestamp;

    const chronoEvents = [...events].reverse();

    const labels = chronoEvents.map(e => {
        if (!e.timestamp) return "";
        const parts = e.timestamp.split(" ");
        if (parts.length > 1) {
            return parts[1].split(".")[0];
        }
        return e.timestamp.slice(11, 19);
    });

    charts.rssi.data.labels = labels;
    charts.rssi.data.datasets[0].data = chronoEvents.map(e => e.rssi ?? -28);
    charts.rssi.update("none");

    charts.packetRate.data.labels = labels;
    charts.packetRate.data.datasets[0].data = chronoEvents.map(e => e.packet_rate ?? 0.2);
    charts.packetRate.update("none");

    charts.requestRate.data.labels = labels;
    charts.requestRate.data.datasets[0].data = chronoEvents.map(e => e.request_rate ?? 0.2);
    charts.requestRate.update("none");

    charts.heap.data.labels = labels;
    charts.heap.data.datasets[0].data = chronoEvents.map(e => e.free_heap ?? 49000);
    charts.heap.update("none");

    charts.anomaly.data.labels = labels;
    charts.anomaly.data.datasets[0].data = chronoEvents.map(e => e.anomaly_score ?? 0.18);
    charts.anomaly.data.datasets[0].pointBackgroundColor = chronoEvents.map(e => ((e.anomaly_score !== null && e.anomaly_score < 0) ? "#ef4444" : "#f59e0b"));
    charts.anomaly.data.datasets[0].pointRadius = chronoEvents.map(e => ((e.anomaly_score !== null && e.anomaly_score < 0) ? 4 : 2));
    charts.anomaly.update("none");

    charts.status.data.labels = labels;
    charts.status.data.datasets[0].data = chronoEvents.map(e => (e.ml_detection === "NORMAL" || e.event_type === "NORMAL" ? 1 : -1));
    charts.status.data.datasets[0].pointBackgroundColor = chronoEvents.map(e => (e.ml_detection === "NORMAL" || e.event_type === "NORMAL" ? "#22c55e" : "#ef4444"));
    charts.status.data.datasets[0].pointRadius = chronoEvents.map(e => (e.ml_detection === "NORMAL" || e.event_type === "NORMAL" ? 3 : 5));
    charts.status.update("none");
}

// =========================================================================
// Telemetry & Security State Polling (Pure In-Place Non-Destructive Updates)
// =========================================================================

async function loadTelemetry() {
    if (isTelemetryLoading) return;
    isTelemetryLoading = true;

    telemetryAbortController = new AbortController();
    const timeoutId = setTimeout(() => telemetryAbortController.abort(), 4500);
    const url = `${API_URL}/api/devices/latest?device_id=${encodeURIComponent(activeDeviceId)}`;

    try {
        const response = await fetch(url, {
            headers: getAuthHeaders(),
            signal: telemetryAbortController.signal
        });
        clearTimeout(timeoutId);

        if (!response.ok) {
            setTelemetryStatus("delayed");
            return;
        }

        const data = await response.json();
        setTelemetryStatus("live");

        if (data.status === "no_data") {
            const devIdEl = document.getElementById("deviceId");
            if (devIdEl) devIdEl.textContent = activeDeviceId;
            const timeEl = document.getElementById("timestamp");
            if (timeEl) timeEl.textContent = "No telemetry received yet";
            const reasonEl = document.getElementById("anomalyReason");
            if (reasonEl) {
                reasonEl.textContent = "No telemetry recorded for this device identity yet.";
                reasonEl.style.color = "#94a3b8";
            }
            return;
        }

        // 1. Target Device Information
        const devIdEl = document.getElementById("deviceId");
        if (devIdEl && devIdEl.textContent !== (data.device_id || activeDeviceId)) devIdEl.textContent = data.device_id || activeDeviceId;
        const macEl = document.getElementById("mac");
        if (macEl && data.mac && macEl.textContent !== data.mac) macEl.textContent = data.mac;
        const ipEl = document.getElementById("ip");
        if (ipEl && data.ip && ipEl.textContent !== data.ip) ipEl.textContent = data.ip;
        const fwVerEl = document.getElementById("firmware");
        if (fwVerEl && data.firmware && fwVerEl.textContent !== data.firmware) fwVerEl.textContent = data.firmware;

        // 2. Multi-Layer Security & Risk Posture
        const idStatusEl = document.getElementById("identityStatus");
        const idVal = (data.identity_status || (data.is_registered ? "REGISTERED" : "UNREGISTERED")).toUpperCase();
        if (idStatusEl) {
            if (idStatusEl.textContent !== idVal) idStatusEl.textContent = idVal;
            idStatusEl.style.color = idVal === "REGISTERED" ? "#22c55e" : "#ef4444";
        }

        const fwEl = document.getElementById("firmwareStatus");
        const fwVal = (data.firmware_status || "--").toUpperCase();
        if (fwEl) {
            if (fwEl.textContent !== fwVal) fwEl.textContent = fwVal;
            fwEl.style.color = fwVal === "VALID" ? "#22c55e" : (fwVal === "--" ? "#e2e8f0" : "#ef4444");
        }

        const mlEl = document.getElementById("mlStatus");
        const mlVal = (data.ml_observation || data.ml_detection || data.ml_status || "--").toUpperCase();
        if (mlEl) {
            if (mlEl.textContent !== mlVal) mlEl.textContent = mlVal;
            mlEl.style.color = mlVal === "NORMAL" ? "#22c55e" : (mlVal === "--" ? "#e2e8f0" : "#ef4444");
        }

        const streakEl = document.getElementById("anomalyStreakDisplay");
        const streakLabelEl = document.getElementById("streakStateLabel");
        if (streakEl) {
            const anomStreak = data.anomaly_streak ?? 0;
            const anomThresh = data.anomaly_confirmation_count ?? 3;
            const streakText = `${anomStreak} / ${anomThresh}`;
            if (streakEl.textContent !== streakText) streakEl.textContent = streakText;
            streakEl.style.color = anomStreak >= anomThresh ? "#ef4444" : (anomStreak > 0 ? "#f59e0b" : "#38bdf8");
        }
        if (streakLabelEl) {
            const labelText = data.behavior_status || (data.anomaly_streak > 0 ? "Monitoring" : "Baseline");
            if (streakLabelEl.textContent !== labelText) streakLabelEl.textContent = labelText;
            streakLabelEl.style.color = data.behavior_status === "PERSISTENT ANOMALY" ? "#ef4444" : (data.behavior_status === "ISOLATED ANOMALY" ? "#f59e0b" : "#38bdf8");
        }

        const secEl = document.getElementById("securityStatus");
        const secVal = (data.security_status || "--").toUpperCase();
        if (secEl) {
            if (secEl.textContent !== secVal) secEl.textContent = secVal;
            if (secVal === "TRUSTED") secEl.style.color = "#22c55e";
            else if (secVal === "MONITORING") secEl.style.color = "#38bdf8";
            else if (secVal === "RECOVERING") secEl.style.color = "#a855f7";
            else if (secVal === "--") secEl.style.color = "#e2e8f0";
            else secEl.style.color = "#ef4444";
        }

        // Risk Score & Badge
        const riskScoreEl = document.getElementById("riskScore");
        const riskBadgeEl = document.getElementById("riskLevelBadge");
        if (riskScoreEl) {
            const rScore = data.risk_score !== undefined ? data.risk_score : 0;
            const rLevel = (data.risk_level || "LOW").toUpperCase();
            const scoreText = `${rScore} / 100`;
            if (riskScoreEl.textContent !== scoreText) riskScoreEl.textContent = scoreText;

            if (riskBadgeEl) {
                if (riskBadgeEl.textContent !== rLevel) riskBadgeEl.textContent = rLevel;
                riskBadgeEl.className = `badge risk-${rLevel.toLowerCase()}`;
            }
        }

        // 3. Live Telemetry Metrics
        const rssiEl = document.getElementById("rssi");
        if (rssiEl && data.rssi !== undefined && data.rssi !== null && rssiEl.textContent !== String(data.rssi)) rssiEl.textContent = data.rssi;
        const heapEl = document.getElementById("heap");
        if (heapEl && data.free_heap !== undefined && data.free_heap !== null && heapEl.textContent !== String(data.free_heap)) heapEl.textContent = data.free_heap;
        const uptimeEl = document.getElementById("uptime");
        if (uptimeEl && data.uptime !== undefined && data.uptime !== null && uptimeEl.textContent !== String(data.uptime)) uptimeEl.textContent = data.uptime;
        const packetsEl = document.getElementById("packets");
        if (packetsEl && data.packet_count !== undefined && data.packet_count !== null && packetsEl.textContent !== String(data.packet_count)) packetsEl.textContent = data.packet_count;
        const requestsEl = document.getElementById("requests");
        if (requestsEl && data.request_count !== undefined && data.request_count !== null && requestsEl.textContent !== String(data.request_count)) requestsEl.textContent = data.request_count;

        // 4. Firmware MD5 & Verification
        const expMd5El = document.getElementById("expectedFirmwareMd5");
        if (expMd5El) {
            const expVal = data.expected_firmware_md5 || "--";
            if (expMd5El.textContent !== expVal) expMd5El.textContent = expVal;
        }
        const fwMd5El = document.getElementById("firmwareMd5");
        if (fwMd5El && data.firmware_md5 && fwMd5El.textContent !== data.firmware_md5) fwMd5El.textContent = data.firmware_md5;
        const fwIntegEl = document.getElementById("firmwareIntegrityDisplay");
        if (fwIntegEl) {
            const fwVal = (data.firmware_status || "--").toUpperCase();
            const fwBadgeClass = fwVal === "VALID" ? "normal" : (fwVal === "--" ? "normal" : "danger");
            const badgeHtml = `<span class="badge ${fwBadgeClass}">${fwVal}</span>`;
            if (fwIntegEl.innerHTML !== badgeHtml) fwIntegEl.innerHTML = badgeHtml;
        }
        const tsEl = document.getElementById("timestamp");
        if (tsEl && data.timestamp && tsEl.textContent !== data.timestamp) tsEl.textContent = data.timestamp;

        // 5. Behavior Monitoring Metrics
        const prEl = document.getElementById("packetRate");
        if (prEl && data.packet_rate !== undefined && data.packet_rate !== null) {
            const prText = Number(data.packet_rate).toFixed(2);
            if (prEl.textContent !== prText) prEl.textContent = prText;
        }
        const rrEl = document.getElementById("requestRate");
        if (rrEl && data.request_rate !== undefined && data.request_rate !== null) {
            const rrText = Number(data.request_rate).toFixed(2);
            if (rrEl.textContent !== rrText) rrEl.textContent = rrText;
        }
        const hcEl = document.getElementById("heapChange");
        if (hcEl && data.heap_change !== undefined && data.heap_change !== null && hcEl.textContent !== String(data.heap_change)) hcEl.textContent = data.heap_change;
        const rcEl = document.getElementById("rssiChange");
        if (rcEl && data.rssi_change !== undefined && data.rssi_change !== null && rcEl.textContent !== String(data.rssi_change)) rcEl.textContent = data.rssi_change;
        
        const rebEl = document.getElementById("reboot");
        const uptimeEvEl = document.getElementById("uptimeEvidence");
        if (rebEl) {
            const isReboot = data.uptime_gap === 1;
            const rebText = isReboot ? "YES" : (data.uptime_gap === 0 ? "NO" : "--");
            if (rebEl.textContent !== rebText) rebEl.textContent = rebText;
            rebEl.style.color = isReboot ? "#ef4444" : "#22c55e";
        }
        if (uptimeEvEl) {
            let evText = "--";
            const prevU = data.previous_uptime;
            const currU = data.uptime ?? data.current_uptime;
            if (prevU !== undefined && prevU !== null) {
                if (data.uptime_gap === 1) {
                    evText = `Prev: ${prevU}s | Curr: ${currU}s`;
                } else {
                    evText = `Uptime: ${currU}s`;
                }
            } else if (currU !== undefined && currU !== null && currU !== "--") {
                evText = `Uptime: ${currU}s`;
            }
            if (uptimeEvEl.textContent !== evText) uptimeEvEl.textContent = evText;
            uptimeEvEl.style.color = data.uptime_gap === 1 ? "#f87171" : "#94a3b8";
        }

        // 6. Isolation Forest Score & Interpretation
        const asEl = document.getElementById("anomalyScore");
        const interpBadgeEl = document.getElementById("scoreInterpretationBadge");
        if (asEl && data.anomaly_score !== undefined && data.anomaly_score !== null) {
            const scoreNum = Number(data.anomaly_score);
            const scoreText = scoreNum.toFixed(4);
            if (asEl.textContent !== scoreText) asEl.textContent = scoreText;
            if (interpBadgeEl) {
                if (scoreNum < 0) {
                    interpBadgeEl.className = "badge danger";
                    interpBadgeEl.textContent = "Anomalous Decision";
                } else {
                    interpBadgeEl.className = "badge normal";
                    interpBadgeEl.textContent = "Normal Baseline";
                }
            }
        }

        // 7. Explainable Root Cause Attribution
        const reasonEl = document.getElementById("anomalyReason");
        if (reasonEl) {
            const reasonVal = data.anomaly_reason || (secVal === "TRUSTED" ? "Device behavior is within the learned normal baseline." : "Anomalous condition detected.");
            if (reasonEl.textContent !== reasonVal) reasonEl.textContent = reasonVal;
            reasonEl.style.color = secVal === "TRUSTED" ? "#22c55e" : (secVal === "MONITORING" ? "#38bdf8" : "#fca5a5");
        }

        // 8. Recent Observations Timeline
        updateObservationsTimeline(data.recent_observations);
    } catch (error) {
        if (error.name !== "AbortError") {
            logDev("Telemetry fetch error:", error);
            setTelemetryStatus("delayed");
        }
    } finally {
        isTelemetryLoading = false;
    }
}

function setTelemetryStatus(state) {
    const statusText = document.getElementById("telemetryStatusText");
    const pulse = document.querySelector("#telemetryStatusNotice .live-pulse");
    if (!statusText || !pulse) return;

    if (state === "live") {
        if (statusText.textContent !== "Live Telemetry Synchronized") statusText.textContent = "Live Telemetry Synchronized";
        if (pulse.className !== "live-pulse") pulse.className = "live-pulse";
    } else {
        if (statusText.textContent !== "Telemetry update delayed") statusText.textContent = "Telemetry update delayed";
        if (pulse.className !== "live-pulse delayed") pulse.className = "live-pulse delayed";
    }
}

function updateObservationsTimeline(observations) {
    const tbody = document.getElementById("timelineTableBody");
    if (!tbody || !observations || observations.length === 0) return;

    const signature = JSON.stringify(observations);
    if (signature === lastTimelineSignature) return;
    lastTimelineSignature = signature;

    const reversed = [...observations].reverse().slice(0, 5);
    tbody.innerHTML = reversed.map(obs => {
        const isNorm = obs.ml === "NORMAL";
        const badgeClass = isNorm ? "normal" : "danger";
        const scoreStr = obs.score !== undefined ? Number(obs.score).toFixed(4) : "--";
        const prStr = obs.packet_rate !== undefined ? `${Number(obs.packet_rate).toFixed(2)} pkts/s` : "--";
        const fhStr = obs.free_heap !== undefined ? `${obs.free_heap} B` : "--";
        const rssiStr = obs.rssi !== undefined ? `${obs.rssi} dBm` : "--";

        return `
            <tr>
                <td><strong>${obs.time || "--"}</strong></td>
                <td><span class="badge ${badgeClass}">${obs.ml || "NORMAL"}</span></td>
                <td><code>${scoreStr}</code></td>
                <td>${prStr}</td>
                <td>${fhStr}</td>
                <td>${rssiStr}</td>
            </tr>
        `;
    }).join("");
}

async function loadHistory() {
    if (isHistoryLoading) return;
    isHistoryLoading = true;

    historyAbortController = new AbortController();
    const url = `${API_URL}/api/history?limit=100&device_id=${encodeURIComponent(activeDeviceId)}`;

    try {
        const response = await fetch(url, {
            headers: getAuthHeaders(),
            signal: historyAbortController.signal
        });
        if (!response.ok) return;

        const raw = await response.json();
        const events = Array.isArray(raw) ? raw : (raw.events || []);

        const currentSignature = JSON.stringify(events.slice(0, 10).map(e => [e.id, e.timestamp, e.ml_detection, e.anomaly_score, e.threat, e.security_status]));
        if (currentSignature !== lastHistorySignature) {
            lastHistorySignature = currentSignature;
            const tbody = document.getElementById("historyTableBody");
            if (tbody) {
                if (events.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: #94a3b8; padding: 18px;">No telemetry history for ${activeDeviceId}.</td></tr>`;
                } else {
                    tbody.innerHTML = events.slice(0, 25).map(event => {
                        const timeStr = event.timestamp ? event.timestamp.split(".")[0] : "--";
                        const secBadge = (event.security_status === "trusted") ? "normal" : (event.security_status === "monitoring" ? "warn" : "danger");
                        const fwBadge = (event.firmware_status === "valid") ? "normal" : "warn";
                        const mlBadge = (event.ml_detection === "NORMAL") ? "normal" : "danger";
                        const threatBadge = (event.threat === "NONE") ? "normal" : "danger";
                        const eventBadge = (event.event_type === "NORMAL") ? "normal" : (event.event_type === "FIRMWARE_TAMPERED" ? "warn" : "danger");

                        return `
                            <tr>
                                <td>${timeStr}</td>
                                <td><strong>${event.device_id || "--"}</strong></td>
                                <td><span class="badge ${secBadge}">${(event.security_status || "--").toUpperCase()}</span></td>
                                <td><span class="badge ${fwBadge}">${(event.firmware_status || "--").toUpperCase()}</span></td>
                                <td><span class="badge ${mlBadge}">${(event.ml_detection || "--").toUpperCase()}</span></td>
                                <td><span class="badge ${threatBadge}">${(event.threat || "--").toUpperCase()}</span></td>
                                <td>${event.anomaly_score !== null && event.anomaly_score !== undefined ? Number(event.anomaly_score).toFixed(4) : "--"}</td>
                                <td style="font-size: 11px; color: #cbd5e1; max-width: 240px;">${event.anomaly_reason || "--"}</td>
                                <td><span class="badge ${eventBadge}">${(event.event_type || "--").toUpperCase()}</span></td>
                            </tr>
                        `;
                    }).join("");
                }
            }
        }

        updateCharts(events);
    } catch (error) {
        if (error.name !== "AbortError") {
            logDev("History fetch error:", error);
        }
    } finally {
        isHistoryLoading = false;
    }
}

async function loadSummary() {
    try {
        const url = `${API_URL}/api/history/summary?device_id=${encodeURIComponent(activeDeviceId)}`;
        const response = await fetch(url, { headers: getAuthHeaders() });
        if (!response.ok) return;

        const summary = await response.json();
        const elTotal = document.getElementById("sumTotal");
        const elNormal = document.getElementById("sumNormal");
        const elAnomalies = document.getElementById("sumAnomalies");
        const elTampered = document.getElementById("sumTampered");
        const elRogue = document.getElementById("sumRogue");

        if (elTotal && elTotal.textContent !== String(summary.total_events ?? 0)) elTotal.textContent = summary.total_events ?? 0;
        if (elNormal && elNormal.textContent !== String(summary.normal_events ?? 0)) elNormal.textContent = summary.normal_events ?? 0;
        if (elAnomalies && elAnomalies.textContent !== String(summary.anomaly_events ?? 0)) elAnomalies.textContent = summary.anomaly_events ?? 0;
        if (elTampered && elTampered.textContent !== String(summary.firmware_tampered ?? 0)) elTampered.textContent = summary.firmware_tampered ?? 0;
        if (elRogue && elRogue.textContent !== String(summary.rogue_devices ?? 0)) elRogue.textContent = summary.rogue_devices ?? 0;
    } catch (error) {
        logDev("Summary fetch error:", error);
    }
}

async function loadAlerts() {
    if (isAlertsLoading) return;
    isAlertsLoading = true;

    alertsAbortController = new AbortController();
    const url = `${API_URL}/api/alerts?limit=50&device_id=${encodeURIComponent(activeDeviceId)}`;

    try {
        const response = await fetch(url, {
            headers: getAuthHeaders(),
            signal: alertsAbortController.signal
        });
        if (!response.ok) return;

        const alerts = await response.json();
        const alertsSignature = JSON.stringify((alerts || []).slice(0, 10).map(a => [a.id, a.timestamp, a.alert_type, a.status, a.severity]));
        if (alertsSignature !== lastAlertsSignature) {
            lastAlertsSignature = alertsSignature;
            const tbody = document.getElementById("alertsTableBody");
            if (tbody) {
                if (!alerts || alerts.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #94a3b8; padding: 18px;">No security alerts detected for ${activeDeviceId}. System operating normally.</td></tr>`;
                } else {
                    tbody.innerHTML = alerts.map(a => {
                        const timeStr = a.timestamp ? a.timestamp.split(".")[0] : "--";
                        const sev = (a.severity || "LOW").toUpperCase();
                        const sevClass = sev === "CRITICAL" ? "sev-critical" :
                            sev === "HIGH" ? "sev-high" :
                                sev === "MEDIUM" ? "sev-medium" : "sev-low";

                        const scoreStr = a.anomaly_score !== null && a.anomaly_score !== undefined
                            ? Number(a.anomaly_score).toFixed(4)
                            : "--";

                        const reasonText = a.anomaly_reason || a.description || "--";

                        return `
                            <tr>
                                <td><span class="sev-badge ${sevClass}">${sev}</span></td>
                                <td><strong>${a.alert_type || "--"}</strong></td>
                                <td>${a.threat || "--"}</td>
                                <td>${a.device_id || "--"}</td>
                                <td>${scoreStr}</td>
                                <td>${timeStr}</td>
                                <td style="max-width: 260px; font-size: 11px; color: #cbd5e1;">${reasonText}</td>
                                <td><span class="status-active">${a.status || "ACTIVE"}</span></td>
                            </tr>
                        `;
                    }).join("");
                }
            }
        }
    } catch (error) {
        if (error.name !== "AbortError") {
            logDev("Alerts fetch error:", error);
        }
    } finally {
        isAlertsLoading = false;
    }
}

async function loadAlertStats() {
    try {
        const url = `${API_URL}/api/alerts/stats?device_id=${encodeURIComponent(activeDeviceId)}`;
        const response = await fetch(url, { headers: getAuthHeaders() });
        if (!response.ok) return;

        const stats = await response.json();
        const elTotal = document.getElementById("alertSumTotal");
        const elCrit = document.getElementById("alertSumCritical");
        const elHigh = document.getElementById("alertSumHigh");
        const elMed = document.getElementById("alertSumMedium");
        const elLow = document.getElementById("alertSumLow");

        if (elTotal && elTotal.textContent !== String(stats.total_alerts ?? 0)) elTotal.textContent = stats.total_alerts ?? 0;
        if (elCrit && elCrit.textContent !== String(stats.critical_count ?? 0)) elCrit.textContent = stats.critical_count ?? 0;
        if (elHigh && elHigh.textContent !== String(stats.high_count ?? 0)) elHigh.textContent = stats.high_count ?? 0;
        if (elMed && elMed.textContent !== String(stats.medium_count ?? 0)) elMed.textContent = stats.medium_count ?? 0;
        if (elLow && elLow.textContent !== String(stats.low_count ?? 0)) elLow.textContent = stats.low_count ?? 0;
    } catch (error) {
        logDev("Alert stats fetch error:", error);
    }
}

// =========================================================================
// Safe Attack / Anomaly Simulation
// =========================================================================

async function triggerSimulation(type) {
    const box = document.getElementById("simResultBox");
    const badge = document.getElementById("simResultBadge");
    const elTarget = document.getElementById("simResultTarget");
    const elType = document.getElementById("simResultType");
    const elDetection = document.getElementById("simResultDetection");
    const elThreat = document.getElementById("simResultThreat");
    const elScore = document.getElementById("simResultScore");
    const elSecurity = document.getElementById("simResultSecurity");
    const elFirmware = document.getElementById("simResultFirmware");
    const elRisk = document.getElementById("simResultRisk");
    const elReason = document.getElementById("simResultReason");

    const simTargetSelect = document.getElementById("simTargetDevice");
    const targetDevice = (simTargetSelect ? simTargetSelect.value : activeDeviceId) || activeDeviceId;

    if (box) box.style.display = "block";
    if (badge) {
        badge.className = "badge warn";
        badge.textContent = "EVALUATING...";
    }
    if (elTarget) elTarget.textContent = targetDevice;
    if (elType) elType.textContent = type.replace("_", " ").toUpperCase();
    if (elDetection) elDetection.textContent = "Evaluating ML inference...";
    if (elThreat) elThreat.textContent = "Analyzing state machine...";
    if (elScore) elScore.textContent = "...";
    if (elSecurity) elSecurity.textContent = "...";
    if (elFirmware) elFirmware.textContent = "...";
    if (elRisk) elRisk.textContent = "...";
    if (elReason) elReason.textContent = "Attributing root cause...";

    try {
        const response = await fetch(`${API_URL}/api/simulate/${type}?device_id=${encodeURIComponent(targetDevice)}`, {
            method: "POST",
            headers: getAuthHeaders()
        });

        if (!response.ok) {
            throw new Error(`Simulation failed with HTTP status ${response.status}`);
        }

        const data = await response.json();

        const simType = (data.simulation_type || data.type || type).replace("_", " ").toUpperCase();
        const detection = (data.detection || data.ml_detection || "NORMAL").toUpperCase();
        const threat = (data.threat || "NONE").toUpperCase();
        const score = data.anomaly_score !== undefined ? Number(data.anomaly_score).toFixed(4) : "0.0000";
        const security = (data.security_status || "trusted").toUpperCase();
        const firmware = (data.firmware_status || "valid").toUpperCase();
        const riskVal = data.risk_score !== undefined ? `${data.risk_score} (${data.risk_level || "LOW"})` : "0 (LOW)";
        const reason = data.anomaly_reason || "--";

        if (elTarget) elTarget.textContent = data.device_id || targetDevice;
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
            elSecurity.style.color = (security === "TRUSTED") ? "#22c55e" : (security === "MONITORING" ? "#38bdf8" : "#ef4444");
        }
        if (elFirmware) {
            elFirmware.textContent = firmware;
            elFirmware.style.color = (firmware === "VALID") ? "#22c55e" : "#ef4444";
        }
        if (elRisk) {
            elRisk.textContent = riskVal;
            elRisk.style.color = (data.risk_level === "CRITICAL" || data.risk_level === "HIGH") ? "#ef4444" : "#38bdf8";
        }
        if (elReason) {
            elReason.textContent = reason;
            elReason.style.color = (detection === "NORMAL" && security === "TRUSTED") ? "#22c55e" : "#fca5a5";
        }

        if (badge) {
            const isAnomaly = (detection === "ANOMALY") || (threat !== "NONE") || (security === "SUSPICIOUS");
            badge.className = isAnomaly ? "badge danger" : "badge normal";
            badge.textContent = isAnomaly ? (threat !== "NONE" ? threat : "ANOMALY") : "NORMAL";
        }

        // Immediately update telemetry, history, alerts without reloading page
        if (targetDevice !== activeDeviceId) {
            selectDevice(targetDevice);
        } else {
            await loadTelemetry();
            await loadHistory();
            await loadAlerts();
            await loadAlertStats();
            await loadDeviceList();
        }
    } catch (error) {
        console.error("Simulation error:", error);
        if (badge) {
            badge.className = "badge danger";
            badge.textContent = "ERROR";
        }
        if (elDetection) elDetection.textContent = "ERROR";
        if (elThreat) elThreat.textContent = "REQUEST FAILED";
        if (elReason) elReason.textContent = "Failed to communicate with simulation engine.";
    }
}

// =========================================================================
// Centralized Non-Overlapping Polling Manager (Zero Layout Shift / Zero Reload)
// =========================================================================

let pollTicks = 0;

async function pollingCycle() {
    pollTicks++;

    // Real-time telemetry: in-place metric updates every 3s
    await loadTelemetry();

    // Every 6 seconds (every 2 cycles): health, fleet status, history, alerts
    if (pollTicks % 2 === 0) {
        await checkBackendHealth();
        await loadDeviceList();
        await loadHistory();
        await loadAlerts();
        await loadAlertStats();
        await loadSummary();
    }
}

async function startDashboard() {
    if (isPollingActive) return;
    isPollingActive = true;

    ensureCharts();
    await checkBackendHealth();
    await loadDeviceList();
    await loadTelemetry();
    await loadHistory();
    await loadAlerts();
    await loadAlertStats();
    await loadSummary();

    // Stable background interval (3s) with pure in-place DOM updates
    setInterval(pollingCycle, 3000);
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startDashboard);
} else {
    startDashboard();
}