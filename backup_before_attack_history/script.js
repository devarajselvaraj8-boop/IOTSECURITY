const API_URL = "http://10.214.179.107:8000";

async function loadTelemetry() {

    try {

        const response = await fetch(
            `${API_URL}/api/devices/latest`
        );

        if (!response.ok) {
            throw new Error("Backend unavailable");
        }

        const data = await response.json();

        if (data.status === "no_data") {
            return;
        }

        // Connection

        document.getElementById("connectionDot").style.background =
            "#22c55e";

        document.getElementById("connectionText").textContent =
            "Backend Online";


        // Device

        document.getElementById("deviceId").textContent =
            data.device_id ?? "--";

        document.getElementById("mac").textContent =
            data.mac ?? "--";

        document.getElementById("ip").textContent =
            data.ip ?? "--";

        document.getElementById("firmware").textContent =
            data.firmware ?? "--";


        // Telemetry

        document.getElementById("rssi").textContent =
            data.rssi ?? "--";

        document.getElementById("heap").textContent =
            data.free_heap ?? "--";

        document.getElementById("uptime").textContent =
            data.uptime ?? "--";

        document.getElementById("packets").textContent =
            data.packet_count ?? "--";

        document.getElementById("requests").textContent =
            data.request_count ?? "--";


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


        // Firmware

        document.getElementById("firmwareMd5").textContent =
            data.firmware_md5 ?? "--";

        document.getElementById("timestamp").textContent =
            data.timestamp ?? "--";


        document.getElementById("packetRate").textContent =
            (data.packet_rate ?? "--").toFixed ? Number(data.packet_rate ?? 0).toFixed(2) : "--";

        document.getElementById("requestRate").textContent =
            (data.request_rate ?? "--").toFixed ? Number(data.request_rate ?? 0).toFixed(2) : "--";

        document.getElementById("heapChange").textContent =
            data.heap_change ?? "--";

        document.getElementById("rssiChange").textContent =
            data.rssi_change ?? "--";

        document.getElementById("reboot").textContent =
            data.uptime_gap === 1 ? "YES" : (data.uptime_gap === 0 ? "NO" : "--");

        document.getElementById("anomalyScore").textContent =
            (data.anomaly_score ?? "--").toFixed ? Number(data.anomaly_score ?? 0).toFixed(3) : "--";

        document.getElementById("lastRefresh").textContent =
            new Date().toLocaleTimeString();

    }

    catch (error) {

        console.error(error);

        document.getElementById("connectionDot").style.background =
            "#ef4444";

        document.getElementById("connectionText").textContent =
            "Backend Offline";
    }
}


// Refresh every 2 seconds

loadTelemetry();

setInterval(loadTelemetry, 2000);