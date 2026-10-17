# IoT Cybersecurity Monitoring & Real-Time Defense Center

A real-time behavioral cybersecurity monitoring and threat detection system for IoT fleets (ESP8266 / ESP32).

## Architecture & Detection Pipeline

```
IoT Hardware (ESP8266 / ESP32)
       │
       ▼ (Telemetry via HTTP POST /api/device)
FastAPI Backend
       │
       ├──► SQLite Database (Persistent Telemetry & Detection History)
       │
       ├──► Cryptographic Firmware Verification (MD5 Fingerprinting)
       │
       ├──► Persistent Unexpected Reboot Detection (Across Server Restarts)
       │
       ├──► Behavioral Feature Extraction (8 Dynamic Metrics)
       │
       ├──► Machine Learning Inference (Isolation Forest Anomaly Detection)
       │
       ├──► Multi-Layer State Machine (Anomaly Persistence & Recovery Thresholds)
       │
       ▼
Real-Time Dynamic Security Dashboard (In-Place Updates, Zero Reflow/Reload)
```

## Key Features

1. **Multi-Device Fleet Management**:
   - Authorized Device Registry (Device ID, MAC address, IP, expected firmware MD5).
   - Rogue/Unregistered Device Detection.
   - Individual device telemetry, security posture, and risk scores.

2. **Cryptographic Firmware Integrity Verification**:
   - Compares incoming reported firmware MD5 hash against the authorized registered baseline.
   - Separate security layer: firmware tampering is detected independently from behavioral anomalies.

3. **Persistent Physical Reboot Detection**:
   - Queries previous telemetry from the database to detect uptime counter resets (`uptime_gap = 1`).
   - Maintains reboot detection and evidence even across FastAPI server restarts.

4. **Explainable ML Anomaly Detection (Isolation Forest)**:
   - Uses 8 dynamic behavioral features: `rssi`, `free_heap`, `uptime`, `packet_rate`, `request_rate`, `heap_change`, `rssi_change`, `uptime_gap`.
   - Distinguishes isolated observations from persistent anomalies using a state machine (3 consecutive confirmations required for escalation, 3 consecutive normals for recovery).
   - Automatic root-cause attribution (traffic bursts, memory exhaustion, RF signal tampering, unexpected reboot).

5. **Real-Time Security Dashboard**:
   - Pure in-place DOM updates: no page refreshes, layout shifts, or focus resets.
   - Live Chart.js analytics for RSSI, packet rate, request rate, heap memory, decision scores, and status history.
   - Security incidents and deduplicated alert feeds.

6. **Safe Attack / Anomaly Simulation Mode**:
   - Built-in simulation engine for traffic spikes, memory stress, RF signal anomalies, unexpected reboot, combined anomalies, and firmware tampering.

## Getting Started

### 1. Installation

Clone the repository and install dependencies:
```bash
git clone https://github.com/devarajselvaraj8-boop/IOTSECURITY.git
cd IOTSECURITY
pip install -r requirements.txt
```

### 2. Start the Backend

Run the FastAPI server:
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

The SQLite database (`iot_security.db`), tables, and default registered device (`ESP8266-01`) will be automatically initialized.

### 3. Open the Dashboard

Open `dashboard/index.html` in your web browser (or serve it with VS Code Live Server / Python HTTP server):
```bash
python -m http.server 5500 -d dashboard
```
Access the dashboard at `http://127.0.0.1:5500`.

### 4. Running Verification Tests

Run the test suite:
```bash
python scratch/test_reboot_and_firmware.py
python scratch/test_pipeline.py
```
