# IoT Cybersecurity Monitoring & Real-Time Defense Center

> **Comprehensive Technical Project Report & System Documentation**  
> *Real-Time Telemetry Ingestion, Cryptographic Firmware Verification, Persistent Physical Reboot Detection, Multi-Layer Machine Learning Anomaly Detection, and Dynamic Threat Posture Management for Constrained IoT Fleets.*

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement & Security Challenges](#2-problem-statement--security-challenges)
3. [System Architecture](#3-system-architecture)
4. [Edge Hardware & Telemetry Ingestion Protocol](#4-edge-hardware--telemetry-ingestion-protocol)
5. [Cryptographic Firmware Integrity Verification Engine](#5-cryptographic-firmware-integrity-verification-engine)
6. [Persistent Physical Reboot Detection Engine](#6-persistent-physical-reboot-detection-engine)
7. [Machine Learning Behavioral Anomaly Detection Pipeline](#7-machine-learning-behavioral-anomaly-detection-pipeline)
8. [Multi-Layer Defensive State Machine & Threat Posture](#8-multi-layer-defensive-state-machine--threat-posture)
9. [Dynamic Risk Scoring & Deduplicated Incident Alerting](#9-dynamic-risk-scoring--deduplicated-incident-alerting)
10. [Safe Attack & Anomaly Simulation Engine](#10-safe-attack--anomaly-simulation-engine)
11. [In-Place Dynamic Dashboard & Frontend Architecture](#11-in-place-dynamic-dashboard--frontend-architecture)
12. [Relational Database Schema & Data Models](#12-relational-database-schema--data-models)
13. [RESTful API Specification](#13-restful-api-specification)
14. [Empirical Verification & Test Results](#14-empirical-verification--test-results)
15. [Installation, Deployment & Operation Guide](#15-installation-deployment--operation-guide)
16. [Directory Structure](#16-directory-structure)
17. [Conclusion & Future Roadmap](#17-conclusion--future-roadmap)

---

## 1. Executive Summary

The **IoT Cybersecurity Monitoring & Real-Time Defense Center** is an enterprise-grade, end-to-end intrusion detection, behavioral anomaly monitoring, and cryptographic integrity platform engineered for microcontrollers such as the **ESP8266** and **ESP32**.

Modern Internet of Things (IoT) ecosystems face severe security vulnerabilities due to memory limitations, unencrypted or weakly authenticated wireless links, and vulnerability to physical tampering. This system resolves these vulnerabilities by operating an intelligent defensive pipeline with **four distinct security layers**:

1. **Hardware Identity Verification**: Distinguishes authorized fleet hardware from unregistered rogue devices.
2. **Cryptographic Firmware Integrity**: Validates binary fingerprints against an immutable registered baseline to block malicious code modifications and supply chain tampering.
3. **Persistent Physical Reboot Detection**: Tracks hardware uptime across backend restarts to detect unauthorized resets, power glitching, or watchdog crashes.
4. **Behavioral Machine Learning (Isolation Forest)**: Analyzes an 8-dimensional operational feature vector in real time to detect volumetric denial-of-service (DoS) bursts, memory leaks, and RF degradation.

The system features an **in-place DOM-mutating web dashboard** that updates live telemetry every 5 seconds without page reflows or scroll jumps, alongside an explainable risk scoring engine (0–100) and an automated 30-second incident deduplication cooldown system.

---

## 2. Problem Statement & Security Challenges

Resource-constrained microcontrollers (e.g., Tensilica Xtensa L106 running at 80/160 MHz with <50 KB available RAM) are ubiquitous in smart infrastructure, industrial telemetry, and sensor networks. However, they present unique attack surfaces:

- **Rogue Device Ingress & Identity Spoofing**: Adversaries can clone MAC addresses or inject rogue nodes into the local subnet to broadcast forged sensor data.
- **Unauthorized Firmware Tampering**: Malicious over-the-air (OTA) updates or direct physical flashing via UART can alter firmware functionality while preserving cosmetic device metadata.
- **Physical Power Glitching & Watchdog Resets**: Attackers may trigger hardware reboots (via power starvation, fault injection, or buffer overflows) to bypass operational lockouts or reset state counters.
- **Volumetric DoS & Flood Attacks**: IoT nodes can be exploited as amplification vectors, flooding local gateways with high-frequency HTTP requests that deplete network bandwidth and device buffers.
- **Heap Memory Exhaustion**: Memory leaks or malicious payloads targeting dynamic allocation can deplete free heap space, precipitating silent watchdog resets.
- **Alert Fatigue & Noisy ML Classifiers**: Standard anomaly detectors often trigger false alarms on single transient network hiccups. Without state-machine confirmation and hysteresis, security operators are overwhelmed with transient false positives.

This project delivers a multi-tiered defense system that addresses each vulnerability without modifying the underlying lightweight hardware firmware.

---

## 3. System Architecture

The following diagram illustrates the complete data flow, from edge microcontroller telemetry collection to real-time security visualization:

```
+-----------------------------------------------------------------------------------+
|                            IoT HARDWARE EDGE LAYER                                |
|                                                                                   |
|   +-----------------------+                         +-----------------------+     |
|   |  ESP8266 NodeMCU #1   |                         |  ESP32 Edge Node #2   |     |
|   |  - Free Heap Tracking |                         |  - Free Heap Tracking |     |
|   |  - Uptime Millis      |                         |  - Uptime Millis      |     |
|   |  - Wi-Fi RSSI Monitor |                         |  - Wi-Fi RSSI Monitor |     |
|   |  - Firmware MD5 Digest|                         |  - Firmware MD5 Digest|     |
|   +-----------+-----------+                         +-----------+-----------+     |
+---------------|-------------------------------------------------|-----------------+
                |                                                 |
                |   HTTP POST /api/device (Every 5 seconds)       |
                +------------------------+------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        FASTAPI BACKEND PROCESSING PIPELINE                        |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | 1. Ingress & Identity Verification                                          |  |
|  |    - Query 'devices' table by MAC / device_id                               |  |
|  |    - Classify Identity: REGISTERED vs. UNREGISTERED (ROGUE)                 |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|  +-------------------------------------v---------------------------------------+  |
|  | 2. Cryptographic Firmware Integrity Engine                                 |  |
|  |    - Verify incoming MD5 against immutable registered baseline             |  |
|  |    - Classify Firmware: VALID vs. FIRMWARE_TAMPERED vs. UNKNOWN             |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|  +-------------------------------------v---------------------------------------+  |
|  | 3. Persistent Discontinuity & Reboot Engine                                |  |
|  |    - Query previous telemetry record from SQLite database                   |  |
|  |    - Check: current_uptime < previous_uptime => uptime_gap = 1              |  |
|  |    - Survives complete backend process restarts                             |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|  +-------------------------------------v---------------------------------------+  |
|  | 4. 8-Dimensional Behavioral Feature Extraction                              |  |
|  |    - [rssi, free_heap, uptime, packet_rate, request_rate,                   |  |
|  |       heap_change, rssi_change, uptime_gap]                                 |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|  +-------------------------------------v---------------------------------------+  |
|  | 5. Machine Learning Inference (Isolation Forest)                             |  |
|  |    - StandardScaler transformation                                          |  |
|  |    - Compute Decision Function Score & Label (NORMAL vs. ANOMALY)           |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|  +-------------------------------------v---------------------------------------+  |
|  | 6. Device State Machine & Threat Posture Synthesis                         |  |
|  |    - Streak Tracking: Anomaly Confirmation (3x) & Recovery (3x)             |  |
|  |    - Transition: TRUSTED -> MONITORING -> SUSPICIOUS -> RECOVERING          |  |
|  |    - Root-Cause Attribution & Risk Score (0-100) Formulation                |  |
|  +-------------------------------------+---------------------------------------+  |
+----------------------------------------|------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                        STORAGE & DATA PERSISTENCE LAYER                           |
|                                                                                   |
|  +-----------------+  +-----------------+  +------------------+  +--------------+ |
|  |   'devices'     |  |   'telemetry'   |  |'detection_history|  |'security_    | |
|  | (Registry Table)|  | (Raw Time-Series|  | (Security Events)|  | alerts'      | |
|  +-----------------+  +-----------------+  +------------------+  +--------------+ |
+----------------------------------------+------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                     REAL-TIME IN-PLACE PRESENTATION LAYER                         |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Dynamic Web Dashboard (HTML5 / Vanilla JS / Chart.js)                       |  |
|  |  - In-Place DOM Value Updating (Zero Page Reload / Zero Layout Reflow)       |  |
|  |  - Multi-Device Fleet Table & Device-Specific Security Detail Inspector      |  |
|  |  - Interactive Simulation Control Center                                    |  |
|  |  - Historical Incident Feed with 30s Deduplication Filters                  |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 4. Edge Hardware & Telemetry Ingestion Protocol

### 4.1 Edge Microcontroller Specification
The system supports ESP8266 and ESP32 microcontrollers. Telemetry collection is integrated directly into the device firmware loop, broadcasting periodic health metrics to the FastAPI ingestion endpoint without impacting the device's operational tasks.

### 4.2 Ingestion Protocol Specification
- **Method**: `POST`
- **Path**: `/api/device`
- **Content-Type**: `application/json`
- **Cadence**: Exactly 5000 ms ($\pm 200\text{ ms}$)

#### Telemetry Payload Schema
```json
{
  "device_id": "ESP8266-01",
  "chip_id": "00733400",
  "mac": "60:01:94:73:34:00",
  "ip": "10.214.179.156",
  "rssi": -28.0,
  "free_heap": 49128,
  "uptime": 542,
  "firmware": "1.0.0",
  "firmware_md5": "3b27ec70c26f9ef3aa13e053336e550c",
  "packet_count": 108,
  "request_count": 108
}
```

#### Field Definitions
| Field | Type | Description |
| :--- | :--- | :--- |
| `device_id` | String | Logical fleet identifier configured on the device. |
| `chip_id` | String | Silicon factory identifier read from hardware registers. |
| `mac` | String | Factory burned-in Wi-Fi MAC address. |
| `ip` | String | Dynamically assigned IPv4 network address. |
| `rssi` | Float | Received Signal Strength Indicator (dBm). |
| `free_heap` | Integer | Dynamic RAM available in the microcontroller heap (bytes). |
| `uptime` | Integer | Microcontroller operating time since last boot (seconds). |
| `firmware` | String | Semantic version string assigned during build compilation. |
| `firmware_md5` | String | 128-bit cryptographic digest calculated over the compiled binary. |
| `packet_count` | Integer | Monotonically increasing counter of Wi-Fi packets transmitted. |
| `request_count` | Integer | Monotonically increasing counter of HTTP transactions processed. |

---

## 5. Cryptographic Firmware Integrity Verification Engine

Firmware tampering detection is decoupled from behavioral machine learning analysis to ensure that firmware modifications are flagged immediately, regardless of whether the device exhibits abnormal behavioral metrics.

### 5.1 Verification Workflow
1. Upon receipt of telemetry, the backend queries the `devices` table using `device_id` and `mac`.
2. If no record exists:
   - Device identity is designated as `UNREGISTERED`.
   - Firmware status is flagged as `UNKNOWN`.
   - Threat is classified as `ROGUE_DEVICE`.
3. If the device exists in the registry:
   - The registered `firmware_md5` baseline is retrieved.
   - The incoming `firmware_md5` is compared against the registered baseline:
     $$\text{Status} = \begin{cases} \text{VALID}, & \text{if } \text{reported\_md5} == \text{expected\_md5} \\ \text{FIRMWARE\_TAMPERED}, & \text{if } \text{reported\_md5} \neq \text{expected\_md5} \end{cases}$$

### 5.2 Registration Baseline Immutability
A critical security requirement is that **telemetry packets cannot overwrite the registered baseline**:
- Telemetry reporting a mismatched MD5 never updates the `devices` table.
- Baselines can only be updated through explicit administrative action via `POST /api/devices/register`.
- This prevents attackers from updating the registered baseline simply by flashing a compromised image that reports an altered hash.

---

## 6. Persistent Physical Reboot Detection Engine

A major vulnerability in naive IoT monitoring tools is maintaining state solely in memory (e.g., Python `defaultdict`). If the backend server restarts while an IoT device is rebooted, the reboot goes undetected because previous state is lost.

### 6.1 Database-Backed Discontinuity Detection
This system queries the SQLite database directly to retrieve the most recent historical record for the device:

```python
# Query the database for the most recent historical record
last_tel = db.query(Telemetry).filter(
    (Telemetry.device_id == device_id) | (Telemetry.mac == mac)
).order_by(Telemetry.id.desc()).first()

if last_tel is not None:
    prev_uptime = last_tel.uptime
    time_difference = current_uptime - prev_uptime
    if time_difference < 0:
        # Hardware reset detected: uptime has dropped below previous value
        uptime_gap = 1
```

### 6.2 Forensic Evidence Preservation
When `uptime_gap == 1`:
- An `UNEXPECTED_REBOOT` event is created.
- Forensic parameters are recorded in the database:
  - `previous_uptime`: Last confirmed operational uptime before the discontinuity.
  - `current_uptime`: Post-boot uptime reported by the device.
  - `timestamp`: Time the reset was detected.
- The state survives complete restarts of the FastAPI server, as verified in our automated test suite.

---

## 7. Machine Learning Behavioral Anomaly Detection Pipeline

Behavioral anomalies (e.g., volumetric floods, memory leakage, RF degradation) are evaluated using an **Isolation Forest** classifier.

### 7.1 Mathematical Foundation of Isolation Forest
Isolation Forest identifies anomalies by recursively partitioning feature space using axis-aligned cuts. Because anomalous data points require fewer random splits to isolate than normal clustering points, their path lengths in the ensemble trees are measurably shorter:

$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

Where:
- $h(x)$ is the path length of observation $x$ in an isolation tree.
- $E(h(x))$ is the expected path length across the ensemble of $t$ trees.
- $c(n) = 2\ln(n - 1) + 0.5772156649\ (\text{Euler's constant}) - \frac{2(n - 1)}{n}$ is the average path length of unsuccessful searches in a Binary Search Tree (BST) over $n$ samples.
- An anomaly score $s(x, n) \to 1.0$ indicates an anomaly, while $s(x, n) < 0.5$ indicates normal behavior.

### 7.2 8-Dimensional Feature Vector
Every incoming telemetry packet is mapped into an 8-dimensional operational feature vector:

$$\vec{X} = \begin{bmatrix} \text{rssi} \\ \text{free\_heap} \\ \text{uptime} \\ \text{packet\_rate} \\ \text{request\_rate} \\ \text{heap\_change} \\ \text{rssi\_change} \\ \text{uptime\_gap} \end{bmatrix} = \begin{bmatrix} \text{Current Wi-Fi Signal Strength (dBm)} \\ \text{Instantaneous Free Heap Space (bytes)} \\ \text{Elapsed Operating Time (seconds)} \\ \Delta\text{packets} / \Delta\text{uptime (packets/second)} \\ \Delta\text{requests} / \Delta\text{uptime (requests/second)} \\ \text{Heap Difference from Previous Interval (bytes)} \\ \text{RSSI Shift from Previous Interval (dBm)} \\ \text{Reboot Discontinuity Flag (0 or 1)} \end{bmatrix}$$

### 7.3 Model Hyperparameters & Offline Training
The model is trained on baseline telemetry collected from physical ESP8266 hardware during standard operation (`ml/normal_behavior.csv`).

```python
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = IsolationForest(
    n_estimators=200,      # 200 randomized isolation decision trees
    contamination=0.05,    # 5% expected baseline anomaly contamination
    random_state=42        # Deterministic seed for reproducible evaluation
)
model.fit(X_scaled)
```

The resulting model (`anomaly_model.pkl`) and scaler (`scaler.pkl`) are serialized using `joblib` and loaded during backend startup.

---

## 8. Multi-Layer Defensive State Machine & Threat Posture

To prevent alert fatigue and eliminate UI flickering from transient network fluctuations, the raw ML predictions are processed through a **State Machine with Hysteresis**.

```
                         [ Normal Baseline ]
                                  │
                                  ▼
                          +---------------+
                          |    TRUSTED    |<──────────────────────────+
                          +---------------+                           │
                            │           ▲                             │
             1 Anomaly Obs. │           │ 1 Normal Obs.               │
                            ▼           │                             │
                        +-------------------+                         │
                        |    MONITORING     |                         │
                        +-------------------+                         │
                            │           ▲                             │
             3 Consecutive  │           │ Anomaly Interrupts          │ 3 Consecutive
             Anomalies      │           │ Recovery                    │ Normal Samples
                            ▼           │                             │ Verified
                        +-------------------+                         │
                        |    SUSPICIOUS     |                         │
                        +-------------------+                         │
                            │                                         │
             1 Normal Obs.  │                                         │
                            ▼                                         │
                        +-------------------+                         │
                        |    RECOVERING     |─────────────────────────+
                        +-------------------+
                          (Recovery 1/3, 2/3)
```

### 8.1 State Definitions
- **TRUSTED**: Device is operating within standard baseline distributions. Single isolated anomalies do not compromise this status.
- **MONITORING**: An isolated anomaly has been detected ($1/3$ or $2/3$). The system observes the device closely without triggering high-priority alerts. If subsequent packets return to normal, the state resets cleanly to `TRUSTED`.
- **SUSPICIOUS**: Confirmed persistent anomaly ($3/3$ consecutive anomalous observations). High-priority security alerts are generated.
- **RECOVERING**: The device has begun returning to normal operating metrics following a `SUSPICIOUS` incident. Full restoration to `TRUSTED` requires 3 consecutive normal telemetry intervals ($M=3$).
- **ROGUE**: Hardware identity is unknown to the registry. This state overrides behavioral metrics.

### 8.2 Root-Cause Attribution Engine
When an anomaly occurs, the system attributes the root cause using heuristic feature analysis:
- **Traffic Burst / Flooding**: $\text{packet\_rate} \ge 2.0\text{ pkts/sec} \lor \text{request\_rate} \ge 2.0\text{ reqs/sec}$.
- **Heap Memory Exhaustion**: $\text{heap\_change} \le -2000\text{ bytes} \lor \text{free\_heap} < 35,000\text{ bytes}$.
- **RF Signal Anomaly**: $|\text{rssi\_change}| \ge 25.0\text{ dBm}$.
- **Unexpected Reboot**: $\text{uptime\_gap} == 1$.
- **Compound Multi-Vector**: Multiple anomalous dimensions occurring concurrently.

---

## 9. Dynamic Risk Scoring & Deduplicated Incident Alerting

### 9.1 Mathematical Risk Score Formulation
The system computes an explainable composite risk score ($S \in [0, 100]$):

$$S = \min\left(100, \sum w_i \cdot I_i\right)$$

#### Penalty Weights ($w_i$)
| Contributing Factor | Weight | Condition |
| :--- | :--- | :--- |
| **Rogue / Unregistered Hardware** | $+40$ | Device MAC / ID missing from registry |
| **Cryptographic Firmware Mismatch** | $+40$ | Reported MD5 does not match registered baseline |
| **Persistent Behavioral Anomaly** | $+30$ | State machine in `SUSPICIOUS` state |
| **Isolated Anomaly Monitoring** | $+15$ | State machine in `MONITORING` state |
| **Recovery Phase** | $+10$ | State machine in `RECOVERING` state |
| **High Statistical Deviation** | $+10$ | ML decision function score $< -0.10$ |
| **Severe Heap Depletion** | $+15$ | Free heap $< 35\text{ KB}$ or $\Delta\text{heap} \le -20\text{ KB}$ |
| **Traffic Rate Surge** | $+15$ | Packet or request rate $\ge 50.0\text{ units/sec}$ |
| **RF Signal Instability** | $+10$ | Absolute $|\Delta\text{RSSI}| \ge 30.0\text{ dBm}$ |
| **Hardware Reboot Discontinuity** | $+10$ | `uptime_gap == 1` |

#### Risk Stratification
- **0–24**: `LOW` (Normal operations)
- **25–49**: `MEDIUM` (Isolated anomaly or minor parameter shift)
- **50–74**: `HIGH` (Persistent behavioral anomaly or multiple flags)
- **75–100**: `CRITICAL` (Firmware tampering or rogue device detected)

### 9.2 Incident Deduplication & Alert Cooldown
To prevent database bloat and alert fatigue, the alerting engine applies a **30-second cooldown per alert type**:

$$\text{Trigger Alert} \iff (t_{\text{current}} - t_{\text{last\_alert}}[\text{device\_id}, \text{alert\_type}]) \ge 30\text{ seconds}$$

Simulated attacks bypass this cooldown to ensure immediate testing feedback.

---

## 10. Safe Attack & Anomaly Simulation Engine

The backend provides a built-in simulation suite via `POST /api/simulate/{simulation_type}` to safely validate detection pipelines without risking hardware damage.

| Simulation Type | Injected Vectors | Expected System Response |
| :--- | :--- | :--- |
| `traffic_spike` | $\text{packet\_rate} = 120\text{ pkts/s}$, $\text{req\_rate} = 120\text{ reqs/s}$, $\Delta\text{heap} = -3500$ | Escalation to `MONITORING`/`SUSPICIOUS`, `TRAFFIC_BURST` alert, Risk Score: 60–75 |
| `memory_stress` | $\text{free\_heap} = 7200\text{ bytes}$, $\Delta\text{heap} = -42300\text{ bytes}$ | `MEMORY_EXHAUSTION` alert, critical heap warning, Risk Score: 60–75 |
| `signal_anomaly` | $\text{rssi} = -88.0\text{ dBm}$, $\Delta\text{rssi} = -61.0\text{ dBm}$ | `SIGNAL_ANOMALY` alert, RF shift warning, Risk Score: 40–55 |
| `reboot_anomaly` | $\text{uptime} = 2\text{ s}$, $\text{uptime\_gap} = 1$, $\Delta\text{heap} = -8000$ | `UNEXPECTED_REBOOT` alert, previous uptime captured, Risk Score: 40–50 |
| `combined_anomaly` | High traffic, low heap, signal degradation, reboot flag | Multi-vector anomaly classification, Risk Score: 85–100 |
| `firmware_tamper` | $\text{firmware\_md5} = \text{"tampered\_bad\_md5\_hash\_9999"}$ | Immediate `FIRMWARE_TAMPERED` status, baseline preserved, Risk Score: 80–100 |

---

## 11. In-Place Dynamic Dashboard & Frontend Architecture

### 11.1 Zero-Reflow Real-Time Updates
A common issue in early dashboard iterations was visual shaking, scroll resets, and input focus loss during high-frequency polling.

The frontend (`dashboard/index.html`) solves this by utilizing **surgical DOM mutation**:
- **Targeted Element Updating**: Elements are addressed directly by ID (`document.getElementById(...)`), updating only `.textContent` and `.className`.
- **Preserved Scroll & Form Focus**: No `innerHTML` replacements on parent containers occur during polling cycles.
- **Stable Multi-Device Selection**: Selected device context persists seamlessly across background telemetry updates.

### 11.2 Analytical Chart.js Visualizations
The dashboard renders five live analytical charts:
1. **RF Signal Quality**: Rolling time-series of Wi-Fi RSSI (dBm).
2. **Network Activity**: Real-time packet and request transmission rates.
3. **Dynamic Memory**: Free heap allocation history (bytes).
4. **Machine Learning Decision Margin**: Isolation Forest decision function values relative to the zero-boundary threshold.
5. **Operational Posture**: Categorical security posture trends over time.

---

## 12. Relational Database Schema & Data Models

The persistence layer uses SQLite with SQLAlchemy ORM.

### Entity Relationship Diagram
```
+------------------------------------+       +------------------------------------+
|             devices                |       |             telemetry              |
+------------------------------------+       +------------------------------------+
| id (PK)                 INTEGER    |       | id (PK)                 INTEGER    |
| device_id (UQ, IDX)     VARCHAR    |<--+   | device_id               VARCHAR    |
| mac (UQ, IDX)           VARCHAR    |   |   | chip_id                 VARCHAR    |
| ip                      VARCHAR    |   |   | mac                     VARCHAR    |
| firmware                VARCHAR    |   |   | ip                      VARCHAR    |
| firmware_md5            VARCHAR    |   |   | rssi                    FLOAT      |
| status                  VARCHAR    |   |   | free_heap               INTEGER    |
| registered_at           DATETIME   |   |   | uptime                  INTEGER    |
+------------------------------------+   |   | firmware                VARCHAR    |
                                         |   | firmware_md5            VARCHAR    |
+------------------------------------+   |   | packet_count            INTEGER    |
|        detection_history           |   |   | request_count           INTEGER    |
+------------------------------------+   |   | security_status         VARCHAR    |
| id (PK)                 INTEGER    |   |   | firmware_status         VARCHAR    |
| device_id               VARCHAR    |---+   | threat                  VARCHAR    |
| mac                     VARCHAR    |   |   | ml_detection            VARCHAR    |
| timestamp               DATETIME   |   |   | anomaly_score           FLOAT      |
| security_status         VARCHAR    |   |   | anomaly_reason          VARCHAR    |
| firmware_status         VARCHAR    |   |   | packet_rate             FLOAT      |
| ml_detection            VARCHAR    |   |   | request_rate            FLOAT      |
| threat                  VARCHAR    |   |   | heap_change             INTEGER    |
| anomaly_score           FLOAT      |   |   | rssi_change             FLOAT      |
| anomaly_reason          VARCHAR    |   |   | uptime_gap              INTEGER    |
| packet_rate             FLOAT      |   |   | timestamp               DATETIME   |
| free_heap               INTEGER    |   |   +------------------------------------+
| uptime_gap              INTEGER    |   |
| event_type              VARCHAR    |   |   +------------------------------------+
+------------------------------------+   |   |          security_alerts           |
                                         |   +------------------------------------+
+------------------------------------+   |   | id (PK)                 INTEGER    |
|               users                |   |   | device_id (IDX)         VARCHAR    |
+------------------------------------+   +-->| timestamp               DATETIME   |
| id (PK)                 INTEGER    |       | alert_type              VARCHAR    |
| name                    VARCHAR    |       | threat                  VARCHAR    |
| email (UQ, IDX)         VARCHAR    |       | severity                VARCHAR    |
| password_hash           VARCHAR    |       | anomaly_score           FLOAT      |
| role                    VARCHAR    |       | anomaly_reason          VARCHAR    |
| created_at              DATETIME   |       | description             VARCHAR    |
| last_login              DATETIME   |       | status                  VARCHAR    |
+------------------------------------+       +------------------------------------+
```

---

## 13. RESTful API Specification

### Core Endpoints

#### 1. Ingest Device Telemetry
- **Endpoint**: `POST /api/device`
- **Description**: Main ingress for real-time telemetry from edge devices.
- **Request Body**: Complete JSON telemetry payload (see Section 4.2).
- **Response**: Evaluation results including identity status, firmware integrity, state machine posture, risk score, and behavioral features.

#### 2. Fleet Overview
- **Endpoint**: `GET /api/devices`
- **Description**: Returns a summary list of all known devices with their current operational and security status.

#### 3. Real-Time Device Telemetry
- **Endpoint**: `GET /api/devices/latest?device_id={id}`
- **Description**: Retrieves the most recent telemetry packet, state machine evidence, and rolling observations for a target device.

#### 4. Register or Update Device
- **Endpoint**: `POST /api/devices/register`
- **Description**: Registers a new authorized hardware unit or updates the expected firmware MD5 baseline.
- **Request Body**:
  ```json
  {
    "device_id": "ESP8266-01",
    "mac": "60:01:94:73:34:00",
    "ip": "10.214.179.156",
    "firmware": "1.0.0",
    "expected_firmware_md5": "3b27ec70c26f9ef3aa13e053336e550c"
  }
  ```

#### 5. Detection History
- **Endpoint**: `GET /api/history?limit=100&device_id={id}`
- **Description**: Returns chronological telemetry logs and classification events for auditing.

#### 6. Incident Alerts
- **Endpoint**: `GET /api/alerts?limit=50&severity={level}&device_id={id}`
- **Description**: Retrieves deduplicated security incident notifications.

#### 7. Attack Simulation
- **Endpoint**: `POST /api/simulate/{simulation_type}?device_id={id}`
- **Description**: Triggers a simulated security attack or anomaly scenario.

---

## 14. Empirical Verification & Test Results

The detection pipeline is validated through automated test suites in the `scratch/` directory.

### 14.1 Test Suite 1: State Machine & ML Pipeline (`test_pipeline.py`)
```bash
python scratch/test_pipeline.py
```
#### Results
- **Test 1 (Normal Baseline Stability)**: 3 consecutive normal telemetry packets maintained `TRUSTED` state with an anomaly streak of 0. **PASSED**.
- **Test 2 (Isolated Anomaly Smoothing)**: An anomalous packet ($120\text{ pkts/sec}$, heap drop) transitioned state to `MONITORING`, preventing premature escalation. **PASSED**.
- **Test 3 (Persistent Escalation Hysteresis)**: 2 additional anomalous packets reached the confirmation threshold ($3/3$), successfully escalating state to `SUSPICIOUS`. **PASSED**.
- **Test 4 (Recovery Verification)**: A normal packet received during `SUSPICIOUS` state moved the device to `RECOVERING` ($1/3$) without immediately reverting to `TRUSTED`. **PASSED**.
- **Test 5 (Full Recovery Threshold)**: 2 subsequent normal packets completed the recovery threshold ($3/3$), restoring status to `TRUSTED`. **PASSED**.
- **Test 6 (Multi-Device Isolation)**: An anomaly triggered on `ESP8266-02` did not affect the isolated state machine of `ESP8266-01`. **PASSED**.
- **Test 7 (Telemetry Endpoint State Validation)**: Validated presence of all multi-layer security metadata in latest telemetry payloads. **PASSED**.

### 14.2 Test Suite 2: Reboot & Firmware Integrity (`test_reboot_and_firmware.py`)
```bash
python scratch/test_reboot_and_firmware.py
```
#### Results
- **Test C (Normal Telemetry)**: Sequential uptime increments produced `uptime_gap = 0`, `firmware_status = VALID`, and `threat = NONE`. **PASSED**.
- **Test A (Runtime Physical Reboot)**: An uptime drop ($100\text{ s} \to 3\text{ s}$) triggered `uptime_gap = 1` and captured previous/current uptime evidence. **PASSED**.
- **Test B (Reboot Detection Across Process Restarts)**: With in-memory RAM caches wiped to simulate a complete FastAPI shutdown, an uptime drop ($250\text{ s} \to 4\text{ s}$) was successfully detected by querying historical database records. **PASSED**.
- **Test D (Firmware Tampering & Baseline Immutability)**: Telemetry with an invalid firmware hash was flagged as `FIRMWARE_TAMPERED`, and the registered baseline in the database remained uncorrupted. **PASSED**.
- **Test E (Valid Firmware Matching)**: Telemetry matching the registered hash verified cleanly as `VALID`. **PASSED**.

---

## 15. Installation, Deployment & Operation Guide

### 15.1 Prerequisites
- Python 3.10+
- Modern Web Browser (Chrome, Firefox, Edge, Safari)
- *Optional Hardware*: ESP8266 NodeMCU or ESP32 board

### 15.2 Step-by-Step Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/devarajselvaraj8-boop/IOTSECURITY.git
   cd IOTSECURITY
   ```

2. **Create and Activate a Virtual Environment**:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux / macOS:
   source .venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Start the FastAPI Backend**:
   ```bash
   python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
   ```
   *The SQLite database (`iot_security.db`) and baseline registered device (`ESP8266-01`) will initialize automatically on startup.*

5. **Launch the Real-Time Dashboard**:
   Serve the `dashboard/` directory using any static web server:
   ```bash
   python -m http.server 5500 -d dashboard
   ```
   Open `http://127.0.0.1:5500` in your web browser.

6. **Run System Verification Tests**:
   ```bash
   python scratch/test_pipeline.py
   python scratch/test_reboot_and_firmware.py
   ```

---

## 16. Directory Structure

```
iot-security/
│
├── backend/
│   ├── main.py                  # Core FastAPI backend, ML inference, state machine & API
│   └── test_backend.py          # Backend test routines
│
├── dashboard/
│   └── index.html               # Real-time web dashboard (Vanilla JS & Chart.js)
│
├── ml/
│   ├── anomaly_model.pkl        # Serialized Isolation Forest ensemble model
│   ├── scaler.pkl               # Serialized StandardScaler transformation model
│   ├── normal_behavior.csv      # Baseline empirical ESP8266 telemetry dataset
│   └── train_model.py           # ML training and model serialization script
│
├── scratch/
│   ├── test_pipeline.py         # Multi-layer state machine validation suite
│   └── test_reboot_and_firmware.py # Reboot detection and firmware integrity test suite
│
├── .gitignore                   # Git repository exclusion definitions
├── requirements.txt             # Python project dependencies
└── README.md                    # System documentation and project report
```

---

## 17. Conclusion & Future Roadmap

The **IoT Cybersecurity Monitoring & Real-Time Defense Center** demonstrates a robust architecture for securing constrained edge IoT fleets. By decoupling device identity, cryptographic firmware validation, and machine-learning behavioral analytics into discrete defensive layers, the system delivers high-confidence threat detection while maintaining low operational overhead.

### Key Accomplishments
- Implemented an **8-dimensional Isolation Forest** pipeline that detects volumetric attacks, memory exhaustion, and RF degradation in real time.
- Implemented **database-backed physical reboot tracking** that reliably detects hardware restarts across server outages.
- Established **immutable firmware baselines** to detect unauthorized code modifications.
- Reduced false alarms through a **state machine with hysteresis** ($N=3$ confirmation, $M=3$ recovery).
- Developed a **zero-reflow real-time dashboard** providing continuous visual telemetry updates without disrupting user workflows.

### Future Roadmap
- **Hardware Cryptographic Co-Processors**: Integrate ATECC608A secure elements on edge nodes for hardware-level ECDSA signatures on every telemetry packet.
- **Mutual TLS (mTLS)**: Implement client-certificate authentication between ESP32 microcontrollers and the FastAPI gateway.
- **Dynamic Policy Enforcement**: Deploy automated quarantine mechanisms that isolate compromised devices via SDN router firewall rules or managed PoE port shutdowns.
