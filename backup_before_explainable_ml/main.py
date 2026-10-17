from fastapi import FastAPI, HTTPException, Query
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from collections import defaultdict
from fastapi.middleware.cors import CORSMiddleware
import os
import joblib
import numpy as np
import pandas as pd


# -------------------------
# FastAPI
# -------------------------

app = FastAPI(title="IoT Security Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------
# Database
# -------------------------

DATABASE_URL = "sqlite:///./iot_security.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

# ==========================================
# Behavioral Tracking
# ==========================================

previous_data = defaultdict(dict)


def calculate_behavior(data, db=None):

    device_id = data.get("device_id")

    current_rssi = data.get("rssi", 0)
    current_heap = data.get("free_heap", 0)
    current_uptime = data.get("uptime", 0)
    current_packets = data.get("packet_count", 0)
    current_requests = data.get("request_count", 0)

    previous = previous_data.get(device_id)

    # Recover previous state from database if in-memory history is empty (e.g. after restart)
    if not previous and db is not None:
        try:
            last_tel = db.query(Telemetry).filter(
                Telemetry.device_id == device_id
            ).order_by(Telemetry.id.desc()).first()
            if last_tel and last_tel.uptime is not None:
                previous = {
                    "rssi": last_tel.rssi,
                    "free_heap": last_tel.free_heap,
                    "uptime": last_tel.uptime,
                    "packet_count": last_tel.packet_count,
                    "request_count": last_tel.request_count
                }
        except Exception:
            pass

    features = {
        "rssi": current_rssi,
        "free_heap": current_heap,
        "uptime": current_uptime,
        "packet_rate": 0.2,
        "request_rate": 0.2,
        "heap_change": 0,
        "rssi_change": 0,
        "uptime_gap": 0
    }

    if previous:

        time_difference = current_uptime - previous["uptime"]

        if time_difference > 0:

            features["packet_rate"] = (
                current_packets - previous["packet_count"]
            ) / time_difference

            features["request_rate"] = (
                current_requests - previous["request_count"]
            ) / time_difference

        features["heap_change"] = (
            current_heap - previous["free_heap"]
        )

        features["rssi_change"] = (
            current_rssi - previous["rssi"]
        )

        # Detect unexpected reboot
        if current_uptime < previous["uptime"]:
            features["uptime_gap"] = 1

    # Store current state
    previous_data[device_id] = {
        "rssi": current_rssi,
        "free_heap": current_heap,
        "uptime": current_uptime,
        "packet_count": current_packets,
        "request_count": current_requests
    }

    return features


def predict_anomaly(features):

    values = pd.DataFrame([[
        features["rssi"],
        features["free_heap"],
        features["uptime"],
        features["packet_rate"],
        features["request_rate"],
        features["heap_change"],
        features["rssi_change"],
        features["uptime_gap"]
    ]], columns=[
        "rssi",
        "free_heap",
        "uptime",
        "packet_rate",
        "request_rate",
        "heap_change",
        "rssi_change",
        "uptime_gap"
    ])

    values_scaled = scaler.transform(values)

    prediction = model.predict(values_scaled)[0]
    score = model.decision_function(values_scaled)[0]

    if prediction == -1:
        return "ANOMALY", float(score)

    return "NORMAL", float(score)


# ==========================================
# ML MODEL
# ==========================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODEL_PATH = os.path.join(
    BASE_DIR, "ml", "anomaly_model.pkl"
)

SCALER_PATH = os.path.join(
    BASE_DIR, "ml", "scaler.pkl"
)

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

print("ML model loaded successfully!")


# -------------------------
# Telemetry Table
# -------------------------

class Telemetry(Base):

    __tablename__ = "telemetry"

    id = Column(Integer, primary_key=True, index=True)

    device_id = Column(String)
    chip_id = Column(String)
    mac = Column(String)
    ip = Column(String)

    rssi = Column(Float)
    free_heap = Column(Integer)
    uptime = Column(Integer)

    firmware = Column(String)
    firmware_md5 = Column(String)
    
    packet_count = Column(Integer)
    request_count = Column(Integer)
    
    security_status = Column(String)
    firmware_status = Column(String)
    threat = Column(String)
    ml_detection = Column(String)
    anomaly_score = Column(Float)
    
    packet_rate = Column(Float)
    request_rate = Column(Float)
    heap_change = Column(Integer)
    rssi_change = Column(Float)
    uptime_gap = Column(Integer)

    timestamp = Column(DateTime)

class Device(Base):

    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)

    device_id = Column(String, unique=True, index=True)
    mac = Column(String, unique=True, index=True)

    ip = Column(String)

    firmware = Column(String)
    firmware_md5 = Column(String)

    status = Column(String, default="trusted")

    registered_at = Column(DateTime)


class DetectionHistory(Base):

    __tablename__ = "detection_history"

    id = Column(Integer, primary_key=True, index=True)

    device_id = Column(String)
    mac = Column(String)
    timestamp = Column(DateTime)

    security_status = Column(String)
    firmware_status = Column(String)
    ml_detection = Column(String)
    threat = Column(String)

    anomaly_score = Column(Float)

    rssi = Column(Float)
    free_heap = Column(Integer)
    uptime = Column(Integer)

    packet_rate = Column(Float)
    request_rate = Column(Float)
    heap_change = Column(Integer)
    rssi_change = Column(Float)
    uptime_gap = Column(Integer)

    event_type = Column(String)


class SecurityAlert(Base):

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.now)

    alert_type = Column(String)       # FIRMWARE_TAMPERED, ROGUE_DEVICE, BEHAVIOR_ANOMALY, etc.
    threat = Column(String)           # FIRMWARE_TAMPERED, ROGUE_DEVICE, BEHAVIOR_ANOMALY, NONE
    severity = Column(String)         # CRITICAL, HIGH, MEDIUM, LOW
    anomaly_score = Column(Float)
    security_status = Column(String)  # suspicious, trusted
    firmware_status = Column(String)  # tampered, valid, unknown
    description = Column(String)
    status = Column(String, default="ACTIVE")  # ACTIVE, ACKNOWLEDGED, RESOLVED


# Create database/table and migrate older schemas if needed
Base.metadata.create_all(bind=engine)


def ensure_detection_history_table():
    inspector = inspect(engine)
    if not inspector.has_table("detection_history"):
        Base.metadata.create_all(bind=engine)


ensure_detection_history_table()


def ensure_security_alerts_table():
    inspector = inspect(engine)
    if not inspector.has_table("security_alerts"):
        Base.metadata.create_all(bind=engine)


ensure_security_alerts_table()


# Alert Deduplication Tracking: (device_id, alert_type) -> datetime of last alert
alert_cooldowns = {}
ALERT_COOLDOWN_SECONDS = 30


def should_create_alert(device_id: str, alert_type: str, now: datetime, force: bool = False) -> bool:
    if force:
        alert_cooldowns[(device_id, alert_type)] = now
        return True

    last_time = alert_cooldowns.get((device_id, alert_type))
    if last_time is None or (now - last_time).total_seconds() >= ALERT_COOLDOWN_SECONDS:
        alert_cooldowns[(device_id, alert_type)] = now
        return True

    return False


def generate_security_alert(
    db,
    device_id: str,
    threat: str,
    ml_status: str,
    anomaly_score: float,
    security_status: str,
    firmware_status: str,
    behavior: dict,
    now: datetime,
    is_simulation: bool = False
):
    """
    Evaluates telemetry & security state to generate a security alert if anomalous.
    Deduplicates repeated alerts for the same device & anomaly type within 30 seconds.
    """
    try:
        alert_type = None
        severity = None
        description = None

        if threat == "FIRMWARE_TAMPERED" or firmware_status == "tampered":
            alert_type = "FIRMWARE_TAMPERED"
            severity = "CRITICAL"
            description = "Cryptographic mismatch: device firmware hash differs from authorized baseline (potential unauthorized code injection)."
        elif threat == "ROGUE_DEVICE":
            alert_type = "ROGUE_DEVICE"
            severity = "CRITICAL"
            description = "Unregistered device transmitting on network with unverified hardware identity."
        elif behavior and behavior.get("uptime_gap") == 1 and (behavior.get("packet_rate", 0) < 50.0 and abs(behavior.get("rssi_change", 0)) < 40.0):
            alert_type = "UNEXPECTED_REBOOT"
            severity = "MEDIUM"
            description = "Device experienced an unexpected restart / uptime counter reset."
        elif ml_status == "ANOMALY" or threat == "BEHAVIOR_ANOMALY":
            heap_ch = behavior.get("heap_change", 0) if behavior else 0
            pkt_rate = behavior.get("packet_rate", 0) if behavior else 0
            rssi_ch = behavior.get("rssi_change", 0) if behavior else 0

            if pkt_rate >= 50.0 and heap_ch <= -1000:
                alert_type = "TRAFFIC_BURST"
                severity = "HIGH"
                description = f"High-volume traffic spike ({pkt_rate:.1f} pkts/sec) and buffer memory consumption detected."
            elif heap_ch <= -20000:
                alert_type = "MEMORY_EXHAUSTION"
                severity = "HIGH"
                description = f"Severe heap memory drop ({heap_ch} bytes); risk of memory leak or buffer exhaustion."
            elif abs(rssi_ch) >= 40.0:
                alert_type = "SIGNAL_ANOMALY"
                severity = "HIGH"
                description = f"Abrupt RF signal deviation ({rssi_ch:.1f} dBm); potential RF jamming or device relocation."
            else:
                alert_type = "BEHAVIOR_ANOMALY"
                severity = "HIGH"
                score_str = f"{anomaly_score:.4f}" if anomaly_score is not None else "N/A"
                description = f"Isolation Forest ML detected anomalous behavioral pattern (anomaly score: {score_str})."
        elif behavior and behavior.get("uptime_gap") == 1:
            alert_type = "UNEXPECTED_REBOOT"
            severity = "MEDIUM"
            description = "Device experienced an unexpected restart / uptime counter reset."

        # If no anomaly / normal telemetry, do not generate alert
        if not alert_type:
            return None

        # Check deduplication cooldown (simulations force alert creation)
        if not should_create_alert(device_id or "UNKNOWN", alert_type, now, force=is_simulation):
            return None

        alert = SecurityAlert(
            device_id=device_id or "UNKNOWN",
            timestamp=now,
            alert_type=alert_type,
            threat=threat or "NONE",
            severity=severity,
            anomaly_score=anomaly_score,
            security_status=security_status,
            firmware_status=firmware_status,
            description=description,
            status="ACTIVE"
        )
        db.add(alert)
        db.commit()
        return alert
    except Exception as e:
        print(f"Error generating security alert: {e}")
        return None



def ensure_telemetry_behavior_columns():
    inspector = inspect(engine)
    if not inspector.has_table("telemetry"):
        Base.metadata.create_all(bind=engine)
        return

    existing_columns = {column["name"] for column in inspector.get_columns("telemetry")}
    required_columns = {
        "packet_rate": "FLOAT",
        "request_rate": "FLOAT",
        "heap_change": "INTEGER",
        "rssi_change": "FLOAT",
        "uptime_gap": "INTEGER",
        "security_status": "VARCHAR",
        "firmware_status": "VARCHAR",
        "threat": "VARCHAR",
        "ml_detection": "VARCHAR",
        "anomaly_score": "FLOAT",
    }

    with engine.begin() as connection:
        for column_name, column_type in required_columns.items():
            if column_name not in existing_columns:
                connection.execute(
                    text(f"ALTER TABLE telemetry ADD COLUMN {column_name} {column_type}")
                )


ensure_telemetry_behavior_columns()


def ensure_default_device():
    inspector = inspect(engine)
    if not inspector.has_table("devices"):
        Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        if db.query(Device).count() == 0:
            db.add(Device(
                device_id="ESP8266-01",
                mac="60:01:94:73:34:00",
                ip="10.214.179.156",
                firmware="1.0.0",
                firmware_md5="3b27ec70c26f9ef3aa13e053336e550c",
                status="trusted",
                registered_at=datetime.now()
            ))
            db.commit()
    finally:
        db.close()


ensure_default_device()



# -------------------------
# Home
# -------------------------

@app.get("/")
def home():

    return {
        "status": "online",
        "message": "IoT Security Backend is running"
    }


# -------------------------
# Receive ESP8266 telemetry
# -------------------------


@app.post("/api/device")
def receive_device(data: dict):

    db = SessionLocal()

    mac = data.get("mac")
    current_md5 = data.get("firmware_md5")

    # Find registered device
    device = db.query(Device).filter(
        Device.mac == mac
    ).first()

    security_status = "suspicious"
    threat = "ROGUE_DEVICE"
    firmware_status = "unknown"

    if device:

        # Firmware integrity check
        if current_md5 == device.firmware_md5:

            security_status = "trusted"
            threat = "NONE"
            firmware_status = "valid"

        else:

            security_status = "suspicious"
            threat = "FIRMWARE_TAMPERED"
            firmware_status = "tampered"

    # Calculate behavioral features first
    behavior = calculate_behavior(data, db)
    ml_status, anomaly_score = predict_anomaly(behavior)

    # Detect behavioral anomalies for trusted devices
    if ml_status == "ANOMALY" and security_status == "trusted":
        security_status = "suspicious"
        threat = "BEHAVIOR_ANOMALY"

    current_time = datetime.now()

    # Save telemetry + behavior features
    telemetry = Telemetry(
        device_id=data.get("device_id"),
        chip_id=data.get("chip_id"),
        mac=mac,
        ip=data.get("ip"),
        rssi=data.get("rssi"),
        free_heap=data.get("free_heap"),
        uptime=data.get("uptime"),
        firmware=data.get("firmware"),
        firmware_md5=current_md5,
        packet_count=data.get("packet_count"),
        request_count=data.get("request_count"),
        security_status=security_status,
        firmware_status=firmware_status,
        threat=threat,
        ml_detection=ml_status,
        anomaly_score=anomaly_score,
        packet_rate=behavior["packet_rate"],
        request_rate=behavior["request_rate"],
        heap_change=behavior["heap_change"],
        rssi_change=behavior["rssi_change"],
        uptime_gap=behavior["uptime_gap"],
        timestamp=current_time
    )

    db.add(telemetry)
    db.commit()

    # Determine event type
    if threat == "ROGUE_DEVICE":
        event_type = "ROGUE_DEVICE"
    elif threat == "FIRMWARE_TAMPERED":
        event_type = "FIRMWARE_TAMPERED"
    elif threat == "BEHAVIOR_ANOMALY" or ml_status == "ANOMALY":
        event_type = "BEHAVIOR_ANOMALY"
    else:
        event_type = "NORMAL"

    detection_event = DetectionHistory(
        device_id=data.get("device_id"),
        mac=mac,
        timestamp=current_time,
        security_status=security_status,
        firmware_status=firmware_status,
        ml_detection=ml_status,
        threat=threat,
        anomaly_score=anomaly_score,
        rssi=data.get("rssi"),
        free_heap=data.get("free_heap"),
        uptime=data.get("uptime"),
        packet_rate=behavior["packet_rate"],
        request_rate=behavior["request_rate"],
        heap_change=behavior["heap_change"],
        rssi_change=behavior["rssi_change"],
        uptime_gap=behavior["uptime_gap"],
        event_type=event_type
    )
    db.add(detection_event)
    db.commit()

    # Generate security alert if anomaly detected (with deduplication)
    generate_security_alert(
        db=db,
        device_id=data.get("device_id"),
        threat=threat,
        ml_status=ml_status,
        anomaly_score=anomaly_score,
        security_status=security_status,
        firmware_status=firmware_status,
        behavior=behavior,
        now=current_time,
        is_simulation=False
    )

    db.close()

    # Console output
    print("\n========== IoT DEVICE ==========")
    print("Device:", data.get("device_id"))
    print("MAC:", mac)
    print("IP:", data.get("ip"))
    print("RSSI:", data.get("rssi"))
    print("Free Heap:", data.get("free_heap"))
    print("Uptime:", data.get("uptime"))
    print("Firmware:", data.get("firmware"))
    print("Firmware MD5:", current_md5)
    print("--------------------------------")
    print("Security Status:", security_status)
    print("Firmware Status:", firmware_status)
    print("THREAT:", threat)
    print("ML Detection:", ml_status)
    print("Anomaly Score:", anomaly_score)
    print("Event Type:", event_type)
    print("Time:", current_time)
    print("Saved to database & detection history!")
    print("================================")
    print("\n========== BEHAVIOR FEATURES ==========")

    print(f"RSSI             : {behavior['rssi']} dBm")
    print(f"Free Heap        : {behavior['free_heap']} bytes")
    print(f"Uptime           : {behavior['uptime']} sec")
    print(f"Packet Rate      : {behavior['packet_rate']:.2f} packets/sec")
    print(f"Request Rate     : {behavior['request_rate']:.2f} requests/sec")
    print(f"Heap Change      : {behavior['heap_change']} bytes")
    print(f"RSSI Change      : {behavior['rssi_change']} dBm")
    print(f"Unexpected Reboot: {behavior['uptime_gap']}")

    print("======================================")

    return {
        "status": "received",
        "database": "saved",
        "device_id": data.get("device_id"),
        "security_status": security_status,
        "firmware_status": firmware_status,
        "threat": threat,
        "ml_status": ml_status,
        "ml_detection": ml_status,
        "anomaly_score": anomaly_score,
        "event_type": event_type,
        "behavioral_features": behavior
    }
    
@app.post("/api/devices/register")
def register_device(data: dict):

    db = SessionLocal()

    mac = data.get("mac")

    existing = db.query(Device).filter(
        Device.mac == mac
    ).first()

    # If device already exists, update its information
    if existing:

        existing.device_id = data.get("device_id")
        existing.ip = data.get("ip")
        existing.firmware = data.get("firmware")
        existing.firmware_md5 = data.get("firmware_md5")
        existing.status = "trusted"

        db.commit()

        response = {
            "status": "updated",
            "device_id": existing.device_id,
            "mac": existing.mac,
            "firmware_md5": existing.firmware_md5
        }

        db.close()

        return response

    # Register new device
    device = Device(
        device_id=data.get("device_id"),
        mac=data.get("mac"),
        ip=data.get("ip"),
        firmware=data.get("firmware"),
        firmware_md5=data.get("firmware_md5"),
        status="trusted",
        registered_at=datetime.now()
    )

    db.add(device)
    db.commit()
    db.refresh(device)

    response = {
        "status": "registered",
        "device_id": device.device_id,
        "mac": device.mac,
        "firmware_md5": device.firmware_md5
    }

    db.close()

    return response

@app.get("/api/devices/latest")
def get_latest_device():

    db = SessionLocal()

    telemetry = db.query(Telemetry).order_by(
        Telemetry.id.desc()
    ).first()

    db.close()

    if not telemetry:
        return {
            "status": "no_data"
        }

    return {
        "device_id": telemetry.device_id,
        "mac": telemetry.mac,
        "ip": telemetry.ip,
        "rssi": telemetry.rssi,
        "free_heap": telemetry.free_heap,
        "uptime": telemetry.uptime,
        "firmware": telemetry.firmware,
        "firmware_md5": telemetry.firmware_md5,
        "packet_count": telemetry.packet_count,
        "request_count": telemetry.request_count,
        "security_status": telemetry.security_status,
        "firmware_status": telemetry.firmware_status,
        "threat": telemetry.threat,
        "ml_detection": telemetry.ml_detection,
        "anomaly_score": telemetry.anomaly_score,
        "packet_rate": telemetry.packet_rate,
        "request_rate": telemetry.request_rate,
        "heap_change": telemetry.heap_change,
        "rssi_change": telemetry.rssi_change,
        "uptime_gap": telemetry.uptime_gap,
        "timestamp": str(telemetry.timestamp)
    }


# -------------------------
# Detection History Endpoints
# -------------------------

@app.get("/api/history")
def get_history(limit: int = 100, format: str = None):

    db = SessionLocal()
    try:
        limit = max(1, min(limit, 500))
        records = db.query(Telemetry).order_by(
            Telemetry.id.desc()
        ).limit(limit).all()

        events = []
        for r in records:
            ev_type = "NORMAL"
            if r.threat == "FIRMWARE_TAMPERED":
                ev_type = "FIRMWARE_TAMPERED"
            elif r.threat == "ROGUE_DEVICE":
                ev_type = "ROGUE_DEVICE"
            elif r.threat == "BEHAVIOR_ANOMALY" or r.ml_detection == "ANOMALY":
                ev_type = "BEHAVIOR_ANOMALY"

            events.append({
                "id": r.id,
                "timestamp": str(r.timestamp),
                "device_id": r.device_id or "ESP8266-01",
                "mac": r.mac,
                "rssi": r.rssi if r.rssi is not None else -28.0,
                "free_heap": r.free_heap if r.free_heap is not None else 49000,
                "uptime": r.uptime if r.uptime is not None else 0,
                "packet_rate": round(r.packet_rate, 2) if r.packet_rate is not None else 0.20,
                "request_rate": round(r.request_rate, 2) if r.request_rate is not None else 0.20,
                "heap_change": r.heap_change if r.heap_change is not None else 0,
                "rssi_change": round(r.rssi_change, 2) if r.rssi_change is not None else 0.0,
                "uptime_gap": r.uptime_gap if r.uptime_gap is not None else 0,
                "anomaly_score": round(r.anomaly_score, 4) if r.anomaly_score is not None else 0.184,
                "ml_detection": r.ml_detection or "NORMAL",
                "security_status": r.security_status or "trusted",
                "firmware_status": r.firmware_status or "valid",
                "threat": r.threat or "NONE",
                "event_type": ev_type
            })

        if format == "dict":
            return {
                "count": len(events),
                "events": events
            }

        # Return list of records as specified by Section 1
        return events
    finally:
        db.close()


@app.get("/api/history/summary")
def get_history_summary():

    db = SessionLocal()
    try:
        total_events = db.query(Telemetry).count()
        normal_events = db.query(Telemetry).filter(
            Telemetry.threat == "NONE",
            (Telemetry.ml_detection == "NORMAL") | (Telemetry.ml_detection == None)
        ).count()
        anomaly_events = total_events - normal_events
        rogue_devices = db.query(Telemetry).filter(Telemetry.threat == "ROGUE_DEVICE").count()
        firmware_tampered = db.query(Telemetry).filter(Telemetry.threat == "FIRMWARE_TAMPERED").count()
        behavior_anomalies = db.query(Telemetry).filter(Telemetry.threat == "BEHAVIOR_ANOMALY").count()

        return {
            "total_events": total_events,
            "normal_events": normal_events,
            "anomaly_events": anomaly_events,
            "rogue_devices": rogue_devices,
            "firmware_tampered": firmware_tampered,
            "behavior_anomalies": behavior_anomalies
        }
    finally:
        db.close()


# -------------------------
# Attack / Anomaly Simulator
# -------------------------

SIMULATION_TYPES = {
    "traffic_spike": "Simulate high packet and request rates (synthetic burst)",
    "memory_stress": "Simulate rapid free heap memory exhaustion and large negative delta",
    "signal_anomaly": "Simulate abnormal radio signal RSSI fluctuation",
    "reboot_anomaly": "Simulate unexpected device reboot with low uptime and uptime gap flag",
    "combined_anomaly": "Simulate concurrent multi-feature behavioral anomalies",
    "firmware_tamper": "Simulate tampered firmware hash mismatch"
}


def run_simulation(sim_type: str):

    if not sim_type or sim_type not in SIMULATION_TYPES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Unknown simulation type",
                "provided": sim_type,
                "supported_types": list(SIMULATION_TYPES.keys())
            }
        )

    if model is None or scaler is None:
        raise HTTPException(
            status_code=500,
            detail={"error": "Machine learning model or scaler is not loaded"}
        )

    db = SessionLocal()
    try:
        device = db.query(Device).first()
        device_id = device.device_id if device else "ESP8266-01"
        mac = device.mac if device else "60:01:94:73:34:00"
        ip = device.ip if device else "10.214.179.156"
        valid_md5 = device.firmware_md5 if device else "3b27ec70c26f9ef3aa13e053336e550c"
        valid_firmware = device.firmware if device else "1.0.0"

        # Baseline parameters
        base_rssi = -27.0
        base_heap = 49500
        base_uptime = 3200
        base_packet_rate = 0.2
        base_request_rate = 0.2
        base_heap_change = 0
        base_rssi_change = 0.0
        base_uptime_gap = 0

        # Firmware determination
        if sim_type == "firmware_tamper":
            current_md5 = "tampered_bad_md5_hash_9999"
        else:
            current_md5 = valid_md5

        # Feature synthesis per anomaly type
        if sim_type == "traffic_spike":
            base_packet_rate = 120.0
            base_request_rate = 120.0
            base_heap_change = -3500
            base_heap = 42000
            base_rssi_change = 1.0
        elif sim_type == "memory_stress":
            base_heap = 7200
            base_heap_change = -42300
            base_packet_rate = 0.2
            base_request_rate = 0.2
        elif sim_type == "signal_anomaly":
            base_rssi = -88.0
            base_rssi_change = -61.0
        elif sim_type == "reboot_anomaly":
            base_uptime = 2
            base_uptime_gap = 1
            base_heap = 41000
            base_heap_change = -8000
        elif sim_type == "combined_anomaly":
            base_packet_rate = 70.0
            base_request_rate = 70.0
            base_heap = 8500
            base_heap_change = -41000
            base_rssi = -82.0
            base_rssi_change = -55.0
            base_uptime = 5
            base_uptime_gap = 1
        elif sim_type == "firmware_tamper":
            pass

        # Pipeline Step 1: Firmware integrity verification
        security_status = "suspicious"
        threat = "ROGUE_DEVICE"
        firmware_status = "unknown"

        if device:
            if current_md5 == device.firmware_md5:
                security_status = "trusted"
                threat = "NONE"
                firmware_status = "valid"
            else:
                security_status = "suspicious"
                threat = "FIRMWARE_TAMPERED"
                firmware_status = "tampered"

        # Pipeline Step 2: ML Behavioral evaluation
        features = {
            "rssi": base_rssi,
            "free_heap": base_heap,
            "uptime": base_uptime,
            "packet_rate": base_packet_rate,
            "request_rate": base_request_rate,
            "heap_change": base_heap_change,
            "rssi_change": base_rssi_change,
            "uptime_gap": base_uptime_gap
        }

        ml_status, anomaly_score = predict_anomaly(features)

        # Pipeline Step 3: Anomaly detection state update
        if ml_status == "ANOMALY" and security_status == "trusted":
            security_status = "suspicious"
            threat = "BEHAVIOR_ANOMALY"

        if sim_type == "firmware_tamper":
            security_status = "suspicious"
            threat = "FIRMWARE_TAMPERED"
            firmware_status = "tampered"
            detection_display = "ANOMALY"
        else:
            detection_display = ml_status

        event_type = threat if threat != "NONE" else "NORMAL"
        now = datetime.now()

        # Update in-memory previous_data tracking
        previous_data[device_id] = {
            "rssi": base_rssi,
            "free_heap": base_heap,
            "uptime": base_uptime,
            "packet_count": 1000,
            "request_count": 1000
        }

        # Persist to DetectionHistory
        history_event = DetectionHistory(
            device_id=device_id,
            mac=mac,
            timestamp=now,
            security_status=security_status,
            firmware_status=firmware_status,
            ml_detection=detection_display,
            threat=threat,
            anomaly_score=anomaly_score,
            rssi=base_rssi,
            free_heap=base_heap,
            uptime=base_uptime,
            packet_rate=base_packet_rate,
            request_rate=base_request_rate,
            heap_change=base_heap_change,
            rssi_change=base_rssi_change,
            uptime_gap=base_uptime_gap,
            event_type=event_type
        )
        db.add(history_event)

        # Persist to Telemetry
        last_tel = db.query(Telemetry).filter(Telemetry.device_id == device_id).order_by(Telemetry.id.desc()).first()
        p_count = (last_tel.packet_count + int(base_packet_rate * 5)) if last_tel and last_tel.packet_count else 600
        r_count = (last_tel.request_count + int(base_request_rate * 5)) if last_tel and last_tel.request_count else 600

        sim_telemetry = Telemetry(
            device_id=device_id,
            chip_id="simulated",
            mac=mac,
            ip=ip,
            rssi=base_rssi,
            free_heap=base_heap,
            uptime=base_uptime,
            firmware=valid_firmware,
            firmware_md5=current_md5,
            packet_count=p_count,
            request_count=r_count,
            security_status=security_status,
            firmware_status=firmware_status,
            threat=threat,
            ml_detection=detection_display,
            anomaly_score=anomaly_score,
            packet_rate=base_packet_rate,
            request_rate=base_request_rate,
            heap_change=base_heap_change,
            rssi_change=base_rssi_change,
            uptime_gap=base_uptime_gap,
            timestamp=now
        )
        db.add(sim_telemetry)

        # Generate alert for simulation event
        generate_security_alert(
            db=db,
            device_id=device_id,
            threat=threat,
            ml_status=detection_display,
            anomaly_score=anomaly_score,
            security_status=security_status,
            firmware_status=firmware_status,
            behavior=features,
            now=now,
            is_simulation=True
        )

        db.commit()

        return {
            "simulation_type": sim_type.upper(),
            "detection": detection_display,
            "threat": threat,
            "anomaly_score": round(anomaly_score, 4),
            "security_status": security_status,
            "firmware_status": firmware_status,
            "behavioral_features": features,
            "ml_detection": detection_display,
            "type": sim_type,
            "event_type": event_type,
            "simulation": True
        }
    finally:
        db.close()


@app.post("/api/simulate/{simulation_type}")
def simulate_attack_by_path(simulation_type: str):
    return run_simulation(simulation_type)


@app.post("/api/simulate")
def simulate_attack_by_body(data: dict = None):
    sim_type = data.get("type") if (data and isinstance(data, dict)) else None
    if not sim_type:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Missing simulation type in JSON body",
                "supported_types": list(SIMULATION_TYPES.keys())
            }
        )
    return run_simulation(sim_type)


# -------------------------
# Security Alerts Endpoints
# -------------------------

@app.get("/api/alerts")
def get_security_alerts(limit: int = 50, severity: str = None):

    db = SessionLocal()
    try:
        limit = max(1, min(limit, 200))
        query = db.query(SecurityAlert)
        if severity:
            query = query.filter(SecurityAlert.severity == severity.upper())

        alerts = query.order_by(SecurityAlert.id.desc()).limit(limit).all()

        return [
            {
                "id": a.id,
                "device_id": a.device_id,
                "timestamp": str(a.timestamp),
                "alert_type": a.alert_type,
                "threat": a.threat,
                "severity": a.severity,
                "anomaly_score": round(a.anomaly_score, 4) if a.anomaly_score is not None else None,
                "security_status": a.security_status,
                "firmware_status": a.firmware_status,
                "description": a.description,
                "status": a.status
            }
            for a in alerts
        ]
    finally:
        db.close()


@app.get("/api/alerts/stats")
def get_security_alerts_stats():

    db = SessionLocal()
    try:
        total = db.query(SecurityAlert).count()
        critical = db.query(SecurityAlert).filter(SecurityAlert.severity == "CRITICAL").count()
        high = db.query(SecurityAlert).filter(SecurityAlert.severity == "HIGH").count()
        medium = db.query(SecurityAlert).filter(SecurityAlert.severity == "MEDIUM").count()
        low = db.query(SecurityAlert).filter(SecurityAlert.severity == "LOW").count()

        return {
            "total_alerts": total,
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low
        }
    finally:
        db.close()

