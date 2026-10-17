from fastapi import FastAPI, HTTPException, Query, Header, Request
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from collections import defaultdict
from fastapi.middleware.cors import CORSMiddleware
import os
import secrets
import hashlib
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

    device_id = data.get("device_id") or "ESP8266-01"
    mac = data.get("mac")

    current_rssi = float(data.get("rssi")) if data.get("rssi") is not None else -28.0
    current_heap = int(data.get("free_heap")) if data.get("free_heap") is not None else 49000
    current_uptime = int(data.get("uptime")) if data.get("uptime") is not None else 0
    current_packets = int(data.get("packet_count")) if data.get("packet_count") is not None else 0
    current_requests = int(data.get("request_count")) if data.get("request_count") is not None else 0

    # 1. Query the most recent PREVIOUS telemetry record for this device from the database
    last_tel = None
    if db is not None:
        try:
            query = db.query(Telemetry)
            if mac:
                query = query.filter((Telemetry.device_id == device_id) | (Telemetry.mac == mac))
            else:
                query = query.filter(Telemetry.device_id == device_id)
            last_tel = query.order_by(Telemetry.id.desc()).first()
        except Exception as e:
            print(f"Error querying previous telemetry for {device_id}: {e}")

    prev_uptime = None
    prev_packets = current_packets
    prev_requests = current_requests
    prev_heap = current_heap
    prev_rssi = current_rssi

    if last_tel is not None:
        prev_uptime = last_tel.uptime
        prev_packets = last_tel.packet_count if last_tel.packet_count is not None else current_packets
        prev_requests = last_tel.request_count if last_tel.request_count is not None else current_requests
        prev_heap = last_tel.free_heap if last_tel.free_heap is not None else current_heap
        prev_rssi = last_tel.rssi if last_tel.rssi is not None else current_rssi
    elif device_id in previous_data:
        # Fallback to in-memory cache if DB was not provided
        prev_uptime = previous_data[device_id].get("uptime")
        prev_packets = previous_data[device_id].get("packet_count", current_packets)
        prev_requests = previous_data[device_id].get("request_count", current_requests)
        prev_heap = previous_data[device_id].get("free_heap", current_heap)
        prev_rssi = previous_data[device_id].get("rssi", current_rssi)

    # 2. Calculate behavioral features & persistent reboot detection
    packet_rate = 0.2
    request_rate = 0.2
    uptime_gap = 0

    if prev_uptime is not None:
        time_difference = current_uptime - prev_uptime

        if time_difference > 0:
            packet_rate = max(0.0, (current_packets - prev_packets) / time_difference)
            request_rate = max(0.0, (current_requests - prev_requests) / time_difference)
        elif time_difference < 0:
            # Physical ESP8266 reboot detected: current_uptime < prev_uptime
            uptime_gap = 1
            if current_uptime > 0:
                packet_rate = max(0.0, current_packets / current_uptime)
                request_rate = max(0.0, current_requests / current_uptime)
        else:
            packet_rate = 0.0
            request_rate = 0.0

        heap_change = current_heap - prev_heap
        rssi_change = current_rssi - prev_rssi
    else:
        # Initial baseline sample for this device
        heap_change = 0
        rssi_change = 0.0
        uptime_gap = 0

    features = {
        "rssi": current_rssi,
        "free_heap": current_heap,
        "uptime": current_uptime,
        "packet_rate": round(packet_rate, 4),
        "request_rate": round(request_rate, 4),
        "heap_change": heap_change,
        "rssi_change": round(rssi_change, 2),
        "uptime_gap": uptime_gap,
        "previous_uptime": prev_uptime,
        "current_uptime": current_uptime
    }

    # Synchronize in-memory cache
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
    anomaly_reason = Column(String)
    
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
    anomaly_reason = Column(String)

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
    anomaly_reason = Column(String)
    security_status = Column(String)  # suspicious, trusted
    firmware_status = Column(String)  # tampered, valid, unknown
    description = Column(String)
    status = Column(String, default="ACTIVE")  # ACTIVE, ACKNOWLEDGED, RESOLVED


class User(Base):

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, default="Administrator")
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="ADMIN")
    created_at = Column(DateTime, default=datetime.now)
    last_login = Column(DateTime, nullable=True)


# Create database/table schemas if needed
Base.metadata.create_all(bind=engine)


# -------------------------
# Security & Hashing Helpers
# -------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100000)
    return f"{salt}${key.hex()}"


def verify_password(password: str, hashed: str) -> bool:
    try:
        if not hashed or "$" not in hashed:
            return False
        salt, key_hex = hashed.split("$")
        computed_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100000)
        return secrets.compare_digest(computed_key.hex(), key_hex)
    except Exception:
        return False


# In-memory prototype token session store: token -> dict
active_sessions = {}


def get_user_from_token(authorization: str = None):
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    if not token or token not in active_sessions:
        return None
    return active_sessions[token]


def ensure_users_table():
    inspector = inspect(engine)
    if not inspector.has_table("users"):
        Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        admin_user = db.query(User).filter(User.email == "admin@iotsecurity.local").first()
        if not admin_user:
            admin_user = User(
                name="Administrator",
                email="admin@iotsecurity.local",
                password_hash=hash_password("admin123"),
                role="ADMIN",
                created_at=datetime.now()
            )
            db.add(admin_user)
            db.commit()
    finally:
        db.close()


ensure_users_table()


# ==========================================
# Anomaly Persistence & Device State Machine
# ==========================================

ANOMALY_CONFIRMATION_COUNT = 3  # consecutive anomalies required before escalating to SUSPICIOUS
RECOVERY_COUNT = 3              # consecutive normal samples required before recovering to TRUSTED


class DeviceStateMachine:
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.state = "TRUSTED"  # TRUSTED, MONITORING, SUSPICIOUS, RECOVERING
        self.anomaly_streak = 0
        self.normal_streak = 0
        self.recent_observations = []  # circular buffer of last 10 dicts
        self.last_evidence = {}
        self.last_reason = "Device behavior is within the learned normal baseline."

    def process_observation(self, ml_status: str, anomaly_score: float, features: dict, timestamp: datetime):
        time_str = timestamp.strftime("%H:%M:%S") if isinstance(timestamp, datetime) else str(timestamp)
        obs = {
            "time": time_str,
            "timestamp": str(timestamp),
            "ml": ml_status,
            "score": round(anomaly_score, 4) if anomaly_score is not None else 0.18,
            "packet_rate": round(features.get("packet_rate", 0.2), 2),
            "free_heap": features.get("free_heap", 49000),
            "rssi": features.get("rssi", -28.0)
        }
        self.recent_observations.append(obs)
        if len(self.recent_observations) > 10:
            self.recent_observations.pop(0)

        if ml_status == "ANOMALY":
            self.anomaly_streak += 1
            self.normal_streak = 0

            if self.state == "TRUSTED":
                self.state = "MONITORING"
                self.last_reason = f"Single anomalous observation detected (1/{ANOMALY_CONFIRMATION_COUNT}). Insufficient evidence for escalation."
            elif self.state == "MONITORING":
                if self.anomaly_streak >= ANOMALY_CONFIRMATION_COUNT:
                    self.state = "SUSPICIOUS"
                    self.last_reason = f"{ANOMALY_CONFIRMATION_COUNT} consecutive anomalous observations detected. Behavior escalated to persistent anomaly."
                else:
                    self.state = "MONITORING"
                    self.last_reason = f"Anomalous observation ({self.anomaly_streak}/{ANOMALY_CONFIRMATION_COUNT}) detected. Monitoring without escalation."
            elif self.state == "SUSPICIOUS":
                self.state = "SUSPICIOUS"
                self.last_reason = f"Persistent behavioral anomaly ongoing ({self.anomaly_streak} consecutive anomalous samples)."
            elif self.state == "RECOVERING":
                self.state = "SUSPICIOUS"
                self.last_reason = f"Anomalous observation ({self.anomaly_streak}/{ANOMALY_CONFIRMATION_COUNT}) interrupted recovery. Reverting to suspicious status."

        else:  # NORMAL
            self.normal_streak += 1
            self.anomaly_streak = 0

            if self.state == "TRUSTED":
                self.state = "TRUSTED"
                self.last_reason = "Device behavior is within the learned normal baseline."
            elif self.state == "MONITORING":
                self.state = "TRUSTED"
                self.last_reason = "Device behavior returned to normal baseline after isolated anomaly."
            elif self.state == "SUSPICIOUS":
                self.state = "RECOVERING"
                self.last_reason = f"Normal observation (1/{RECOVERY_COUNT}) received after anomaly. Verifying recovery."
            elif self.state == "RECOVERING":
                if self.normal_streak >= RECOVERY_COUNT:
                    self.state = "TRUSTED"
                    self.last_reason = f"Device behavior recovered to normal baseline ({RECOVERY_COUNT} consecutive normal samples verified)."
                else:
                    self.state = "RECOVERING"
                    self.last_reason = f"Normal observation ({self.normal_streak}/{RECOVERY_COUNT}) received. Sustained stability required for full recovery."

        pr = features.get("packet_rate", 0.2)
        fh = features.get("free_heap", 49000)
        hc = features.get("heap_change", 0)
        rssi_val = features.get("rssi", -28.0)
        rc = features.get("rssi_change", 0.0)
        ug = features.get("uptime_gap", 0)

        self.last_evidence = {
            "anomaly_streak": self.anomaly_streak,
            "anomaly_threshold": ANOMALY_CONFIRMATION_COUNT,
            "normal_streak": self.normal_streak,
            "recovery_threshold": RECOVERY_COUNT,
            "anomaly_score": round(anomaly_score, 4) if anomaly_score is not None else 0.18,
            "packet_rate": round(pr, 2) if pr is not None else 0.2,
            "free_heap": fh if fh is not None else 49000,
            "heap_change": hc if hc is not None else 0,
            "rssi": rssi_val if rssi_val is not None else -28.0,
            "rssi_change": round(rc, 2) if rc is not None else 0.0,
            "uptime_gap": ug if ug is not None else 0,
            "state": self.state
        }

        return self.state, self.last_reason, self.last_evidence


device_state_machines = {}


def get_or_create_state_machine(device_id: str, db=None) -> DeviceStateMachine:
    if device_id in device_state_machines:
        return device_state_machines[device_id]

    sm = DeviceStateMachine(device_id)
    if db is not None:
        try:
            recent_tels = db.query(Telemetry).filter(
                Telemetry.device_id == device_id
            ).order_by(Telemetry.id.desc()).limit(10).all()
            if recent_tels:
                for t in reversed(recent_tels):
                    obs = {
                        "time": t.timestamp.strftime("%H:%M:%S") if t.timestamp else "--",
                        "timestamp": str(t.timestamp),
                        "ml": t.ml_detection or "NORMAL",
                        "score": round(t.anomaly_score, 4) if t.anomaly_score is not None else 0.18,
                        "packet_rate": round(t.packet_rate, 2) if t.packet_rate is not None else 0.2,
                        "free_heap": t.free_heap if t.free_heap is not None else 49000,
                        "rssi": t.rssi if t.rssi is not None else -28.0
                    }
                    sm.recent_observations.append(obs)

                consec_anom = 0
                consec_norm = 0
                for t in recent_tels:
                    if t.ml_detection == "ANOMALY":
                        if consec_norm > 0:
                            break
                        consec_anom += 1
                    else:
                        if consec_anom > 0:
                            break
                        consec_norm += 1

                sm.anomaly_streak = consec_anom
                sm.normal_streak = consec_norm
                if consec_anom >= ANOMALY_CONFIRMATION_COUNT:
                    sm.state = "SUSPICIOUS"
                elif consec_anom > 0:
                    sm.state = "MONITORING"
                else:
                    sm.state = "TRUSTED"
        except Exception as e:
            print(f"Error initializing state machine for {device_id}: {e}")

    device_state_machines[device_id] = sm
    return sm


def calculate_risk_score(security_status: str, firmware_status: str, threat: str, ml_status: str, anomaly_score: float, behavior: dict = None, sm_state: str = None) -> dict:
    """
    Calculates a transparent, explainable Security Risk Score (0-100) and risk level.
    """
    score = 0
    factors = []

    sec_lower = (security_status or "").lower()
    fw_lower = (firmware_status or "").lower()

    if threat == "ROGUE_DEVICE" or sec_lower == "rogue":
        score += 40
        factors.append("Unregistered / Rogue Device (+40)")

    if threat == "FIRMWARE_TAMPERED" or fw_lower == "tampered":
        score += 40
        factors.append("Cryptographic Firmware Mismatch (+40)")

    if sec_lower == "suspicious" or sm_state == "SUSPICIOUS":
        score += 30
        factors.append("Persistent Behavioral Anomaly (+30)")
    elif sec_lower == "monitoring" or sm_state == "MONITORING":
        score += 15
        factors.append("Isolated Anomaly Monitoring (+15)")
    elif sec_lower == "recovering" or sm_state == "RECOVERING":
        score += 10
        factors.append("Anomaly Recovery in Progress (+10)")

    if anomaly_score is not None and anomaly_score < -0.1:
        score += 10
        factors.append("High Statistical Anomaly Deviation (+10)")

    if behavior:
        if behavior.get("heap_change", 0) <= -20000 or (behavior.get("free_heap") is not None and behavior.get("free_heap") < 35000):
            score += 15
            factors.append("Heap Memory Depletion (+15)")
        if (behavior.get("packet_rate", 0) or 0) >= 50.0 or (behavior.get("request_rate", 0) or 0) >= 50.0:
            score += 15
            factors.append("Network Traffic Spike (+15)")
        if abs(behavior.get("rssi_change", 0) or 0) >= 30.0:
            score += 10
            factors.append("Abrupt RF Signal Fluctuation (+10)")
        if behavior.get("uptime_gap") == 1:
            score += 10
            factors.append("Unexpected Device Reboot (+10)")

    score = min(100, max(0, score))

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": score,
        "risk_level": level,
        "risk_factors": factors
    }


def ensure_detection_history_table():
    inspector = inspect(engine)
    if not inspector.has_table("detection_history"):
        Base.metadata.create_all(bind=engine)
        return

    existing_cols = {col["name"] for col in inspector.get_columns("detection_history")}
    if "anomaly_reason" not in existing_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE detection_history ADD COLUMN anomaly_reason VARCHAR"))


ensure_detection_history_table()


def ensure_security_alerts_table():
    inspector = inspect(engine)
    if not inspector.has_table("security_alerts"):
        Base.metadata.create_all(bind=engine)
        return

    existing_cols = {col["name"] for col in inspector.get_columns("security_alerts")}
    if "anomaly_reason" not in existing_cols:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE security_alerts ADD COLUMN anomaly_reason VARCHAR"))


ensure_security_alerts_table()


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
        "anomaly_reason": "VARCHAR",
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


def explain_anomaly(features: dict, ml_status: str, sim_type: str = None, threat: str = None) -> str:
    """
    Analyzes behavioral features and security signals to produce an explainable attribution.
    When normal: 'Device behavior is within the learned normal baseline.'
    When anomalous: attributes root cause based on empirical distribution baselines.
    """
    if sim_type:
        sim_explanations = {
            "traffic_spike": "Synthetic traffic spike detected: packet/request rate is abnormally high.",
            "memory_stress": "Synthetic memory stress detected: free heap behavior is abnormal.",
            "signal_anomaly": "Synthetic signal anomaly detected: RSSI deviation is abnormal.",
            "reboot_anomaly": "Unexpected reboot behavior detected.",
            "combined_anomaly": "Multiple abnormal behavioral features detected simultaneously.",
            "firmware_tamper": "Firmware MD5 does not match the registered firmware."
        }
        if sim_type in sim_explanations:
            return sim_explanations[sim_type]

    if threat == "FIRMWARE_TAMPERED":
        return "Firmware MD5 does not match the registered firmware."

    if threat == "ROGUE_DEVICE":
        return "Unregistered or unauthorized hardware identity detected on network."

    if ml_status == "NORMAL" and (threat == "NONE" or not threat):
        return "Device behavior is within the learned normal baseline."

    if not features:
        return "Device behavioral features deviate from the learned baseline."

    pr = features.get("packet_rate", 0.2)
    rr = features.get("request_rate", 0.2)
    fh = features.get("free_heap", 49000)
    hc = features.get("heap_change", 0)
    rc = features.get("rssi_change", 0.0)
    ug = features.get("uptime_gap", 0)

    # Statistical baseline thresholds from normal_behavior.csv:
    is_traffic = (pr is not None and pr >= 2.0) or (rr is not None and rr >= 2.0)
    is_memory = (hc is not None and hc <= -2000) or (fh is not None and fh < 35000)
    is_signal = (rc is not None and abs(rc) >= 25.0)
    is_reboot = (ug == 1)

    abnormal_count = sum([is_traffic, is_memory, is_signal, is_reboot])

    if abnormal_count > 1:
        return "Multiple behavioral features deviate from the learned baseline."
    elif is_traffic:
        return "Packet/request rate is significantly higher than the learned normal behavior."
    elif is_memory:
        return "Free heap or heap change indicates abnormal memory behavior."
    elif is_signal:
        return "RSSI changed significantly from the previous telemetry sample."
    elif is_reboot:
        return "Unexpected device reboot detected."
    else:
        return "Device behavioral features deviate from the learned baseline."


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
    is_simulation: bool = False,
    anomaly_reason: str = None
):
    """
    Evaluates telemetry & security state to generate a security alert if anomalous.
    Deduplicates repeated alerts for the same device & anomaly type within 30 seconds.
    """
    try:
        alert_type = None
        severity = None
        description = None

        if threat == "FIRMWARE_TAMPERED" or (firmware_status or "").upper() == "FIRMWARE_TAMPERED" or (firmware_status or "").lower() == "tampered":
            alert_type = "FIRMWARE_TAMPERED"
            severity = "CRITICAL"
            expected = behavior.get("expected_firmware_md5") if behavior else "authorized baseline"
            reported = behavior.get("reported_firmware_md5", behavior.get("firmware_md5")) if behavior else "unauthorized"
            description = f"Cryptographic mismatch: device firmware hash differs from authorized baseline (Expected: {expected}, Reported: {reported})."
        elif threat == "ROGUE_DEVICE":
            alert_type = "ROGUE_DEVICE"
            severity = "CRITICAL"
            description = "Unregistered device transmitting on network with unverified hardware identity."
        elif threat == "UNEXPECTED_REBOOT" or (behavior and behavior.get("uptime_gap") == 1):
            alert_type = "UNEXPECTED_REBOOT"
            severity = "MEDIUM"
            prev_u = behavior.get("previous_uptime") if behavior else None
            curr_u = behavior.get("current_uptime", behavior.get("uptime") if behavior else None)
            if prev_u is not None and curr_u is not None:
                description = f"Unexpected device reboot detected (Previous uptime: {prev_u}s, Current uptime: {curr_u}s)."
            else:
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

        # If no anomaly / normal telemetry, do not generate alert
        if not alert_type:
            return None

        # Determine anomaly explanation if not already provided
        if not anomaly_reason:
            anomaly_reason = explain_anomaly(behavior, ml_status, threat=threat)

        # Use anomaly explanation as description if appropriate
        if anomaly_reason and not description:
            description = anomaly_reason

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
            anomaly_reason=anomaly_reason,
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


# -------------------------
# Home & Health
# -------------------------

@app.get("/")
def home():
    return {
        "status": "online",
        "service": "IoT Security Backend",
        "message": "IoT Security Backend is running"
    }


@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "service": "IoT Security Backend",
        "timestamp": str(datetime.now())
    }


# -------------------------
# Receive ESP8266 telemetry
# -------------------------

@app.post("/api/device")
def receive_device(data: dict):

    db = SessionLocal()
    try:
        mac = data.get("mac")
        device_id = data.get("device_id") or "ESP8266-01"
        current_md5 = (data.get("firmware_md5") or "").strip()

        # 1. Device Registration & Firmware Integrity Layer
        device = db.query(Device).filter(
            (Device.mac == mac) | (Device.device_id == device_id)
        ).first()

        if not device:
            identity_status = "UNREGISTERED"
            firmware_status = "UNKNOWN"
            expected_md5 = "--"
            reported_md5 = current_md5 or "--"
            threat = "ROGUE_DEVICE"
        else:
            identity_status = "REGISTERED"
            expected_md5 = (device.firmware_md5 or "").strip()
            reported_md5 = current_md5

            if expected_md5 and reported_md5 and expected_md5.lower() == reported_md5.lower():
                firmware_status = "VALID"
                threat = "NONE"
            else:
                firmware_status = "FIRMWARE_TAMPERED"
                threat = "FIRMWARE_TAMPERED"

        # 2. Behavioral Feature Extraction with Persistent Database Previous Telemetry
        behavior = calculate_behavior(data, db)
        behavior["expected_firmware_md5"] = expected_md5
        behavior["reported_firmware_md5"] = reported_md5
        current_time = datetime.now()

        # 3. Machine Learning Inference (Isolation Forest)
        ml_status, anomaly_score = predict_anomaly(behavior)

        # 4. State Machine & Anomaly Persistence Evaluation
        sm = get_or_create_state_machine(device_id, db)
        sm_state, sm_reason, sm_evidence = sm.process_observation(ml_status, anomaly_score, behavior, current_time)

        # 5. Multi-Layer Security Posture Synthesis
        if not device:
            security_status = "rogue"
            threat = "ROGUE_DEVICE"
            event_type = "ROGUE_DEVICE"
            anomaly_reason = "Unregistered or unauthorized hardware identity detected on network."
            behavior_status = "UNREGISTERED"
        elif firmware_status == "FIRMWARE_TAMPERED":
            security_status = "suspicious"
            threat = "FIRMWARE_TAMPERED"
            event_type = "FIRMWARE_TAMPERED"
            anomaly_reason = f"Cryptographic firmware mismatch: reported MD5 ({reported_md5}) does not match expected baseline ({expected_md5})."
            behavior_status = "TAMPERED"
        elif behavior.get("uptime_gap") == 1:
            # Physical ESP reboot detected
            event_type = "UNEXPECTED_REBOOT"
            threat = "UNEXPECTED_REBOOT"
            prev_u = behavior.get("previous_uptime")
            curr_u = behavior.get("current_uptime")
            anomaly_reason = f"Unexpected device reboot detected (Previous uptime: {prev_u}s -> Current uptime: {curr_u}s)."
            behavior_status = "REBOOT DETECTED"
            security_status = "suspicious" if sm_state == "SUSPICIOUS" else "monitoring"
        else:
            # Registered & valid firmware & normal/persistent anomaly
            if sm_state == "SUSPICIOUS":
                security_status = "suspicious"
                threat = "BEHAVIOR_ANOMALY"
                anomaly_reason = sm_reason
                behavior_status = "PERSISTENT ANOMALY"
                event_type = "BEHAVIOR_ANOMALY"
            elif sm_state == "MONITORING":
                security_status = "monitoring"
                threat = "NONE"
                anomaly_reason = sm_reason
                behavior_status = "ISOLATED ANOMALY"
                event_type = "MONITORING"
            elif sm_state == "RECOVERING":
                security_status = "recovering"
                threat = "NONE"
                anomaly_reason = sm_reason
                behavior_status = "RECOVERING"
                event_type = "RECOVERING"
            else:
                security_status = "trusted"
                threat = "NONE"
                anomaly_reason = sm_reason
                behavior_status = "NORMAL"
                event_type = "NORMAL"

        # Save telemetry to database
        telemetry = Telemetry(
            device_id=device_id,
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
            anomaly_reason=anomaly_reason,
            packet_rate=behavior["packet_rate"],
            request_rate=behavior["request_rate"],
            heap_change=behavior["heap_change"],
            rssi_change=behavior["rssi_change"],
            uptime_gap=behavior["uptime_gap"],
            timestamp=current_time
        )

        db.add(telemetry)
        db.commit()

        # Persist to Detection History
        detection_event = DetectionHistory(
            device_id=device_id,
            mac=mac,
            timestamp=current_time,
            security_status=security_status,
            firmware_status=firmware_status,
            ml_detection=ml_status,
            threat=threat,
            anomaly_score=anomaly_score,
            anomaly_reason=anomaly_reason,
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

        # Generate security alert if incident condition met
        if threat in ["FIRMWARE_TAMPERED", "ROGUE_DEVICE", "UNEXPECTED_REBOOT"] or (threat == "BEHAVIOR_ANOMALY" and sm.anomaly_streak == ANOMALY_CONFIRMATION_COUNT):
            generate_security_alert(
                db=db,
                device_id=device_id,
                threat=threat,
                ml_status=ml_status,
                anomaly_score=anomaly_score,
                security_status=security_status,
                firmware_status=firmware_status,
                behavior=behavior,
                now=current_time,
                is_simulation=False,
                anomaly_reason=anomaly_reason
            )

        # Output to console
        print(f"\n========== IoT TELEMETRY [{device_id}] ==========")
        print(f"Identity Status : {identity_status}")
        print(f"Firmware Status : {firmware_status} (Expected: {expected_md5}, Reported: {reported_md5})")
        print(f"ML Observation  : {ml_status} (Score: {anomaly_score:.4f})")
        print(f"Behavior Streak : {sm.anomaly_streak}/{ANOMALY_CONFIRMATION_COUNT} anomalies, {sm.normal_streak}/{RECOVERY_COUNT} normal")
        print(f"Security Posture: {security_status.upper()}")
        if behavior.get("uptime_gap") == 1:
            print(f"Reboot Detected : YES (Prev: {behavior.get('previous_uptime')}s -> Curr: {behavior.get('current_uptime')}s)")
        print(f"Reason          : {anomaly_reason}")
        print("==================================================")

        risk = calculate_risk_score(security_status, firmware_status, threat, ml_status, anomaly_score, behavior, sm_state=sm_state)

        return {
            "status": "received",
            "database": "saved",
            "device_id": device_id,
            "identity_status": identity_status,
            "security_status": security_status,
            "firmware_status": firmware_status,
            "expected_firmware_md5": expected_md5,
            "firmware_md5": reported_md5,
            "threat": threat,
            "ml_status": ml_status,
            "ml_detection": ml_status,
            "ml_observation": ml_status,
            "behavior_status": behavior_status,
            "anomaly_score": round(anomaly_score, 4) if anomaly_score is not None else 0.18,
            "anomaly_streak": sm.anomaly_streak,
            "anomaly_confirmation_count": ANOMALY_CONFIRMATION_COUNT,
            "recovery_streak": sm.normal_streak,
            "recovery_count": RECOVERY_COUNT,
            "anomaly_reason": anomaly_reason,
            "evidence": sm_evidence,
            "recent_observations": sm.recent_observations,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "risk_factors": risk["risk_factors"],
            "event_type": event_type,
            "previous_uptime": behavior.get("previous_uptime"),
            "current_uptime": behavior.get("current_uptime"),
            "uptime_gap": behavior["uptime_gap"],
            "behavioral_features": behavior
        }
    finally:
        db.close()


# -------------------------
# Admin Authentication Endpoints
# -------------------------

@app.post("/api/auth/login")
def login(credentials: dict):
    email = credentials.get("email", "").strip().lower()
    password = credentials.get("password", "")

    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        user.last_login = datetime.now()
        db.commit()

        token = secrets.token_urlsafe(32)
        active_sessions[token] = {
            "user_id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "created_at": str(user.created_at),
            "last_login": str(user.last_login)
        }

        return {
            "status": "success",
            "success": True,
            "message": "Authentication successful",
            "token": token,
            "user": active_sessions[token]
        }
    finally:
        db.close()


@app.post("/api/auth/logout")
def logout(authorization: str = Header(None)):
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif authorization:
        token = authorization.strip()

    if token and token in active_sessions:
        del active_sessions[token]

    return {"status": "success", "success": True, "message": "Logged out successfully"}


@app.get("/api/auth/me")
def get_current_admin(authorization: str = Header(None)):
    user_data = get_user_from_token(authorization)
    if not user_data:
        raise HTTPException(status_code=401, detail="Not authenticated or session expired")
    return user_data


# -------------------------
# Multi-Device Management Endpoints
# -------------------------

@app.get("/api/devices")
def get_all_devices():
    """
    Returns an overview list of all known IoT devices (registered + observed in telemetry),
    with their latest security status, firmware status, ML observation, threat, and risk score.
    """
    db = SessionLocal()
    try:
        registered = {d.device_id: d for d in db.query(Device).all()}
        telemetry_devices = [r[0] for r in db.query(Telemetry.device_id).distinct().all() if r[0]]

        all_device_ids = list(dict.fromkeys(list(registered.keys()) + telemetry_devices))
        if not all_device_ids:
            all_device_ids = ["ESP8266-01"]

        device_list = []
        for dev_id in all_device_ids:
            reg = registered.get(dev_id)
            latest_tel = db.query(Telemetry).filter(Telemetry.device_id == dev_id).order_by(Telemetry.id.desc()).first()
            sm = get_or_create_state_machine(dev_id, db)

            if latest_tel:
                sec_status = latest_tel.security_status or ("trusted" if reg else "suspicious")
                fw_status = latest_tel.firmware_status or ("valid" if reg else "unregistered")
                ml_det = latest_tel.ml_detection or "NORMAL"
                thr = latest_tel.threat or ("NONE" if reg else "ROGUE_DEVICE")
                score = latest_tel.anomaly_score
                last_seen = str(latest_tel.timestamp)
                mac = latest_tel.mac or (reg.mac if reg else "UNKNOWN")
                ip = latest_tel.ip or (reg.ip if reg else "UNKNOWN")
                fw_ver = latest_tel.firmware or (reg.firmware if reg else "1.0.0")
                fw_md5 = latest_tel.firmware_md5 or (reg.firmware_md5 if reg else "")
                packet_rate = latest_tel.packet_rate
                free_heap = latest_tel.free_heap
                rssi = latest_tel.rssi
                beh = {
                    "packet_rate": latest_tel.packet_rate,
                    "request_rate": latest_tel.request_rate,
                    "free_heap": latest_tel.free_heap,
                    "heap_change": latest_tel.heap_change,
                    "rssi_change": latest_tel.rssi_change,
                    "uptime_gap": latest_tel.uptime_gap
                }
            else:
                sec_status = "trusted" if reg else "suspicious"
                fw_status = "valid" if reg else "unregistered"
                ml_det = "NORMAL"
                thr = "NONE" if reg else "ROGUE_DEVICE"
                score = 0.18
                last_seen = str(reg.registered_at) if reg else "--"
                mac = reg.mac if reg else "UNKNOWN"
                ip = reg.ip if reg else "UNKNOWN"
                fw_ver = reg.firmware if reg else "1.0.0"
                fw_md5 = reg.firmware_md5 if reg else ""
                packet_rate = 0.2
                free_heap = 49500
                rssi = -28.0
                beh = {}

            risk = calculate_risk_score(sec_status, fw_status, thr, ml_det, score, beh, sm_state=sm.state)

            device_list.append({
                "device_id": dev_id,
                "mac": mac,
                "ip": ip,
                "firmware": fw_ver,
                "firmware_md5": fw_md5,
                "is_registered": reg is not None,
                "identity_status": "REGISTERED" if reg else "UNREGISTERED",
                "registered_status": reg.status if reg else "unregistered",
                "registered_at": str(reg.registered_at) if reg else None,
                "security_status": sec_status,
                "firmware_status": fw_status,
                "ml_detection": ml_det,
                "ml_observation": ml_det,
                "behavior_status": "PERSISTENT ANOMALY" if sm.anomaly_streak >= ANOMALY_CONFIRMATION_COUNT else ("ISOLATED ANOMALY" if sm.anomaly_streak > 0 else ("RECOVERING" if sm.state == "RECOVERING" else "NORMAL")),
                "anomaly_streak": sm.anomaly_streak,
                "anomaly_confirmation_count": ANOMALY_CONFIRMATION_COUNT,
                "threat": thr,
                "anomaly_score": round(score, 4) if score is not None else 0.18,
                "risk_score": risk["risk_score"],
                "risk_level": risk["risk_level"],
                "risk_factors": risk["risk_factors"],
                "packet_rate": packet_rate,
                "free_heap": free_heap,
                "rssi": rssi,
                "last_seen": last_seen
            })

        return device_list
    finally:
        db.close()


@app.get("/api/devices/latest")
def get_latest_device(device_id: str = None):
    db = SessionLocal()
    try:
        target_id = device_id or "ESP8266-01"
        reg = None
        if target_id and target_id != "all":
            reg = db.query(Device).filter(Device.device_id == target_id).first()

        query = db.query(Telemetry)
        if target_id and target_id != "all":
            query = query.filter(Telemetry.device_id == target_id)

        telemetry = query.order_by(Telemetry.id.desc()).first()
        sm = get_or_create_state_machine(target_id, db)

        if not telemetry:
            if reg:
                return {
                    "status": "ready",
                    "device_id": reg.device_id,
                    "mac": reg.mac,
                    "ip": reg.ip or "--",
                    "rssi": "--",
                    "free_heap": "--",
                    "uptime": "--",
                    "firmware": reg.firmware or "1.0.0",
                    "firmware_md5": reg.firmware_md5 or "--",
                    "packet_count": 0,
                    "request_count": 0,
                    "is_registered": True,
                    "identity_status": "REGISTERED",
                    "security_status": "trusted",
                    "firmware_status": "valid",
                    "threat": "NONE",
                    "ml_detection": "NORMAL",
                    "ml_observation": "NORMAL",
                    "behavior_status": "NORMAL",
                    "anomaly_score": 0.18,
                    "anomaly_streak": 0,
                    "anomaly_confirmation_count": ANOMALY_CONFIRMATION_COUNT,
                    "recovery_streak": 0,
                    "recovery_count": RECOVERY_COUNT,
                    "anomaly_reason": "Device is registered. Waiting for initial telemetry broadcast.",
                    "evidence": {
                        "anomaly_streak": 0,
                        "anomaly_threshold": ANOMALY_CONFIRMATION_COUNT,
                        "normal_streak": 0,
                        "recovery_threshold": RECOVERY_COUNT,
                        "anomaly_score": 0.18,
                        "packet_rate": 0.0,
                        "free_heap": 49000,
                        "heap_change": 0,
                        "rssi": -28.0,
                        "rssi_change": 0.0,
                        "uptime_gap": 0,
                        "state": "TRUSTED"
                    },
                    "recent_observations": sm.recent_observations,
                    "risk_score": 0,
                    "risk_level": "LOW",
                    "risk_factors": [],
                    "packet_rate": 0.0,
                    "request_rate": 0.0,
                    "heap_change": 0,
                    "rssi_change": 0.0,
                    "uptime_gap": 0,
                    "timestamp": "No telemetry received yet"
                }

            return {
                "status": "no_data",
                "device_id": target_id,
                "message": f"No telemetry received yet for '{target_id}'"
            }

        if not reg:
            reg = db.query(Device).filter(Device.mac == telemetry.mac).first()

        beh = {
            "packet_rate": telemetry.packet_rate,
            "request_rate": telemetry.request_rate,
            "free_heap": telemetry.free_heap,
            "heap_change": telemetry.heap_change,
            "rssi_change": telemetry.rssi_change,
            "uptime_gap": telemetry.uptime_gap,
            "rssi": telemetry.rssi
        }

        risk = calculate_risk_score(
            telemetry.security_status,
            telemetry.firmware_status,
            telemetry.threat,
            telemetry.ml_detection,
            telemetry.anomaly_score,
            beh,
            sm_state=sm.state
        )

        behavior_status = "PERSISTENT ANOMALY" if sm.anomaly_streak >= ANOMALY_CONFIRMATION_COUNT else (
            "ISOLATED ANOMALY" if sm.anomaly_streak > 0 else (
                "RECOVERING" if sm.state == "RECOVERING" else "NORMAL"
            )
        )

        evidence = sm.last_evidence or {
            "anomaly_streak": sm.anomaly_streak,
            "anomaly_threshold": ANOMALY_CONFIRMATION_COUNT,
            "normal_streak": sm.normal_streak,
            "recovery_threshold": RECOVERY_COUNT,
            "anomaly_score": round(telemetry.anomaly_score, 4) if telemetry.anomaly_score is not None else 0.18,
            "packet_rate": round(telemetry.packet_rate, 2) if telemetry.packet_rate is not None else 0.2,
            "free_heap": telemetry.free_heap if telemetry.free_heap is not None else 49000,
            "heap_change": telemetry.heap_change if telemetry.heap_change is not None else 0,
            "rssi": telemetry.rssi if telemetry.rssi is not None else -28.0,
            "rssi_change": round(telemetry.rssi_change, 2) if telemetry.rssi_change is not None else 0.0,
            "uptime_gap": telemetry.uptime_gap if telemetry.uptime_gap is not None else 0,
            "state": sm.state
        }

        prev_uptime = None
        if telemetry.uptime_gap == 1:
            prev_t = db.query(Telemetry).filter(
                Telemetry.device_id == telemetry.device_id,
                Telemetry.id < telemetry.id
            ).order_by(Telemetry.id.desc()).first()
            if prev_t and prev_t.uptime is not None:
                prev_uptime = prev_t.uptime

        return {
            "status": "ok",
            "device_id": telemetry.device_id,
            "mac": telemetry.mac,
            "ip": telemetry.ip or (reg.ip if reg else "--"),
            "rssi": telemetry.rssi,
            "free_heap": telemetry.free_heap,
            "uptime": telemetry.uptime,
            "current_uptime": telemetry.uptime,
            "previous_uptime": prev_uptime,
            "firmware": telemetry.firmware or (reg.firmware if reg else "1.0.0"),
            "expected_firmware_md5": reg.firmware_md5 if reg else "--",
            "firmware_md5": telemetry.firmware_md5 or (reg.firmware_md5 if reg else "--"),
            "packet_count": telemetry.packet_count,
            "request_count": telemetry.request_count,
            "is_registered": reg is not None,
            "identity_status": "REGISTERED" if reg else "UNREGISTERED",
            "security_status": telemetry.security_status,
            "firmware_status": telemetry.firmware_status,
            "threat": telemetry.threat,
            "ml_detection": telemetry.ml_detection,
            "ml_observation": telemetry.ml_detection,
            "behavior_status": behavior_status,
            "anomaly_score": round(telemetry.anomaly_score, 4) if telemetry.anomaly_score is not None else 0.18,
            "anomaly_streak": sm.anomaly_streak,
            "anomaly_confirmation_count": ANOMALY_CONFIRMATION_COUNT,
            "recovery_streak": sm.normal_streak,
            "recovery_count": RECOVERY_COUNT,
            "anomaly_reason": getattr(telemetry, "anomaly_reason", None) or sm.last_reason or "Device behavior is within normal baseline.",
            "evidence": evidence,
            "recent_observations": sm.recent_observations,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "risk_factors": risk["risk_factors"],
            "packet_rate": telemetry.packet_rate,
            "request_rate": telemetry.request_rate,
            "heap_change": telemetry.heap_change,
            "rssi_change": telemetry.rssi_change,
            "uptime_gap": telemetry.uptime_gap,
            "timestamp": str(telemetry.timestamp)
        }
    finally:
        db.close()


@app.post("/api/devices/register")
def register_device(data: dict):

    db = SessionLocal()
    try:
        mac = data.get("mac")
        device_id = data.get("device_id")
        ip = data.get("ip") or "10.0.0.1"
        fw = data.get("firmware_version") or data.get("firmware") or "1.0.0"
        md5 = data.get("expected_firmware_md5") or data.get("firmware_md5") or ""

        if not device_id or not mac:
            raise HTTPException(status_code=400, detail="device_id and mac are required")

        existing = db.query(Device).filter(
            (Device.mac == mac) | (Device.device_id == device_id)
        ).first()

        # If device already exists, update its information
        if existing:
            existing.device_id = device_id
            existing.mac = mac
            existing.ip = ip
            existing.firmware = fw
            if md5:
                existing.firmware_md5 = md5
            existing.status = "trusted"

            db.commit()

            return {
                "status": "updated",
                "success": True,
                "message": f"Device '{device_id}' updated successfully",
                "device_id": existing.device_id,
                "mac": existing.mac,
                "firmware_md5": existing.firmware_md5
            }

        # Register new device
        device = Device(
            device_id=device_id,
            mac=mac,
            ip=ip,
            firmware=fw,
            firmware_md5=md5,
            status="trusted",
            registered_at=datetime.now()
        )

        db.add(device)
        db.commit()
        db.refresh(device)

        return {
            "status": "registered",
            "success": True,
            "message": f"Device '{device.device_id}' registered successfully",
            "device_id": device.device_id,
            "mac": device.mac,
            "firmware_md5": device.firmware_md5
        }
    finally:
        db.close()


@app.get("/api/devices/{device_id}")
def get_device_details(device_id: str):
    db = SessionLocal()
    try:
        reg = db.query(Device).filter(Device.device_id == device_id).first()
        latest_tel = db.query(Telemetry).filter(Telemetry.device_id == device_id).order_by(Telemetry.id.desc()).first()

        if not reg and not latest_tel:
            raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found")

        sec_status = latest_tel.security_status if latest_tel else ("trusted" if reg else "suspicious")
        fw_status = latest_tel.firmware_status if latest_tel else ("valid" if reg else "unregistered")
        ml_det = latest_tel.ml_detection if latest_tel else "NORMAL"
        thr = latest_tel.threat if latest_tel else ("NONE" if reg else "ROGUE_DEVICE")
        score = latest_tel.anomaly_score if latest_tel else 0.18

        beh = {
            "packet_rate": latest_tel.packet_rate,
            "request_rate": latest_tel.request_rate,
            "free_heap": latest_tel.free_heap,
            "heap_change": latest_tel.heap_change,
            "rssi_change": latest_tel.rssi_change,
            "uptime_gap": latest_tel.uptime_gap
        } if latest_tel else {}

        risk = calculate_risk_score(sec_status, fw_status, thr, ml_det, score, beh)

        return {
            "device_id": device_id,
            "mac": reg.mac if reg else (latest_tel.mac if latest_tel else "UNKNOWN"),
            "ip": reg.ip if reg else (latest_tel.ip if latest_tel else "UNKNOWN"),
            "firmware": reg.firmware if reg else (latest_tel.firmware if latest_tel else "1.0.0"),
            "firmware_md5": reg.firmware_md5 if reg else (latest_tel.firmware_md5 if latest_tel else ""),
            "is_registered": reg is not None,
            "registered_at": str(reg.registered_at) if reg else None,
            "security_status": sec_status,
            "firmware_status": fw_status,
            "ml_detection": ml_det,
            "threat": thr,
            "anomaly_score": round(score, 4) if score is not None else None,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "risk_factors": risk["risk_factors"],
            "last_seen": str(latest_tel.timestamp) if latest_tel else None
        }
    finally:
        db.close()


@app.delete("/api/devices/{device_id}")
def delete_device(device_id: str):
    db = SessionLocal()
    try:
        reg = db.query(Device).filter(Device.device_id == device_id).first()
        if not reg:
            raise HTTPException(status_code=404, detail=f"Device '{device_id}' is not in registered registry")
        db.delete(reg)
        db.commit()
        return {
            "status": "deleted",
            "success": True,
            "message": f"Device '{device_id}' unregistered successfully"
        }
    finally:
        db.close()


@app.get("/api/devices/{device_id}/telemetry")
def get_device_telemetry(device_id: str):
    return get_latest_device(device_id=device_id)


# -------------------------
# Detection History Endpoints
# -------------------------

@app.get("/api/history")
def get_history(limit: int = 100, format: str = None, device_id: str = None):

    db = SessionLocal()
    try:
        limit = max(1, min(limit, 500))
        query = db.query(Telemetry)
        if device_id and device_id != "all":
            query = query.filter(Telemetry.device_id == device_id)

        records = query.order_by(Telemetry.id.desc()).limit(limit).all()

        events = []
        for r in records:
            ev_type = "NORMAL"
            if r.threat == "FIRMWARE_TAMPERED" or (r.firmware_status and (r.firmware_status.upper() == "FIRMWARE_TAMPERED" or r.firmware_status.lower() == "tampered")):
                ev_type = "FIRMWARE_TAMPERED"
            elif r.threat == "ROGUE_DEVICE":
                ev_type = "ROGUE_DEVICE"
            elif r.threat == "UNEXPECTED_REBOOT" or r.uptime_gap == 1:
                ev_type = "UNEXPECTED_REBOOT"
            elif r.threat == "BEHAVIOR_ANOMALY" or r.ml_detection == "ANOMALY":
                ev_type = "BEHAVIOR_ANOMALY"

            reason = getattr(r, "anomaly_reason", None) or explain_anomaly(
                {"packet_rate": r.packet_rate, "request_rate": r.request_rate, "free_heap": r.free_heap, "heap_change": r.heap_change, "rssi_change": r.rssi_change, "uptime_gap": r.uptime_gap, "uptime": r.uptime},
                r.ml_detection,
                threat=r.threat
            )

            severity = "low"
            if ev_type in ["FIRMWARE_TAMPERED", "ROGUE_DEVICE"]:
                severity = "critical"
            elif ev_type == "BEHAVIOR_ANOMALY":
                severity = "high"
            elif ev_type == "UNEXPECTED_REBOOT":
                severity = "medium"

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
                "anomaly_reason": reason,
                "ml_detection": r.ml_detection or "NORMAL",
                "security_status": r.security_status or "trusted",
                "firmware_status": r.firmware_status or "valid",
                "threat": r.threat or ("UNEXPECTED_REBOOT" if ev_type == "UNEXPECTED_REBOOT" else "NONE"),
                "event_type": ev_type,
                "event": ev_type,
                "severity": severity
            })

        if format == "dict":
            return {
                "count": len(events),
                "events": events
            }

        return events
    finally:
        db.close()


@app.get("/api/devices/{device_id}/history")
def get_device_history(device_id: str, limit: int = 100):
    return get_history(limit=limit, device_id=device_id)


@app.get("/api/history/summary")
def get_history_summary(device_id: str = None):

    db = SessionLocal()
    try:
        query = db.query(Telemetry)
        if device_id and device_id != "all":
            query = query.filter(Telemetry.device_id == device_id)

        total_events = query.count()
        normal_events = query.filter(
            Telemetry.threat == "NONE",
            (Telemetry.ml_detection == "NORMAL") | (Telemetry.ml_detection == None)
        ).count()
        anomaly_events = total_events - normal_events
        rogue_devices = query.filter(Telemetry.threat == "ROGUE_DEVICE").count()
        firmware_tampered = query.filter(Telemetry.threat == "FIRMWARE_TAMPERED").count()
        behavior_anomalies = query.filter(Telemetry.threat == "BEHAVIOR_ANOMALY").count()

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


def run_simulation(sim_type: str, target_device_id: str = None):

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
        now = datetime.now()

        # Target Device Selection
        if target_device_id and target_device_id != "all":
            device = db.query(Device).filter(Device.device_id == target_device_id).first()
            device_id = target_device_id
            mac = device.mac if device else f"simulate:{target_device_id}"
            ip = device.ip if device else "10.0.0.99"
            valid_md5 = device.firmware_md5 if device else "simulated_baseline_md5_hash"
            valid_firmware = device.firmware if device else "1.0.0"
        else:
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
        if not device:
            identity_status = "UNREGISTERED"
            firmware_status = "UNKNOWN"
            expected_md5 = "--"
            threat = "ROGUE_DEVICE"
        elif sim_type == "firmware_tamper":
            identity_status = "REGISTERED"
            expected_md5 = device.firmware_md5 or valid_md5
            firmware_status = "FIRMWARE_TAMPERED"
            threat = "FIRMWARE_TAMPERED"
        else:
            identity_status = "REGISTERED"
            expected_md5 = device.firmware_md5 or valid_md5
            firmware_status = "VALID"
            threat = "NONE"

        # Pipeline Step 2: ML Behavioral evaluation
        features = {
            "rssi": base_rssi,
            "free_heap": base_heap,
            "uptime": base_uptime,
            "packet_rate": base_packet_rate,
            "request_rate": base_request_rate,
            "heap_change": base_heap_change,
            "rssi_change": base_rssi_change,
            "uptime_gap": base_uptime_gap,
            "previous_uptime": 3200 if base_uptime_gap == 1 else None,
            "current_uptime": base_uptime,
            "expected_firmware_md5": expected_md5,
            "reported_firmware_md5": current_md5
        }

        ml_status, anomaly_score = predict_anomaly(features)
        detection_display = "ANOMALY" if sim_type in ["firmware_tamper", "reboot_anomaly", "traffic_spike", "memory_stress", "signal_anomaly", "combined_anomaly"] else ml_status

        # Pipeline Step 3: State Machine Update
        sm = get_or_create_state_machine(device_id, db)
        sm_state, sm_reason, sm_evidence = sm.process_observation(detection_display, anomaly_score, features, now)

        if not device:
            security_status = "rogue"
            threat = "ROGUE_DEVICE"
            event_type = "ROGUE_DEVICE"
            anomaly_reason = "Unregistered or unauthorized hardware identity detected on network."
            behavior_status = "UNREGISTERED"
        elif firmware_status == "FIRMWARE_TAMPERED":
            security_status = "suspicious"
            threat = "FIRMWARE_TAMPERED"
            event_type = "FIRMWARE_TAMPERED"
            anomaly_reason = f"Firmware MD5 mismatch detected (Expected: {expected_md5}, Reported: {current_md5})."
            behavior_status = "TAMPERED"
        elif sim_type == "reboot_anomaly" or base_uptime_gap == 1:
            security_status = "monitoring"
            threat = "UNEXPECTED_REBOOT"
            event_type = "UNEXPECTED_REBOOT"
            anomaly_reason = "Unexpected device reboot detected (Previous uptime: 3200s, Current uptime: 2s)."
            behavior_status = "REBOOT DETECTED"
        else:
            if sm_state == "SUSPICIOUS":
                security_status = "suspicious"
                threat = "BEHAVIOR_ANOMALY"
                behavior_status = "PERSISTENT ANOMALY"
                event_type = "BEHAVIOR_ANOMALY"
                anomaly_reason = explain_anomaly(features, detection_display, sim_type=sim_type, threat=threat)
            elif sm_state == "MONITORING":
                security_status = "monitoring"
                threat = "NONE"
                behavior_status = "ISOLATED ANOMALY"
                event_type = "MONITORING"
                anomaly_reason = f"Simulated single anomaly detected ({sm.anomaly_streak}/{ANOMALY_CONFIRMATION_COUNT}). Security status remains MONITORING."
            else:
                security_status = "trusted"
                threat = "NONE"
                behavior_status = "NORMAL"
                event_type = "NORMAL"
                anomaly_reason = "Device behavior is within normal baseline."

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
            anomaly_reason=anomaly_reason,
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
            anomaly_reason=anomaly_reason,
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
            is_simulation=True,
            anomaly_reason=anomaly_reason
        )

        db.commit()

        # Risk score
        risk = calculate_risk_score(security_status, firmware_status, threat, detection_display, anomaly_score, features, sm_state=sm_state)

        return {
            "simulation_type": sim_type.upper(),
            "device_id": device_id,
            "detection": detection_display,
            "threat": threat,
            "anomaly_score": round(anomaly_score, 4) if anomaly_score is not None else 0.18,
            "anomaly_reason": anomaly_reason,
            "security_status": security_status,
            "firmware_status": firmware_status,
            "identity_status": identity_status,
            "behavior_status": behavior_status,
            "anomaly_streak": sm.anomaly_streak,
            "anomaly_confirmation_count": ANOMALY_CONFIRMATION_COUNT,
            "recovery_streak": sm.normal_streak,
            "recovery_count": RECOVERY_COUNT,
            "evidence": sm_evidence,
            "recent_observations": sm.recent_observations,
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
            "risk_factors": risk["risk_factors"],
            "behavioral_features": features,
            "ml_detection": detection_display,
            "ml_observation": detection_display,
            "type": sim_type,
            "event_type": event_type,
            "simulation": True
        }
    finally:
        db.close()


@app.post("/api/simulate/{simulation_type}")
def simulate_attack_by_path(simulation_type: str, device_id: str = None):
    return run_simulation(simulation_type, target_device_id=device_id)


@app.post("/api/simulate")
def simulate_attack_by_body(data: dict = None):
    sim_type = data.get("type") if (data and isinstance(data, dict)) else None
    dev_id = data.get("device_id") if (data and isinstance(data, dict)) else None
    if not sim_type:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Missing simulation type in JSON body",
                "supported_types": list(SIMULATION_TYPES.keys())
            }
        )
    return run_simulation(sim_type, target_device_id=dev_id)


# -------------------------
# Security Alerts Endpoints
# -------------------------

@app.get("/api/alerts")
def get_security_alerts(limit: int = 50, severity: str = None, device_id: str = None):

    db = SessionLocal()
    try:
        limit = max(1, min(limit, 200))
        query = db.query(SecurityAlert)
        if severity:
            query = query.filter(SecurityAlert.severity == severity.upper())
        if device_id and device_id != "all":
            query = query.filter(SecurityAlert.device_id == device_id)

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
                "anomaly_reason": a.anomaly_reason or a.description,
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
def get_security_alerts_stats(device_id: str = None):

    db = SessionLocal()
    try:
        query = db.query(SecurityAlert)
        if device_id and device_id != "all":
            query = query.filter(SecurityAlert.device_id == device_id)

        total = query.count()
        critical = query.filter(SecurityAlert.severity == "CRITICAL").count()
        high = query.filter(SecurityAlert.severity == "HIGH").count()
        medium = query.filter(SecurityAlert.severity == "MEDIUM").count()
        low = query.filter(SecurityAlert.severity == "LOW").count()

        return {
            "total_alerts": total,
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low
        }
    finally:
        db.close()
