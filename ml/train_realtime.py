import os
import sys
import joblib
import pandas as pd

from sqlalchemy import create_engine
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ==========================================
# Database
# ==========================================

DATABASE_URL = "sqlite:///./iot_security.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# ==========================================
# Load REAL telemetry
# ==========================================

query = """
SELECT
    rssi,
    free_heap,
    uptime,
    packet_rate,
    request_rate,
    heap_change,
    rssi_change,
    uptime_gap
FROM telemetry
WHERE uptime_gap = 0
"""

df = pd.read_sql(query, engine)

print("========================================")
print(" REAL-TIME TELEMETRY TRAINING")
print("========================================")
print("Training samples:", len(df))

if len(df) < 20:
    print()
    print("Not enough telemetry data.")
    print("Collect at least 20-50 normal samples first.")
    sys.exit()

features = [
    "rssi",
    "free_heap",
    "uptime",
    "packet_rate",
    "request_rate",
    "heap_change",
    "rssi_change",
    "uptime_gap"
]

X = df[features]

print("Features per sample:", len(features))

# ==========================================
# Scale features
# ==========================================

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ==========================================
# Train Isolation Forest
# ==========================================

model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42
)

model.fit(X_scaled)

# ==========================================
# Save model
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model_path = os.path.join(BASE_DIR, "anomaly_model.pkl")
scaler_path = os.path.join(BASE_DIR, "scaler.pkl")

joblib.dump(model, model_path)
joblib.dump(scaler, scaler_path)

print()
print("Training completed!")
print("Model saved:")
print(model_path)
print("Scaler saved:")
print(scaler_path)

predictions = model.predict(X_scaled)

print()
print("Predictions:")
print(predictions)
print()
print("1  = NORMAL")
print("-1 = ANOMALY")
print()
print("========================================")
print(" REAL TELEMETRY MODEL READY")
print("========================================")
