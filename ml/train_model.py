import os
import pandas as pd
import joblib

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_PATH = os.path.join(
    BASE_DIR,
    "normal_behavior.csv"
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "anomaly_model.pkl"
)

SCALER_PATH = os.path.join(
    BASE_DIR,
    "scaler.pkl"
)


# Load real ESP8266 telemetry
df = pd.read_csv(DATA_PATH)

print("Real telemetry samples:", len(df))

# Features
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


# Scale
scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)


# Train anomaly detector
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42
)

model.fit(X_scaled)


# Save
joblib.dump(model, MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)


print("\nTraining completed!")
print("Samples:", len(X))
print("Model:", MODEL_PATH)
print("Scaler:", SCALER_PATH)