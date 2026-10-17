import sqlite3
import pandas as pd

DB_PATH = "iot_security.db"

conn = sqlite3.connect(DB_PATH)

query = """
SELECT
    rssi,
    free_heap,
    uptime,
    packet_count,
    request_count
FROM telemetry
ORDER BY timestamp
"""

df = pd.read_sql_query(query, conn)

conn.close()

# Calculate behavioral features
df["packet_rate"] = df["packet_count"].diff() / df["uptime"].diff()
df["request_rate"] = df["request_count"].diff() / df["uptime"].diff()

df["heap_change"] = df["free_heap"].diff()
df["rssi_change"] = df["rssi"].diff()

df["uptime_gap"] = (
    df["uptime"].diff() < 0
).astype(int)

# Keep only ML features
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

df = df[features]

# Remove first row and invalid values
df = df.dropna()

# Save dataset
df.to_csv("ml/normal_behavior.csv", index=False)

print("Dataset created successfully!")
print("Samples:", len(df))
print("\nFirst 5 samples:")
print(df.head())

print("\nSaved to:")
print("ml/normal_behavior.csv")