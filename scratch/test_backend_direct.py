import sys
import os
sys.path.insert(0, r"c:\Users\devar\Downloads\iot-security\backend")

from main import (
    app,
    health_check,
    receive_device,
    get_latest_device,
    get_all_devices,
    get_history,
    get_history_summary,
    get_security_alerts,
    get_security_alerts_stats,
    run_simulation,
    SIMULATION_TYPES
)

print("=== 1. Testing health_check() ===")
h = health_check()
print("Health:", h)
assert h["status"] == "online"

print("\n=== 2. Testing receive_device() ===")
sample_telemetry = {
    "device_id": "ESP8266-01",
    "mac": "60:01:94:73:34:00",
    "ip": "10.214.179.156",
    "rssi": -26.0,
    "free_heap": 49576,
    "uptime": 1700,
    "firmware": "1.0.0",
    "firmware_md5": "3b27ec70c26f9ef3aa13e053336e550c",
    "packet_count": 338,
    "request_count": 338
}
rec = receive_device(sample_telemetry)
print("Receive result:", rec)
assert rec["status"] == "received"
assert rec["device_id"] == "ESP8266-01"
assert "security_status" in rec
assert "firmware_status" in rec
assert "ml_detection" in rec
assert "risk_score" in rec

print("\n=== 3. Testing get_latest_device('ESP8266-01') ===")
lat = get_latest_device("ESP8266-01")
print("Latest device data:", lat)
assert lat["status"] == "ok"
assert lat["device_id"] == "ESP8266-01"
assert lat["mac"] == "60:01:94:73:34:00"
assert lat["firmware"] == "1.0.0"
assert lat["free_heap"] == 49576
assert lat["rssi"] == -26.0
assert lat["uptime"] == 1700
assert lat["packet_count"] == 338
assert lat["request_count"] == 338
assert "risk_score" in lat
assert "risk_level" in lat
assert "botnet_status" not in lat
assert "botnet_group" not in lat

print("\n=== 4. Testing get_all_devices() ===")
devs = get_all_devices()
print(f"All devices count: {len(devs)}")
assert any(d["device_id"] == "ESP8266-01" for d in devs)
for d in devs:
    assert "botnet_status" not in d
    assert "botnet_group" not in d
    assert "botnet_score" not in d

print("\n=== 5. Testing get_history() ===")
hist = get_history(limit=10, device_id="ESP8266-01")
print(f"History count: {len(hist)}")
assert len(hist) > 0

print("\n=== 6. Testing get_history_summary() ===")
summ = get_history_summary(device_id="ESP8266-01")
print("Summary:", summ)
assert "total_events" in summ

print("\n=== 7. Testing get_security_alerts() and get_security_alerts_stats() ===")
alerts = get_security_alerts(device_id="ESP8266-01")
print(f"Alerts count: {len(alerts)}")
stats = get_security_alerts_stats(device_id="ESP8266-01")
print("Alert stats:", stats)
assert "total_alerts" in stats

print("\n=== 8. Testing run_simulation('traffic_spike') ===")
sim = run_simulation("traffic_spike", target_device_id="ESP8266-01")
print("Sim result:", sim)
assert sim["simulation"] is True
assert sim["detection"] == "ANOMALY"

print("\n=== 9. Testing SIMULATION_TYPES dictionary ===")
print("Simulation types available:", list(SIMULATION_TYPES.keys()))
assert "botnet" not in SIMULATION_TYPES
assert "traffic_spike" in SIMULATION_TYPES
assert "memory_stress" in SIMULATION_TYPES
assert "signal_anomaly" in SIMULATION_TYPES
assert "reboot_anomaly" in SIMULATION_TYPES
assert "combined_anomaly" in SIMULATION_TYPES
assert "firmware_tamper" in SIMULATION_TYPES

print("\n=== 10. Checking FastAPI Routes ===")
routes = [route.path for route in app.routes]
print("Registered routes:")
for r in sorted(routes):
    print(" ", r)

# Assert no botnet routes
assert not any("botnet" in r for r in routes), "Found botnet route!"
assert not any("profile" in r for r in routes), "Found profile route!"

print("\n>>> ALL 10 VERIFICATION CHECKS PASSED PERFECTLY! <<<")
