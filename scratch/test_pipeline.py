import sys
import os

# Add root directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.main import (
    app,
    SessionLocal,
    Device,
    Telemetry,
    receive_device,
    get_latest_device,
    get_all_devices,
    get_history,
    run_simulation,
    get_or_create_state_machine,
    ANOMALY_CONFIRMATION_COUNT,
    RECOVERY_COUNT
)

def run_tests():
    print("==================================================")
    print("STARTING TEST SUITE FOR REAL-TIME ML & STATE MACHINE")
    print("==================================================")

    # 1. Get registered device and its baseline MD5
    db = SessionLocal()
    dev = db.query(Device).filter(Device.device_id == "ESP8266-01").first()
    if not dev:
        dev = Device(
            device_id="ESP8266-01",
            mac="60:01:94:73:34:00",
            ip="10.214.179.156",
            firmware="1.0.0",
            firmware_md5="ec5d16ed40b1d58538a1d4e8a2deb7fa",
            status="trusted"
        )
        db.add(dev)
        db.commit()
    
    valid_md5 = dev.firmware_md5
    dev_mac = dev.mac
    db.close()

    # Reset state machine for clean test
    sm = get_or_create_state_machine("ESP8266-01")
    sm.state = "TRUSTED"
    sm.anomaly_streak = 0
    sm.normal_streak = 0

    print("\n[TEST 1] Sending 3 Normal Telemetry Packets...")
    for i in range(3):
        data = receive_device({
            "device_id": "ESP8266-01",
            "mac": dev_mac,
            "ip": "10.214.179.156",
            "rssi": -28.0,
            "free_heap": 49500,
            "uptime": 100 + i * 5,
            "firmware": "1.0.0",
            "firmware_md5": valid_md5,
            "packet_count": 500 + i,
            "request_count": 500 + i
        })
        print(f"  Sample {i+1}: ML Observation = {data['ml_observation']}, Security Posture = {data['security_status']}, Streak = {data['anomaly_streak']}/{data['anomaly_confirmation_count']}")
        assert data["ml_observation"] == "NORMAL"
        assert data["security_status"] == "trusted"
        assert data["anomaly_streak"] == 0

    print(">>> TEST 1 PASSED: Normal telemetry stays stable as TRUSTED.\n")

    print("[TEST 2] Sending 1 Isolated Anomalous Packet (Traffic Spike & Memory Depletion)...")
    data = receive_device({
        "device_id": "ESP8266-01",
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -28.0,
        "free_heap": 35000,
        "uptime": 115,
        "firmware": "1.0.0",
        "firmware_md5": valid_md5,
        "packet_count": 1102,   # 120 pkts/sec
        "request_count": 1102
    })
    print(f"  Result: ML Observation = {data['ml_observation']}, Security Posture = {data['security_status']}, Streak = {data['anomaly_streak']}/{data['anomaly_confirmation_count']}")
    print(f"  Reason: {data['anomaly_reason']}")
    assert data["ml_observation"] == "ANOMALY"
    assert data["security_status"] == "monitoring", f"Expected 'monitoring', got {data['security_status']}"
    assert data["anomaly_streak"] == 1
    print(">>> TEST 2 PASSED: 1 Anomaly observation changes state to MONITORING, NOT immediately SUSPICIOUS.\n")

    print("[TEST 3] Sending 2 More Consecutive Anomalous Packets...")
    for i in range(2):
        data = receive_device({
            "device_id": "ESP8266-01",
            "mac": dev_mac,
            "ip": "10.214.179.156",
            "rssi": -28.0,
            "free_heap": 30000 - i * 5000,
            "uptime": 120 + i * 5,
            "firmware": "1.0.0",
            "firmware_md5": valid_md5,
            "packet_count": 1702 + i * 600,
            "request_count": 1702 + i * 600
        })
        print(f"  Anomaly #{i+2}: ML Observation = {data['ml_observation']}, Security Posture = {data['security_status']}, Streak = {data['anomaly_streak']}/{data['anomaly_confirmation_count']}")
        print(f"  Reason: {data['anomaly_reason']}")

    assert data["anomaly_streak"] == 3
    assert data["security_status"] == "suspicious"
    assert data["behavior_status"] == "PERSISTENT ANOMALY"
    print(">>> TEST 3 PASSED: 3 Consecutive Anomalies escalate Security Status to SUSPICIOUS.\n")

    print("[TEST 4] Sending 1 Normal Packet after SUSPICIOUS (Recovery 1/3)...")
    data = receive_device({
        "device_id": "ESP8266-01",
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -28.0,
        "free_heap": 25000,
        "uptime": 130,
        "firmware": "1.0.0",
        "firmware_md5": valid_md5,
        "packet_count": 2303,  # 1 packet in 5s (0.2 pkts/sec)
        "request_count": 2303
    })
    print(f"  Normal #1: ML Observation = {data['ml_observation']}, Security Posture = {data['security_status']}, Recovery Streak = {data['recovery_streak']}/{data['recovery_count']}")
    print(f"  Reason: {data['anomaly_reason']}")
    assert data["ml_observation"] == "NORMAL"
    assert data["security_status"] in ["recovering", "suspicious"]
    assert data["recovery_streak"] == 1
    print(">>> TEST 4 PASSED: 1 Normal sample does NOT immediately jump to TRUSTED.\n")

    print("[TEST 5] Sending 2 More Normal Packets to Reach Recovery Threshold (3/3 normal samples)...")
    for i in range(2):
        data = receive_device({
            "device_id": "ESP8266-01",
            "mac": dev_mac,
            "ip": "10.214.179.156",
            "rssi": -28.0,
            "free_heap": 25000,
            "uptime": 135 + i * 5,
            "firmware": "1.0.0",
            "firmware_md5": valid_md5,
            "packet_count": 2304 + i,
            "request_count": 2304 + i
        })
        print(f"  Normal #{i+2}: ML Observation = {data['ml_observation']}, Security Posture = {data['security_status']}, Recovery Streak = {data['recovery_streak']}/{data['recovery_count']}")
        print(f"  Reason: {data['anomaly_reason']}")

    assert data["security_status"] == "trusted"
    assert data["recovery_streak"] == 3
    print(">>> TEST 5 PASSED: Recovery to TRUSTED requires 3 verified consecutive normal samples.\n")

    print("[TEST 6] Testing Multi-Device Independence...")
    sm1 = get_or_create_state_machine("ESP8266-01")
    sm2 = get_or_create_state_machine("ESP8266-02")
    sm2.state = "TRUSTED"
    sm2.anomaly_streak = 0

    # Trigger anomaly on ESP8266-02
    data2 = receive_device({
        "device_id": "ESP8266-02",
        "mac": "AA:BB:CC:DD:EE:02",
        "ip": "10.214.179.157",
        "rssi": -85.0,
        "free_heap": 5000,
        "uptime": 200,
        "firmware": "1.0.0",
        "firmware_md5": "bad_md5",
        "packet_count": 5000,
        "request_count": 5000
    })
    assert sm1.anomaly_streak == 0, "ESP8266-01 streak was contaminated!"
    print(f"  ESP8266-01 Streak: {sm1.anomaly_streak} | ESP8266-02 Streak: {sm2.anomaly_streak}")
    print(">>> TEST 6 PASSED: Devices maintain completely isolated state machines.\n")

    print("[TEST 7] Testing Latest Device Telemetry Endpoint...")
    latest_data = get_latest_device("ESP8266-01")
    assert latest_data["status"] == "ok"
    assert "identity_status" in latest_data
    assert "firmware_status" in latest_data
    assert "ml_observation" in latest_data
    assert "security_status" in latest_data
    assert "anomaly_streak" in latest_data
    assert "anomaly_reason" in latest_data
    assert "recent_observations" in latest_data
    print(f"  Latest Data Security Status: {latest_data['security_status']}")
    print(f"  Latest Data Reason: {latest_data['anomaly_reason']}")
    print(f"  Recent Observations Count: {len(latest_data['recent_observations'])}")
    print(">>> TEST 7 PASSED: Latest telemetry endpoint contains complete multi-layer state.\n")

    print("==================================================")
    print("ALL TESTS PASSED SUCCESSFULLY (100% VERIFIED)!")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
