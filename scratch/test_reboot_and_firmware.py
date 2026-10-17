import sys
import os
import unittest
from datetime import datetime

# Ensure backend module is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import (
    SessionLocal,
    Device,
    Telemetry,
    DetectionHistory,
    SecurityAlert,
    receive_device,
    calculate_behavior,
    previous_data,
    device_state_machines
)


def run_tests():
    print("=" * 70)
    print("RUNNING COMPREHENSIVE REBOOT & FIRMWARE INTEGRITY VERIFICATION SUITE")
    print("=" * 70)

    db = SessionLocal()
    device_id = "ESP8266-01"
    
    # Ensure default test device is registered
    dev = db.query(Device).filter(Device.device_id == device_id).first()
    if not dev:
        dev = Device(
            device_id=device_id,
            mac="60:01:94:73:34:00",
            ip="10.214.179.156",
            firmware="1.0.0",
            firmware_md5="ec5d16ed40b1d58538a1d4e8a2deb7fa",
            status="trusted",
            registered_at=datetime.now()
        )
        db.add(dev)
        db.commit()
    
    registered_md5 = dev.firmware_md5
    dev_mac = dev.mac
    db.close()

    # -------------------------------------------------------------------------
    # TEST C: Normal ESP Telemetry (No Reboot, Valid Firmware)
    # -------------------------------------------------------------------------
    print("\n[TEST C] Testing Normal ESP Telemetry (Sequential Uptime Increment)...")
    res_c1 = receive_device({
        "device_id": device_id,
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -30.0,
        "free_heap": 49000,
        "uptime": 50,
        "firmware": "1.0.0",
        "firmware_md5": registered_md5,
        "packet_count": 10,
        "request_count": 10
    })
    
    res_c2 = receive_device({
        "device_id": device_id,
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -30.0,
        "free_heap": 49000,
        "uptime": 55,
        "firmware": "1.0.0",
        "firmware_md5": registered_md5,
        "packet_count": 11,
        "request_count": 11
    })

    assert res_c2["uptime_gap"] == 0, f"Expected uptime_gap == 0, got {res_c2['uptime_gap']}"
    assert res_c2["firmware_status"] == "VALID", f"Expected firmware_status == VALID, got {res_c2['firmware_status']}"
    assert res_c2["threat"] == "NONE", f"Expected threat == NONE, got {res_c2['threat']}"
    print(">>> TEST C PASSED: Normal telemetry produces uptime_gap = 0 and VALID firmware.")

    # -------------------------------------------------------------------------
    # TEST A: Physical ESP Reset while FastAPI is Running (100s -> 3s)
    # -------------------------------------------------------------------------
    print("\n[TEST A] Testing Physical ESP Reset while FastAPI is Running (100s -> 3s)...")
    receive_device({
        "device_id": device_id,
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -30.0,
        "free_heap": 49000,
        "uptime": 100,
        "firmware": "1.0.0",
        "firmware_md5": registered_md5,
        "packet_count": 20,
        "request_count": 20
    })

    res_a = receive_device({
        "device_id": device_id,
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -30.0,
        "free_heap": 49000,
        "uptime": 3,
        "firmware": "1.0.0",
        "firmware_md5": registered_md5,
        "packet_count": 1,
        "request_count": 1
    })

    assert res_a["uptime_gap"] == 1, f"Expected uptime_gap == 1, got {res_a['uptime_gap']}"
    assert res_a["event_type"] == "UNEXPECTED_REBOOT", f"Expected event_type == UNEXPECTED_REBOOT, got {res_a['event_type']}"
    assert res_a["previous_uptime"] == 100, f"Expected previous_uptime == 100, got {res_a['previous_uptime']}"
    assert res_a["current_uptime"] == 3, f"Expected current_uptime == 3, got {res_a['current_uptime']}"
    assert res_a["firmware_status"] == "VALID", f"Reboot must NOT be classified as firmware tampering (got {res_a['firmware_status']})"
    print(f"  Captured Evidence: Prev={res_a['previous_uptime']}s -> Curr={res_a['current_uptime']}s | Reason={res_a['anomaly_reason']}")
    print(">>> TEST A PASSED: UNEXPECTED_REBOOT detected with preserved evidence.")

    # -------------------------------------------------------------------------
    # TEST B: Persistent Reboot Detection across FastAPI Restart
    # -------------------------------------------------------------------------
    print("\n[TEST B] Testing Persistent Reboot Detection across FastAPI Process Restart...")
    # Step 1: Send telemetry with high uptime
    receive_device({
        "device_id": device_id,
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -30.0,
        "free_heap": 49000,
        "uptime": 250,
        "firmware": "1.0.0",
        "firmware_md5": registered_md5,
        "packet_count": 50,
        "request_count": 50
    })

    # Step 2: SIMULATE COMPLETE FASTAPI RESTART (Wipe all RAM caches)
    print("  Simulating FastAPI restart: clearing in-memory previous_data and state machines...")
    previous_data.clear()
    device_state_machines.clear()
    assert len(previous_data) == 0, "previous_data RAM must be completely empty"

    # Step 3: ESP undergoes physical reset and sends packet with low uptime (uptime = 4)
    print("  ESP reboots to uptime = 4 after FastAPI restarted...")
    res_b = receive_device({
        "device_id": device_id,
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -30.0,
        "free_heap": 49000,
        "uptime": 4,
        "firmware": "1.0.0",
        "firmware_md5": registered_md5,
        "packet_count": 1,
        "request_count": 1
    })

    assert res_b["uptime_gap"] == 1, f"Expected uptime_gap == 1 from DB lookup, got {res_b['uptime_gap']}"
    assert res_b["event_type"] == "UNEXPECTED_REBOOT", f"Expected event_type == UNEXPECTED_REBOOT, got {res_b['event_type']}"
    assert res_b["previous_uptime"] == 250, f"Expected previous_uptime == 250 from DB, got {res_b['previous_uptime']}"
    assert res_b["current_uptime"] == 4, f"Expected current_uptime == 4, got {res_b['current_uptime']}"
    print(f"  Database Looked-Up Evidence: Prev={res_b['previous_uptime']}s -> Curr={res_b['current_uptime']}s")
    print(">>> TEST B PASSED: Reboot successfully detected using persistent SQLite database record.")

    # -------------------------------------------------------------------------
    # TEST D: Firmware MD5 Mismatch Detection (FIRMWARE_TAMPERED)
    # -------------------------------------------------------------------------
    print("\n[TEST D] Testing Firmware MD5 Mismatch Detection...")
    res_d = receive_device({
        "device_id": device_id,
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -30.0,
        "free_heap": 49000,
        "uptime": 10,
        "firmware": "1.0.0",
        "firmware_md5": "tampered_unauthorized_firmware_md5_hash_999",
        "packet_count": 2,
        "request_count": 2
    })

    assert res_d["firmware_status"] == "FIRMWARE_TAMPERED", f"Expected firmware_status == FIRMWARE_TAMPERED, got {res_d['firmware_status']}"
    assert res_d["threat"] == "FIRMWARE_TAMPERED", f"Expected threat == FIRMWARE_TAMPERED, got {res_d['threat']}"
    assert res_d["expected_firmware_md5"] == registered_md5, f"Expected MD5 must remain untouched registered value ({registered_md5})"
    
    # Verify in DB that registered device expected_firmware_md5 was NOT overwritten!
    db = SessionLocal()
    dev_after = db.query(Device).filter(Device.device_id == device_id).first()
    assert dev_after.firmware_md5 == registered_md5, f"CRITICAL: Registered device expected MD5 was corrupted! {dev_after.firmware_md5} != {registered_md5}"
    db.close()
    print(f"  Integrity Check: Expected={res_d['expected_firmware_md5']} | Reported={res_d['firmware_md5']}")
    print(">>> TEST D PASSED: FIRMWARE_TAMPERED detected and registered expected MD5 preserved.")

    # -------------------------------------------------------------------------
    # TEST E: Normal Firmware MD5 Verification (VALID)
    # -------------------------------------------------------------------------
    print("\n[TEST E] Testing Normal Firmware MD5 Verification...")
    res_e = receive_device({
        "device_id": device_id,
        "mac": dev_mac,
        "ip": "10.214.179.156",
        "rssi": -30.0,
        "free_heap": 49000,
        "uptime": 15,
        "firmware": "1.0.0",
        "firmware_md5": registered_md5,
        "packet_count": 3,
        "request_count": 3
    })

    assert res_e["firmware_status"] == "VALID", f"Expected firmware_status == VALID, got {res_e['firmware_status']}"
    print(">>> TEST E PASSED: Matching firmware hash verified as VALID.")

    print("\n" + "=" * 70)
    print("ALL 5 TESTS (TEST A - TEST E) PASSED WITH 100% ACCURACY!")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
