"""
Test False Positive Elimination & Detection Policy Validation.
Tests:
1. Active model prediction outputs continuous calibrated confidence (not hard-coded 1.0)
2. Normal infrastructure traffic (DNS, mDNS, SSDP, DHCP) -> BENIGN, 0 alerts
3. Normal HTTPS web browsing flows -> BENIGN, 0 alerts
4. Isolated single-port connection -> BENIGN / unconfirmed PortScan, 0 alerts
5. True multi-port probing (>=5 ports within 30s) -> PortScan confirmed, 1 alert
6. Alert deduplication -> repeated attacks from same source to same destination within window do NOT create multiple alerts
7. Mathematical counter consistency: packets captured != flows analyzed != alerts raised
"""
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app
app = create_app()

from backend.network.flow import NetworkFlow
from backend.network.policy import get_detection_policy
from backend.network.capture_service import get_capture_service
from backend.database.repositories.model_repo import ModelRepository
from backend.database.repositories.alert_repo import AlertRepository
from backend.ml.predictor import predict_single

passed = 0
failed = 0

def test(name, condition, details=""):
    global passed, failed
    if condition:
        print(f"  [PASS] {name}")
        passed += 1
    else:
        print(f"  [FAIL] {name} - {details}")
        failed += 1

print("\n" + "=" * 65)
print("  NIDS FALSE POSITIVE & DETECTION POLICY TEST SUITE")
print("=" * 65)

active_model = ModelRepository().find_active()
print(f"Active model: {active_model.get('model_id')} ({active_model.get('name')}, v={active_model.get('version')})")

policy = get_detection_policy()
service = get_capture_service()

# ── TEST 1: Model Calibrated Probabilities ────────────────────────────
print("\n[1] Testing Model Probabilities Calibration...")
test_flow_normal = NetworkFlow("192.168.31.27", "142.250.190.46", 52140, 443, "TCP")
test_flow_normal.add_packet(64, "192.168.31.27", 52140, tcp_flags={"SYN": 1}, win_size=64240)
test_flow_normal.add_packet(64, "142.250.190.46", 443, tcp_flags={"SYN": 1, "ACK": 1}, win_size=65535)
test_flow_normal.add_packet(1200, "192.168.31.27", 52140, tcp_flags={"ACK": 1, "PSH": 1}, win_size=64240, payload_len=1150)
test_flow_normal.add_packet(64, "142.250.190.46", 443, tcp_flags={"ACK": 1}, win_size=65535)

feats_normal = test_flow_normal.to_features()
raw_pred = predict_single(feats_normal, active_model["model_dir"], active_model["version"])
print(f"      Normal HTTPS prediction: {raw_pred['prediction']} (conf: {raw_pred['confidence']})")
test("Normal HTTPS is classified BENIGN", raw_pred["prediction"] == "BENIGN")
test("Confidence is realistic float (0 < conf < 1.0)", 0.0 < raw_pred["confidence"] < 1.0, f"Got {raw_pred['confidence']}")

# ── TEST 2: Infrastructure & Broadcast Traffic Normalization ───────────
print("\n[2] Testing Infrastructure Traffic Policy Normalization...")
# UDP DNS flow
dns_flow = NetworkFlow("192.168.31.27", "8.8.8.8", 53100, 53, "UDP")
dns_flow.add_packet(72, "192.168.31.27", 53100)
dns_flow.add_packet(140, "8.8.8.8", 53)
raw_dns = predict_single(dns_flow.to_features(), active_model["model_dir"], active_model["version"])
decision_dns = policy.validate_prediction(dns_flow, raw_dns)
print(f"      DNS 53 raw: {raw_dns['prediction']} -> policy: {decision_dns['prediction']} (alert: {decision_dns['should_alert']})")
test("DNS flow normalized to BENIGN", decision_dns["prediction"] == "BENIGN")
test("DNS flow does NOT trigger alert", decision_dns["should_alert"] is False)

# UDP mDNS multicast flow (224.0.0.251:5353)
mdns_flow = NetworkFlow("192.168.31.27", "224.0.0.251", 5353, 5353, "UDP")
mdns_flow.add_packet(85, "192.168.31.27", 5353)
raw_mdns = predict_single(mdns_flow.to_features(), active_model["model_dir"], active_model["version"])
decision_mdns = policy.validate_prediction(mdns_flow, raw_mdns)
print(f"      mDNS 5353 raw: {raw_mdns['prediction']} -> policy: {decision_mdns['prediction']} (alert: {decision_mdns['should_alert']})")
test("mDNS multicast flow normalized to BENIGN", decision_mdns["prediction"] == "BENIGN")
test("mDNS flow does NOT trigger alert", decision_mdns["should_alert"] is False)

# UDP SSDP multicast flow (239.255.255.250:1900)
ssdp_flow = NetworkFlow("192.168.31.27", "239.255.255.250", 1900, 1900, "UDP")
ssdp_flow.add_packet(200, "192.168.31.27", 1900)
raw_ssdp = predict_single(ssdp_flow.to_features(), active_model["model_dir"], active_model["version"])
decision_ssdp = policy.validate_prediction(ssdp_flow, raw_ssdp)
print(f"      SSDP 1900 raw: {raw_ssdp['prediction']} -> policy: {decision_ssdp['prediction']} (alert: {decision_ssdp['should_alert']})")
test("SSDP multicast flow normalized to BENIGN", decision_ssdp["prediction"] == "BENIGN")
test("SSDP flow does NOT trigger alert", decision_ssdp["should_alert"] is False)

# ── TEST 3: PortScan Temporal Correlation ──────────────────────────────
print("\n[3] Testing PortScan Behavioral Temporal Correlation...")
# Simulate isolated probe from 10.0.0.99 to port 22
single_probe = NetworkFlow("10.0.0.99", "192.168.31.1", 40001, 22, "TCP")
single_probe.add_packet(64, "10.0.0.99", 40001, tcp_flags={"SYN": 1})
fake_pred = {"prediction": "PortScan", "confidence": 0.88, "severity": "HIGH"}
decision_single = policy.validate_prediction(single_probe, fake_pred)
print(f"      Single probe on port 22: {decision_single['prediction']} (alert: {decision_single['should_alert']})")
test("Single probe does not confirm PortScan (BENIGN)", decision_single["prediction"] == "BENIGN")
test("Single probe does not raise alert", decision_single["should_alert"] is False)

# Test correlation threshold crossing:
# We already sent 1 probe (port 22). Now send probes 2, 3, 4 (ports 21, 23, 80)
for p in [21, 23, 80]:
    probe = NetworkFlow("10.0.0.99", "192.168.31.1", 40000 + p, p, "TCP")
    probe.add_packet(64, "10.0.0.99", 40000 + p, tcp_flags={"SYN": 1})
    dec = policy.validate_prediction(probe, fake_pred)
    test(f"Probe to port {p} (under threshold) is BENIGN", dec["prediction"] == "BENIGN")
    test(f"Probe to port {p} does not alert", dec["should_alert"] is False)

# Now send probe 5 (port 8080) -> hits min_probes = 5
probe5 = NetworkFlow("10.0.0.99", "192.168.31.1", 48080, 8080, "TCP")
probe5.add_packet(64, "10.0.0.99", 48080, tcp_flags={"SYN": 1})
dec5 = policy.validate_prediction(probe5, fake_pred)
print(f"      5th probe (port 8080): {dec5['prediction']} (alert: {dec5['should_alert']})")
test("5th distinct port probe confirms PortScan", dec5["prediction"] == "PortScan")
test("5th probe raises alert", dec5["should_alert"] is True)

# ── TEST 4: Alert Deduplication & Aggregation ──────────────────────────
print("\n[4] Testing Alert Deduplication & Aggregation...")
# Send 6th probe from same source to same destination immediately
probe6 = NetworkFlow("10.0.0.99", "192.168.31.1", 43389, 3389, "TCP")
probe6.add_packet(64, "10.0.0.99", 43389, tcp_flags={"SYN": 1})
dec6 = policy.validate_prediction(probe6, fake_pred)
print(f"      6th probe within window: {dec6['prediction']} (is_dup: {dec6['is_duplicate']}, alert: {dec6['should_alert']})")
test("6th probe flagged as duplicate within dedup window", dec6["is_duplicate"] is True)
test("Duplicate probe does not spawn duplicate alert", dec6["should_alert"] is False)

# Test repository level create_or_aggregate with unique IP to verify fresh creation + aggregation
alert_repo = AlertRepository()
test_src = f"10.88.{int(time.time()) % 250}.{int(time.time() * 10) % 250}"
alert_data = {
    "source_ip": test_src,
    "destination_ip": "192.168.31.1",
    "attack_type": "PortScan",
    "severity": "HIGH",
    "confidence": 0.88,
}
id1, is_new1 = alert_repo.create_or_aggregate(alert_data, window_seconds=60.0)
id2, is_new2 = alert_repo.create_or_aggregate(alert_data, window_seconds=60.0)
print(f"      AlertRepo aggregate test ({test_src}): is_new1={is_new1}, is_new2={is_new2}, id1={id1}, id2={id2}")
test("First alert creates new record", is_new1 is True)
test("Second alert aggregates existing record (is_new == False)", is_new2 is False)
test("Aggregated alert references same ID", id1 == id2)

# ── TEST 5: CaptureService End-to-End Counter Consistency ─────────────
print("\n[5] Testing CaptureService End-to-End Flow & Counters...")
# Reset service stats
service.stats = {
    "packets_captured": 0,
    "flows_generated": 0,
    "flows_analyzed": 0,
    "normal_traffic": 0,
    "intrusions": 0,
    "alerts": 0,
}

# 1. Add 10 normal web/DNS flows
for i in range(10):
    f = NetworkFlow("192.168.31.27", f"142.250.190.{i+1}", 50000 + i, 443, "TCP")
    f.add_packet(64, "192.168.31.27", 50000 + i, tcp_flags={"SYN": 1}, win_size=64240)
    f.add_packet(64, f"142.250.190.{i+1}", 443, tcp_flags={"SYN": 1, "ACK": 1}, win_size=65535)
    f.add_packet(500, "192.168.31.27", 50000 + i, tcp_flags={"ACK": 1}, win_size=64240, payload_len=450)
    service._analyze_and_store_flow(f)

print(f"      Stats after 10 normal flows: {service.stats}")
test("All 10 flows analyzed", service.stats["flows_analyzed"] == 10)
test("Normal traffic counter is 10", service.stats["normal_traffic"] == 10)
test("Intrusions counter is 0 for normal traffic", service.stats["intrusions"] == 0)
test("Alerts counter is 0 for normal traffic", service.stats["alerts"] == 0)

print("\n" + "=" * 65)
print(f"  RESULTS: {passed} PASSED, {failed} FAILED")
print("=" * 65 + "\n")

if failed > 0:
    sys.exit(1)
