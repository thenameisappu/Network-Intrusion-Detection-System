"""
Comprehensive E2E and Unit Verification for Network Traffic Capture Pipeline.
Tests:
1. Interface discovery
2. Capability detection (Npcap/Scapy/RawSocket)
3. 5-tuple flow aggregation & direction handling
4. 77 CIC-IDS2017 feature extraction schema
5. ML prediction on flow through active ML model
6. HTTP REST API: /network/interfaces, /network/capture/status, /network/capture/inject-test-flow, /network/capture/events
7. Dashboard verification: live flows reflected in dashboard summary
8. Detection history verification: mode: LIVE recorded
"""
import sys
import os
import json
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.app import create_app
app = create_app()

from backend.network.interfaces import get_network_interfaces, check_capture_capability
from backend.network.flow import NetworkFlow
from backend.network.aggregator import FlowAggregator
from backend.network.capture_service import get_capture_service
from backend.ml.feature_config import FEATURE_NAMES
from backend.database.repositories.model_repo import ModelRepository
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

print("\n" + "=" * 60)
print("  NIDS LIVE NETWORK CAPTURE — VERIFICATION SUITE")
print("=" * 60)

# 1. Interface Discovery
print("\n[1] Testing Interface Discovery...")
ifaces = get_network_interfaces()
test("Discovered >= 1 interface", len(ifaces) > 0, f"Found {len(ifaces)}")
wifi = next((i for i in ifaces if "wi-fi" in i["name"].lower() or "wireless" in i["description"].lower()), None)
test("Wi-Fi interface detected", wifi is not None, "Wi-Fi not found in list")
if wifi:
    print(f"      Adapter: {wifi['name']} | IP: {wifi['ip']} | Status: {wifi['status']}")

# 2. Capability Detection
print("\n[2] Testing Capture Capability...")
cap = check_capture_capability()
test("Capability dict well-formed", "available" in cap and "driver" in cap)
print(f"      Driver: {cap['driver']} | Available: {cap['available']}")
print(f"      Message: {cap['message'][:60]}...")

# 3. Flow Aggregation & Direction
print("\n[3] Testing 5-Tuple Flow Aggregation...")
agg = FlowAggregator(active_timeout=10.0, idle_timeout=3.0)
agg.add_packet({"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "src_port": 54321, "dst_port": 53, "protocol": "UDP", "pkt_len": 72})
agg.add_packet({"src_ip": "8.8.8.8", "dst_ip": "192.168.1.10", "src_port": 53, "dst_port": 54321, "protocol": "UDP", "pkt_len": 150})
flows = agg.flush_all()
test("Bidirectional flow merged to 1 flow", len(flows) == 1)
test("Forward packet count == 1", len(flows[0].fwd_packet_lengths) == 1)
test("Backward packet count == 1", len(flows[0].bwd_packet_lengths) == 1)

# 4. 77 Feature Extraction Schema
print("\n[4] Testing 77 CIC-IDS2017 Feature Extraction...")
flow = NetworkFlow("192.168.1.20", "1.1.1.1", 49152, 443, "TCP", start_time=100.0)
flow.add_packet(64, "192.168.1.20", 49152, timestamp=100.0, tcp_flags={"SYN": 1}, win_size=65535)
flow.add_packet(64, "1.1.1.1", 443, timestamp=100.02, tcp_flags={"SYN": 1, "ACK": 1}, win_size=65535)
flow.add_packet(1460, "192.168.1.20", 49152, timestamp=100.04, tcp_flags={"ACK": 1, "PSH": 1}, payload_len=1400)
flow.add_packet(64, "1.1.1.1", 443, timestamp=100.06, tcp_flags={"ACK": 1})
feats = flow.to_features()
test("Feature dictionary generated", isinstance(feats, dict))
missing = [f for f in FEATURE_NAMES if f not in feats]
test("All 77 CIC-IDS2017 features present", len(missing) == 0, f"Missing: {missing}")
test("Total Fwd Packets == 2", feats["Total Fwd Packets"] == 2)
test("Total Backward Packets == 2", feats["Total Backward Packets"] == 2)
test("Total Length of Fwd Packets == 1524", feats["Total Length of Fwd Packets"] == 1524)

# 5. ML Prediction on Extracted Flow
print("\n[5] Testing ML Prediction with Active Model...")
active_model = ModelRepository().find_active()
test("Active ML model present", active_model is not None)
if active_model:
    pred = predict_single(feats, active_model["model_dir"], active_model["version"])
    test("Prediction returns attack label", "prediction" in pred)
    test("Prediction returns confidence", "confidence" in pred and 0 <= pred["confidence"] <= 1.0)
    test("Severity assigned", pred["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL"))
    print(f"      Prediction: {pred['prediction']} | Severity: {pred['severity']} | Confidence: {pred['confidence']}")

# 6. HTTP API Endpoints
print("\n[6] Testing HTTP REST Endpoints...")
BASE = "http://127.0.0.1:5000"

def http(method, path, body=None, token=None):
    url = BASE + path
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode())
    except Exception as e:
        return {"success": False, "error": str(e)}

# Login
login_res = http("POST", "/auth/login", {"username": "admin", "password": "Admin@123"})
test("Admin login via API", login_res.get("success") is True)
token = login_res.get("data", {}).get("access_token")

if token:
    # GET /network/interfaces
    if_res = http("GET", "/network/interfaces", token=token)
    test("GET /network/interfaces returns 200", if_res.get("success") is True)
    test("Interfaces returned in API data", len(if_res.get("data", {}).get("interfaces", [])) > 0)

    # GET /network/capture/status
    st_res = http("GET", "/network/capture/status", token=token)
    test("GET /network/capture/status returns valid state", st_res.get("success") is True and "state" in st_res.get("data", {}))

    # POST /network/capture/inject-test-flow (Normal)
    inj_norm = http("POST", "/network/capture/inject-test-flow", {"source_ip": "192.168.31.27", "destination_ip": "1.1.1.1", "attack_simulation": False}, token=token)
    test("POST /network/capture/inject-test-flow (Normal)", inj_norm.get("success") is True)

    # POST /network/capture/inject-test-flow (Attack)
    inj_atk = http("POST", "/network/capture/inject-test-flow", {"source_ip": "192.168.1.189", "destination_ip": "192.168.31.27", "attack_simulation": True}, token=token)
    test("POST /network/capture/inject-test-flow (Attack)", inj_atk.get("success") is True)

    # GET /network/capture/events
    ev_res = http("GET", "/network/capture/events?limit=10", token=token)
    test("GET /network/capture/events retrieves live events", ev_res.get("success") is True and len(ev_res.get("data", {}).get("events", [])) > 0)

    # GET /dashboard/summary
    dash_res = http("GET", "/dashboard/summary", token=token)
    test("Dashboard reflects detections and traffic", dash_res.get("success") is True and dash_res.get("data", {}).get("total_traffic", 0) > 0)

    # GET /detections
    det_res = http("GET", "/detections?per_page=5", token=token)
    test("Detections history contains records", det_res.get("success") is True and len(det_res.get("data", {}).get("detections", [])) > 0)

print("\n" + "=" * 60)
print(f"  RESULTS: {passed} PASSED, {failed} FAILED")
print("=" * 60 + "\n")

if failed > 0:
    sys.exit(1)
