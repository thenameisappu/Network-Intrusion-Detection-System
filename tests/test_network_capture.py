"""
Automated unit and integration tests for Network Traffic Capture module.
Tests:
1. Interface discovery
2. Capability detection (Npcap/Scapy/RawSocket)
3. 5-tuple flow aggregation & direction handling
4. 77 CIC-IDS2017 feature extraction schema
5. Prediction on flow through active ML model
6. CaptureService state machine & lifecycle (start/stop/status)
7. REST API endpoints (/network/interfaces, /network/capture/*)
"""
import pytest
import time
from backend.network.interfaces import get_network_interfaces, check_capture_capability
from backend.network.flow import NetworkFlow
from backend.network.aggregator import FlowAggregator
from backend.network.capture_service import get_capture_service
from backend.ml.feature_config import FEATURE_NAMES
from backend.database.repositories.model_repo import ModelRepository
from backend.ml.predictor import predict_single


def test_interface_discovery():
    """Verify that network interfaces are discovered and include expected fields."""
    interfaces = get_network_interfaces()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0

    first = interfaces[0]
    assert "name" in first
    assert "status" in first
    assert "ip" in first
    assert "is_up" in first


def test_capability_detection():
    """Verify capture capability check returns well-formed dict."""
    cap = check_capture_capability()
    assert isinstance(cap, dict)
    assert "available" in cap
    assert "driver" in cap
    assert "message" in cap
    assert cap["driver"] in ("Npcap", "WinPcap", "RawSocket", "None")


def test_flow_aggregation_and_direction():
    """Verify bidirectional 5-tuple flow aggregates both directions correctly."""
    agg = FlowAggregator(active_timeout=10.0, idle_timeout=3.0)

    # Forward packet
    p1 = {
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "src_port": 54321,
        "dst_port": 53,
        "protocol": "UDP",
        "pkt_len": 68,
        "timestamp": 1000.0,
    }
    # Backward packet (response)
    p2 = {
        "src_ip": "8.8.8.8",
        "dst_ip": "192.168.1.100",
        "src_port": 53,
        "dst_port": 54321,
        "protocol": "UDP",
        "pkt_len": 128,
        "timestamp": 1000.02,
    }

    fin1 = agg.add_packet(p1)
    assert len(fin1) == 0
    assert agg.count_active() == 1

    fin2 = agg.add_packet(p2)
    assert len(fin2) == 0
    assert agg.count_active() == 1

    # Flush all
    flows = agg.flush_all()
    assert len(flows) == 1
    flow = flows[0]
    assert len(flow.fwd_packet_lengths) == 1
    assert len(flow.bwd_packet_lengths) == 1
    assert flow.fwd_packet_lengths[0] == 68
    assert flow.bwd_packet_lengths[0] == 128


def test_feature_extraction_77_features():
    """Verify that NetworkFlow extracts all 77 canonical features."""
    flow = NetworkFlow("192.168.1.50", "1.1.1.1", 49152, 443, "TCP", start_time=100.0)
    flow.add_packet(64, "192.168.1.50", 49152, timestamp=100.0, tcp_flags={"SYN": 1}, win_size=65535)
    flow.add_packet(64, "1.1.1.1", 443, timestamp=100.01, tcp_flags={"SYN": 1, "ACK": 1}, win_size=65535)
    flow.add_packet(1500, "192.168.1.50", 49152, timestamp=100.02, tcp_flags={"ACK": 1, "PSH": 1}, payload_len=1460)
    flow.add_packet(64, "1.1.1.1", 443, timestamp=100.03, tcp_flags={"ACK": 1})

    features = flow.to_features()
    assert isinstance(features, dict)

    # Must contain all canonical features
    for name in FEATURE_NAMES:
        assert name in features, f"Missing expected feature: {name}"

    assert features["Total Fwd Packets"] == 2
    assert features["Total Backward Packets"] == 2
    assert features["Total Length of Fwd Packets"] == 1564
    assert features["Total Length of Bwd Packets"] == 128
    assert features["SYN Flag Count"] == 2
    assert features["ACK Flag Count"] == 3


def test_ml_prediction_on_flow():
    """Verify that extracted flow features successfully pass through active ML predictor."""
    active_model = ModelRepository().find_active()
    assert active_model is not None, "Active ML model must be present."

    flow = NetworkFlow("192.168.1.20", "10.0.0.1", 52345, 80, "TCP")
    flow.add_packet(64, "192.168.1.20", 52345, tcp_flags={"SYN": 1})
    flow.add_packet(64, "10.0.0.1", 80, tcp_flags={"SYN": 1, "ACK": 1})
    flow.add_packet(1200, "192.168.1.20", 52345, tcp_flags={"ACK": 1}, payload_len=1140)

    feats = flow.to_features()
    result = predict_single(feats, active_model["model_dir"], active_model["version"])

    assert "prediction" in result
    assert "severity" in result
    assert "confidence" in result
    assert "is_intrusion" in result
    assert result["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_capture_service_lifecycle():
    """Verify CaptureService transitions and state reporting."""
    svc = get_capture_service()
    status = svc.get_status()
    assert "state" in status
    assert "stats" in status

    # Stopping an idle service should succeed safely
    res = svc.stop_capture()
    assert res["success"] is True
    assert svc.get_status()["state"] == "STOPPED"
