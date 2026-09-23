"""
Network routes — /network/* and /api/network/*
Exposes interface discovery, capture control, live event polling, and SSE streaming.
"""
import time
import json
from flask import Blueprint, request, Response, jsonify
from backend.network.interfaces import get_network_interfaces, check_capture_capability
from backend.network.capture_service import get_capture_service
from backend.utils.response import success_response, error_response
from backend.utils.decorators import login_required
from backend.utils.logger import get_logger

logger = get_logger(__name__)

network_bp = Blueprint("network", __name__, url_prefix="/network")


@network_bp.route("/interfaces", methods=["GET"])
@login_required
def list_interfaces():
    """List all available network interfaces on the machine and capture capability."""
    interfaces = get_network_interfaces()
    capability = check_capture_capability()
    return success_response("Interfaces retrieved.", data={
        "interfaces": interfaces,
        "capability": capability,
    })


@network_bp.route("/capture/start", methods=["POST"])
@login_required
def start_capture():
    """Start live packet capture on a selected interface."""
    data = request.get_json(silent=True) or {}
    interface_name = data.get("interface")
    if not interface_name:
        return error_response("Interface name is required.", "MISSING_INTERFACE")

    service = get_capture_service()
    result = service.start_capture(interface_name)

    if not result["success"]:
        return error_response(
            message=result["message"],
            code=result.get("code", "CAPTURE_START_FAILED"),
            status_code=400,
            details={"install_guide": result.get("install_guide")} if "install_guide" in result else None
        )

    return success_response(result["message"], data=service.get_status())


@network_bp.route("/capture/stop", methods=["POST"])
@login_required
def stop_capture():
    """Stop active packet capture."""
    service = get_capture_service()
    result = service.stop_capture()
    return success_response(result["message"], data=service.get_status())


@network_bp.route("/capture/status", methods=["GET"])
@login_required
def capture_status():
    """Get current capture service status, uptime, and counters."""
    service = get_capture_service()
    return success_response("Capture status.", data=service.get_status())


@network_bp.route("/capture/events", methods=["GET"])
@login_required
def get_events():
    """Poll recent captured flow events."""
    limit = min(int(request.args.get("limit", 50)), 200)
    since_id = int(request.args.get("since", 0))

    service = get_capture_service()
    events = service.get_events(limit=limit, since_id=since_id)
    status = service.get_status()

    return success_response("Events retrieved.", data={
        "events": events,
        "status": status,
    })


@network_bp.route("/capture/stream", methods=["GET"])
def stream_events():
    """Server-Sent Events (SSE) stream for live detections."""
    def event_stream():
        service = get_capture_service()
        last_id = 0
        while True:
            events = service.get_events(limit=20, since_id=last_id)
            if events:
                for evt in events:
                    last_id = max(last_id, evt["id"])
                    yield f"data: {json.dumps(evt)}\n\n"
            else:
                # Send periodic heartbeat comment
                yield ": heartbeat\n\n"
            time.sleep(1.0)

    return Response(event_stream(), mimetype="text/event-stream")


@network_bp.route("/capture/inject-test-flow", methods=["POST"])
@login_required
def inject_test_flow():
    """
    Test helper endpoint: inject a packet/flow through the live pipeline
    to verify flow aggregation, feature extraction, ML prediction, and alerts.
    """
    data = request.get_json(silent=True) or {}
    src_ip = data.get("source_ip", "192.168.1.100")
    dst_ip = data.get("destination_ip", "192.168.1.1")
    src_port = int(data.get("source_port", 55432))
    dst_port = int(data.get("destination_port", 80))
    protocol = data.get("protocol", "TCP")
    attack_simulation = data.get("attack_simulation", False)

    from backend.network.flow import NetworkFlow
    flow = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol)

    if attack_simulation:
        # Simulate attack-like pattern (e.g. SYN flood or rapid probe)
        for _ in range(50):
            flow.add_packet(64, src_ip, src_port, tcp_flags={"SYN": 1})
    else:
        # Normal 3-way handshake + HTTP exchange
        flow.add_packet(64, src_ip, src_port, tcp_flags={"SYN": 1}, header_len=20)
        flow.add_packet(64, dst_ip, dst_port, tcp_flags={"SYN": 1, "ACK": 1}, header_len=20)
        flow.add_packet(1500, src_ip, src_port, tcp_flags={"ACK": 1, "PSH": 1}, header_len=20, payload_len=1460)
        flow.add_packet(64, dst_ip, dst_port, tcp_flags={"ACK": 1}, header_len=20)
        flow.add_packet(64, src_ip, src_port, tcp_flags={"FIN": 1, "ACK": 1}, header_len=20)

    service = get_capture_service()
    service._analyze_and_store_flow(flow)

    recent = service.get_events(limit=1)
    return success_response("Test flow injected and analyzed.", data=recent[0] if recent else {})
