"""
Capture Service: Manages live network packet capture, background workers,
flow aggregation, ML classification, database persistence, and live UI streaming.
"""
import os
import time
import logging
import threading
import collections
from queue import Queue, Empty
from datetime import datetime

# Suppress scapy warning when libpcap is not installed
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from backend.network.interfaces import get_network_interfaces, check_capture_capability
from backend.network.aggregator import FlowAggregator
from backend.network.flow import NetworkFlow
from backend.database.repositories.model_repo import ModelRepository
from backend.database.repositories.detection_repo import DetectionRepository
from backend.database.repositories.alert_repo import AlertRepository
from backend.ml.predictor import predict_single
from backend.network.policy import get_detection_policy
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class CaptureService:
    """
    Singleton capture service that coordinates packet sniffing, flow aggregation,
    ML classification, and real-time event broadcasting.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.state = "STOPPED"  # STOPPED, STARTING, CAPTURING, STOPPING, ERROR
        self.current_interface = None
        self.error_message = None
        self.start_time = None

        # Session counters
        self.stats = {
            "packets_captured": 0,
            "flows_generated": 0,
            "flows_analyzed": 0,
            "normal_traffic": 0,
            "intrusions": 0,
            "alerts": 0,
        }

        # Concurrency & Queues
        self._packet_queue = Queue(maxsize=5000)
        self._stop_event = threading.Event()
        self._capture_thread = None
        self._processor_thread = None
        self._aggregator = FlowAggregator(active_timeout=15.0, idle_timeout=5.0)

        # In-memory circular buffer for frontend real-time monitor
        self._events = collections.deque(maxlen=500)
        self._event_id_counter = 0

    def get_status(self) -> dict:
        """Return current service state, stats, and interface info."""
        with self._lock:
            uptime = round(time.time() - self.start_time, 1) if self.start_time and self.state == "CAPTURING" else 0
            return {
                "state": self.state,
                "interface": self.current_interface,
                "uptime_seconds": uptime,
                "stats": dict(self.stats),
                "active_flows": self._aggregator.count_active(),
                "queue_size": self._packet_queue.qsize(),
                "error_message": self.error_message,
            }

    def get_events(self, limit: int = 50, since_id: int = 0) -> list:
        """Return live events newer than since_id."""
        with self._lock:
            events = [e for e in self._events if e["id"] > since_id]
            return events[-limit:] if limit else events

    def start_capture(self, interface_name: str) -> dict:
        """
        Start live packet capture on the specified interface.
        """
        with self._lock:
            if self.state in ("CAPTURING", "STARTING"):
                return {"success": False, "message": "Capture is already active or starting."}

            cap = check_capture_capability()
            if not cap["available"]:
                self.state = "ERROR"
                self.error_message = cap["message"]
                return {
                    "success": False,
                    "message": cap["message"],
                    "install_guide": cap.get("install_guide"),
                    "code": "NPCAP_REQUIRED",
                }

            # Verify interface exists
            interfaces = get_network_interfaces()
            matched = next((i for i in interfaces if i["name"] == interface_name or i["id"] == interface_name), None)
            if not matched:
                return {"success": False, "message": f"Interface '{interface_name}' not found."}

            self.state = "STARTING"
            self.current_interface = matched["name"]
            self.error_message = None
            self.start_time = time.time()
            self._stop_event.clear()

            # Reset session stats
            self.stats = {
                "packets_captured": 0,
                "flows_generated": 0,
                "flows_analyzed": 0,
                "normal_traffic": 0,
                "intrusions": 0,
                "alerts": 0,
            }

            # Drain any old packets
            while not self._packet_queue.empty():
                try:
                    self._packet_queue.get_nowait()
                except Empty:
                    break

            # Start background threads
            self._processor_thread = threading.Thread(target=self._processing_loop, daemon=True, name="NIDS-Processor")
            self._processor_thread.start()

            self._capture_thread = threading.Thread(
                target=self._capture_loop, args=(matched,), daemon=True, name="NIDS-Capture"
            )
            self._capture_thread.start()

            self.state = "CAPTURING"
            logger.info(f"Capture started successfully on interface: {self.current_interface}")
            return {"success": True, "message": f"Capture started on {self.current_interface}"}

    def stop_capture(self) -> dict:
        """
        Safely stop packet capture, flush remaining flows, and update status.
        """
        with self._lock:
            if self.state not in ("CAPTURING", "STARTING"):
                return {"success": True, "message": "Capture is already stopped."}
            self.state = "STOPPING"

        logger.info("Stopping capture workers...")
        self._stop_event.set()

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)

        # Flush remaining flows in aggregator
        final_flows = self._aggregator.flush_all()
        for flow in final_flows:
            self._analyze_and_store_flow(flow)

        if self._processor_thread and self._processor_thread.is_alive():
            self._processor_thread.join(timeout=2.0)

        with self._lock:
            self.state = "STOPPED"
            self.current_interface = None
            self.start_time = None

        logger.info("Capture service stopped successfully.")
        return {"success": True, "message": "Capture stopped."}

    def _capture_loop(self, iface_info: dict):
        """Worker thread that sniffs packets using Scapy and pushes to packet queue."""
        iface_name = iface_info.get("name")
        logger.info(f"Beginning packet sniffing on {iface_name}")

        try:
            from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

            def _pkt_callback(pkt):
                if self._stop_event.is_set():
                    return

                try:
                    if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                        return

                    # Extract Layer 3
                    if pkt.haslayer(IP):
                        ip_layer = pkt[IP]
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        proto_code = ip_layer.proto
                    else:
                        ip_layer = pkt[IPv6]
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        proto_code = ip_layer.nh

                    src_port = 0
                    dst_port = 0
                    protocol = "IP"
                    tcp_flags = {}
                    win_size = 0
                    payload_len = 0
                    header_len = len(ip_layer) - len(ip_layer.payload)

                    # Extract Layer 4
                    if pkt.haslayer(TCP):
                        protocol = "TCP"
                        tcp_layer = pkt[TCP]
                        src_port = tcp_layer.sport
                        dst_port = tcp_layer.dport
                        win_size = tcp_layer.window
                        header_len += len(tcp_layer) - len(tcp_layer.payload)
                        payload_len = len(tcp_layer.payload) if hasattr(tcp_layer, "payload") else 0

                        # Flags extraction
                        flags_int = int(tcp_layer.flags)
                        tcp_flags = {
                            "FIN": 1 if (flags_int & 0x01) else 0,
                            "SYN": 1 if (flags_int & 0x02) else 0,
                            "RST": 1 if (flags_int & 0x04) else 0,
                            "PSH": 1 if (flags_int & 0x08) else 0,
                            "ACK": 1 if (flags_int & 0x10) else 0,
                            "URG": 1 if (flags_int & 0x20) else 0,
                            "ECE": 1 if (flags_int & 0x40) else 0,
                            "CWE": 1 if (flags_int & 0x80) else 0,
                        }
                    elif pkt.haslayer(UDP):
                        protocol = "UDP"
                        udp_layer = pkt[UDP]
                        src_port = udp_layer.sport
                        dst_port = udp_layer.dport
                        header_len += 8
                        payload_len = len(udp_layer.payload) if hasattr(udp_layer, "payload") else 0
                    elif pkt.haslayer(ICMP):
                        protocol = "ICMP"
                        header_len += 8

                    pkt_dict = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "src_port": src_port,
                        "dst_port": dst_port,
                        "protocol": protocol,
                        "pkt_len": len(pkt),
                        "timestamp": time.time(),
                        "tcp_flags": tcp_flags,
                        "header_len": max(20, header_len),
                        "win_size": win_size,
                        "payload_len": payload_len,
                    }

                    try:
                        self._packet_queue.put(pkt_dict, block=False)
                        with self._lock:
                            self.stats["packets_captured"] += 1
                    except Exception:
                        pass  # Queue full, drop packet to preserve memory

                except Exception as e:
                    logger.debug(f"Packet parsing error: {e}")

            # Run sniff with stop_filter
            sniff(
                prn=_pkt_callback,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )

        except Exception as e:
            logger.error(f"Packet capture error on {iface_name}: {e}")
            with self._lock:
                self.state = "ERROR"
                self.error_message = str(e)

    def _processing_loop(self):
        """Worker thread that consumes raw packets, aggregates flows, and triggers ML inference."""
        logger.info("Starting flow aggregation and ML inference processor loop")
        last_sweep = time.time()

        while not self._stop_event.is_set() or not self._packet_queue.empty():
            try:
                pkt = self._packet_queue.get(timeout=0.5)
                finalized = self._aggregator.add_packet(pkt)
                for flow in finalized:
                    self._analyze_and_store_flow(flow)
            except Empty:
                pass
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")

            # Periodically sweep for timed-out flows (every 1.0s)
            now = time.time()
            if now - last_sweep >= 1.0:
                expired = self._aggregator.sweep_expired(now)
                for flow in expired:
                    self._analyze_and_store_flow(flow)
                last_sweep = now

    def _analyze_and_store_flow(self, flow: NetworkFlow):
        """Extract features, run prediction, save detection, and update counters."""
        try:
            with self._lock:
                self.stats["flows_generated"] += 1

            # Extract 77 features
            features = flow.to_features()

            # Find active ML model
            active_model = ModelRepository().find_active()
            if not active_model:
                logger.warning("No active ML model found for live detection.")
                return

            model_dir = active_model.get("model_dir")
            version = active_model.get("version", "unknown")

            # Run prediction through existing ML pipeline
            raw_pred = predict_single(features=features, model_dir=model_dir, model_version=version)

            # Validate prediction through DetectionPolicy layer
            policy = get_detection_policy()
            decision = policy.validate_prediction(flow, raw_pred)

            pred_label = decision["prediction"]
            is_intrusion = decision["is_intrusion"]
            confidence = decision["confidence"]
            severity = decision["severity"]
            should_alert = decision["should_alert"]

            with self._lock:
                self.stats["flows_analyzed"] += 1
                if is_intrusion:
                    self.stats["intrusions"] += 1
                else:
                    self.stats["normal_traffic"] += 1

            # Store detection in database
            detection_doc = {
                "source_ip": flow.src_ip,
                "destination_ip": flow.dst_ip,
                "source_port": flow.src_port,
                "destination_port": flow.dst_port,
                "protocol": flow.protocol,
                "prediction": pred_label,
                "confidence": confidence,
                "severity": severity,
                "is_intrusion": is_intrusion,
                "model_version": version,
                "mode": "LIVE",
                "batch": False,
                "features": {k: round(v, 4) if isinstance(v, float) else v for k, v in list(features.items())[:12]},
            }
            det_id = DetectionRepository().create(detection_doc)

            # Raise alert if intrusion and policy confirms alert
            if is_intrusion and should_alert:
                alert_doc = {
                    "detection_id": det_id,
                    "source_ip": flow.src_ip,
                    "destination_ip": flow.dst_ip,
                    "source_port": flow.src_port,
                    "destination_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "attack_type": pred_label,
                    "severity": severity,
                    "confidence": confidence,
                    "model_version": version,
                }
                _, is_new_alert = AlertRepository().create_or_aggregate(alert_doc, window_seconds=60.0)
                if is_new_alert:
                    with self._lock:
                        self.stats["alerts"] += 1

            # Broadcast event to in-memory live stream
            with self._lock:
                self._event_id_counter += 1
                event = {
                    "id": self._event_id_counter,
                    "time": datetime.utcnow().strftime("%H:%M:%S"),
                    "timestamp": time.time(),
                    "source_ip": flow.src_ip,
                    "destination_ip": flow.dst_ip,
                    "source_port": flow.src_port,
                    "destination_port": flow.dst_port,
                    "protocol": flow.protocol,
                    "prediction": pred_label,
                    "severity": severity,
                    "confidence": confidence,
                    "is_intrusion": is_intrusion,
                    "mode": "LIVE",
                    "validation_note": decision.get("validation_note", ""),
                }
                self._events.append(event)

        except Exception as e:
            logger.error(f"Error analyzing flow: {e}")


# Singleton instance
_service_instance = None
_instance_lock = threading.Lock()


def get_capture_service() -> CaptureService:
    global _service_instance
    with _instance_lock:
        if _service_instance is None:
            _service_instance = CaptureService()
        return _service_instance
