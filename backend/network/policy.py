"""
Detection Policy & Security Validation Engine.
Acts as a verification layer between ML model inference and alert generation:
- Filters/normalizes legitimate infrastructure traffic (multicast, broadcast, mDNS, SSDP, DHCP, DNS).
- Enforces behavioral correlation (e.g. PortScan requires multi-port probing over a time window).
- Enforces volumetric checks for DoS/DDoS.
- Applies configurable confidence thresholds.
- Deduplicates and aggregates security alerts to prevent alert storms.
"""
import os
import time
import ipaddress
import threading
from collections import deque, defaultdict
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Standard infrastructure port mappings
INFRASTRUCTURE_PORTS = {
    53: "DNS",
    67: "DHCP_SERVER",
    68: "DHCP_CLIENT",
    123: "NTP",
    137: "NETBIOS_NS",
    138: "NETBIOS_DGM",
    1900: "SSDP",
    3702: "WS_DISCOVERY",
    5353: "MDNS",
    5355: "LLMNR",
}


class DetectionPolicy:
    """
    Validates ML predictions against network context, temporal correlation,
    and threshold policies before confirming an intrusion and triggering an alert.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Configurable settings (can be overridden via environment variables)
        self.confidence_threshold = float(os.getenv("NIDS_DETECTION_CONFIDENCE_THRESHOLD", "0.75"))
        self.port_scan_window_sec = float(os.getenv("NIDS_PORT_SCAN_WINDOW", "30.0"))
        self.port_scan_min_probes = int(os.getenv("NIDS_PORT_SCAN_MIN_PROBES", "5"))
        self.dedup_window_sec = float(os.getenv("NIDS_DEDUP_WINDOW", "60.0"))

        # In-memory sliding windows
        # {src_ip: deque([(timestamp, dst_ip, dst_port)])}
        self._port_probe_history = defaultdict(deque)

        # Alert deduplication cache:
        # {(src_ip, dst_ip, attack_type): {"alert_id": str, "timestamp": float, "count": int}}
        self._alert_dedup_cache = {}

    def is_infrastructure_traffic(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> bool:
        """
        Detect if flow is legitimate broadcast, multicast, or standard network discovery traffic.
        """
        # 1. Multicast check
        try:
            ip_obj = ipaddress.ip_address(dst_ip)
            if ip_obj.is_multicast:
                return True
            if dst_ip.endswith(".255") or dst_ip == "255.255.255.255":
                return True
        except ValueError:
            pass

        # 2. Local multicast string checks
        if dst_ip.startswith("224.") or dst_ip.startswith("239."):
            return True

        # 3. Known infrastructure discovery ports (SSDP, mDNS, LLMNR, DHCP, NTP, DNS)
        if dst_port in INFRASTRUCTURE_PORTS or src_port in INFRASTRUCTURE_PORTS:
            return True

        return False

    def validate_prediction(self, flow, ml_prediction: dict) -> dict:
        """
        Validate and refine raw ML prediction.
        flow: NetworkFlow object
        ml_prediction: result dict from predict_single()

        Returns validated decision dict:
        {
            "prediction": str,          # Validated category (e.g. BENIGN, PortScan)
            "is_intrusion": bool,        # True only if genuine validated attack
            "confidence": float,        # Calibrated confidence
            "severity": str,            # LOW, MEDIUM, HIGH, CRITICAL
            "should_alert": bool,       # True only if an alert should be created
            "validation_note": str,     # Explanation of policy decision
            "is_duplicate": bool,       # True if already alerted recently
            "dedup_key": tuple          # Cache key for deduplication
        }
        """
        raw_attack = ml_prediction["prediction"]
        raw_conf = ml_prediction["confidence"]
        raw_sev = ml_prediction["severity"]

        src_ip = flow.src_ip
        dst_ip = flow.dst_ip
        src_port = flow.src_port
        dst_port = flow.dst_port
        protocol = flow.protocol
        now = time.time()

        # If model already said BENIGN, no further checks needed
        if raw_attack == "BENIGN":
            return {
                "prediction": "BENIGN",
                "is_intrusion": False,
                "confidence": raw_conf,
                "severity": "LOW",
                "should_alert": False,
                "validation_note": "Classified as normal benign traffic by ML model.",
                "is_duplicate": False,
                "dedup_key": None,
            }

        # ── POLICY 1: Infrastructure & Broadcast Traffic Normalization ─────────────
        if self.is_infrastructure_traffic(src_ip, dst_ip, src_port, dst_port, protocol):
            # Normal network discovery / DNS / DHCP / mDNS / SSDP
            # Unless it is an extreme volumetric flood, treat as benign
            total_pkts = len(flow.fwd_packet_lengths) + len(flow.bwd_packet_lengths)
            if total_pkts < 100:
                logger.debug(f"Normalizing infrastructure flow to BENIGN: {src_ip} -> {dst_ip}:{dst_port} ({protocol})")
                return {
                    "prediction": "BENIGN",
                    "is_intrusion": False,
                    "confidence": 0.95,
                    "severity": "LOW",
                    "should_alert": False,
                    "validation_note": f"Normal infrastructure network traffic ({dst_ip}:{dst_port} {protocol}).",
                    "is_duplicate": False,
                    "dedup_key": None,
                }

        # ── POLICY 2: PortScan Temporal Correlation ────────────────────────────────
        if raw_attack == "PortScan":
            with self._lock:
                probe_deque = self._port_probe_history[src_ip]
                # Expire old entries
                while probe_deque and (now - probe_deque[0][0]) > self.port_scan_window_sec:
                    probe_deque.popleft()

                # Add current target
                probe_deque.append((now, dst_ip, dst_port))

                # Count distinct (dst_ip, dst_port) pairs
                distinct_targets = len(set((item[1], item[2]) for item in probe_deque))

                if distinct_targets < self.port_scan_min_probes:
                    # Isolated probe — insufficient evidence for PortScan attack
                    logger.debug(f"PortScan unconfirmed (probes: {distinct_targets}/{self.port_scan_min_probes}) for {src_ip}")
                    return {
                        "prediction": "BENIGN",
                        "is_intrusion": False,
                        "confidence": 0.85,
                        "severity": "LOW",
                        "should_alert": False,
                        "validation_note": f"Single/isolated connection to port {dst_port} (PortScan requires >={self.port_scan_min_probes} probes).",
                        "is_duplicate": False,
                        "dedup_key": None,
                    }

        # ── POLICY 3: DoS / DDoS Volumetric Verification ───────────────────────────
        if raw_attack in ("DoS", "DDoS"):
            total_pkts = len(flow.fwd_packet_lengths) + len(flow.bwd_packet_lengths)
            dur = max(0.0001, flow.last_seen_time - flow.start_time)
            rate = total_pkts / dur
            syn_ratio = flow.syn_count / max(1, total_pkts)

            # DoS requires either high packet rate, flood volume, or high SYN ratio
            if total_pkts < 20 and rate < 50 and syn_ratio < 0.70:
                logger.debug(f"DoS unconfirmed (pkts={total_pkts}, rate={rate:.1f}/s, syn_ratio={syn_ratio:.2f}) for {src_ip}")
                return {
                    "prediction": "BENIGN",
                    "is_intrusion": False,
                    "confidence": 0.85,
                    "severity": "LOW",
                    "should_alert": False,
                    "validation_note": "Normal traffic volume (insufficient volumetric evidence for DoS).",
                    "is_duplicate": False,
                    "dedup_key": None,
                }

        # ── POLICY 4: Confidence Threshold Check ──────────────────────────────────
        if raw_conf < self.confidence_threshold:
            logger.debug(f"Intrusion {raw_attack} rejected due to low confidence ({raw_conf} < {self.confidence_threshold})")
            return {
                "prediction": "BENIGN",
                "is_intrusion": False,
                "confidence": raw_conf,
                "severity": "LOW",
                "should_alert": False,
                "validation_note": f"ML confidence ({raw_conf:.2f}) below detection threshold ({self.confidence_threshold:.2f}).",
                "is_duplicate": False,
                "dedup_key": None,
            }

        # ── POLICY 5: Alert Deduplication & Aggregation ────────────────────────────
        dedup_key = (src_ip, dst_ip, raw_attack)
        is_duplicate = False

        with self._lock:
            cached = self._alert_dedup_cache.get(dedup_key)
            if cached and (now - cached["timestamp"]) < self.dedup_window_sec:
                cached["count"] += 1
                cached["timestamp"] = now
                is_duplicate = True
            else:
                self._alert_dedup_cache[dedup_key] = {
                    "timestamp": now,
                    "count": 1,
                }

        return {
            "prediction": raw_attack,
            "is_intrusion": True,
            "confidence": raw_conf,
            "severity": raw_sev,
            "should_alert": not is_duplicate,  # Only create alert if not duplicate
            "validation_note": f"Confirmed {raw_attack} intrusion with {raw_conf * 100:.1f}% confidence.",
            "is_duplicate": is_duplicate,
            "dedup_key": dedup_key,
        }


# Singleton policy engine
_policy_instance = None
_policy_lock = threading.Lock()


def get_detection_policy() -> DetectionPolicy:
    global _policy_instance
    with _policy_lock:
        if _policy_instance is None:
            _policy_instance = DetectionPolicy()
        return _policy_instance
