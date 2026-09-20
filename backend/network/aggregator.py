"""
Flow Aggregator for grouping live packets into bidirectional 5-tuple flows.
Handles state tracking, active/idle timeouts, and connection termination.
"""
import time
import threading
from typing import Dict, List, Tuple
from backend.network.flow import NetworkFlow
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class FlowAggregator:
    """
    Thread-safe aggregator that maps raw network packets into NetworkFlow objects.
    """

    def __init__(self, active_timeout: float = 15.0, idle_timeout: float = 5.0):
        """
        active_timeout: Max duration in seconds before an ongoing flow is flushed.
        idle_timeout: Max inactivity in seconds before an idle flow is flushed.
        """
        self.active_timeout = active_timeout
        self.idle_timeout = idle_timeout
        self._flows: Dict[Tuple, NetworkFlow] = {}
        self._lock = threading.Lock()

    @staticmethod
    def make_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> Tuple:
        """
        Create a canonical direction-independent flow key.
        """
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 <= ep2:
            return (protocol.upper(), ep1, ep2)
        return (protocol.upper(), ep2, ep1)

    def add_packet(self, pkt: dict) -> List[NetworkFlow]:
        """
        Ingest a packet dict into the aggregator.
        Returns a list of finalized flows if any (e.g. on TCP FIN/RST).
        """
        src_ip = pkt.get("src_ip", "0.0.0.0")
        dst_ip = pkt.get("dst_ip", "0.0.0.0")
        src_port = int(pkt.get("src_port", 0))
        dst_port = int(pkt.get("dst_port", 0))
        protocol = str(pkt.get("protocol", "IP")).upper()
        pkt_len = int(pkt.get("pkt_len", 60))
        timestamp = float(pkt.get("timestamp") or time.time())
        tcp_flags = pkt.get("tcp_flags") or {}
        header_len = int(pkt.get("header_len", 20))
        win_size = int(pkt.get("win_size", 0))
        payload_len = int(pkt.get("payload_len", 0))

        key = self.make_key(src_ip, dst_ip, src_port, dst_port, protocol)
        finalized = []

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                # First packet seen establishes forward direction
                flow = NetworkFlow(src_ip, dst_ip, src_port, dst_port, protocol, start_time=timestamp)
                self._flows[key] = flow

            flow.add_packet(
                pkt_len=pkt_len,
                src_ip=src_ip,
                src_port=src_port,
                timestamp=timestamp,
                tcp_flags=tcp_flags,
                header_len=header_len,
                win_size=win_size,
                payload_len=payload_len,
            )

            # If terminated (TCP FIN or RST) or exceeded active timeout
            dur = timestamp - flow.start_time
            if flow.is_terminated or dur >= self.active_timeout:
                self._flows.pop(key, None)
                finalized.append(flow)

        return finalized

    def sweep_expired(self, current_time: float = None) -> List[NetworkFlow]:
        """
        Check for flows that have timed out (idle or active).
        Removes and returns finalized flows.
        """
        now = current_time or time.time()
        finalized = []

        with self._lock:
            expired_keys = []
            for key, flow in self._flows.items():
                dur = now - flow.start_time
                idle = now - flow.last_seen_time
                if dur >= self.active_timeout or idle >= self.idle_timeout or flow.is_terminated:
                    expired_keys.append(key)
                    finalized.append(flow)

            for k in expired_keys:
                self._flows.pop(k, None)

        return finalized

    def flush_all(self) -> List[NetworkFlow]:
        """
        Flush and return all remaining flows immediately.
        """
        with self._lock:
            finalized = list(self._flows.values())
            self._flows.clear()
        return finalized

    def count_active(self) -> int:
        """Return number of currently active flows."""
        with self._lock:
            return len(self._flows)
