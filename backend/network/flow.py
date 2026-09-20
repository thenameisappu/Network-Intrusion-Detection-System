"""
Bidirectional 5-Tuple Network Flow and Feature Extraction.
Extracts the exact 77 canonical features matching CIC-IDS2017 dataset
and the active NIDS ML model.
"""
import time
import numpy as np
from backend.ml.feature_config import FEATURE_NAMES


class NetworkFlow:
    """
    Tracks bidirectional network flow between two endpoints.
    5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
    """

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, start_time: float = None):
        # Initiator 5-tuple
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol.upper()

        # Timestamps
        self.start_time = start_time or time.time()
        self.last_seen_time = self.start_time

        # Forward & Backward packet metadata
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.fwd_timestamps = []
        self.bwd_timestamps = []
        self.all_timestamps = [self.start_time]

        # TCP flags
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0

        self.fwd_psh_count = 0
        self.bwd_psh_count = 0
        self.fwd_urg_count = 0
        self.bwd_urg_count = 0

        # Headers and Windows
        self.fwd_header_length = 0
        self.bwd_header_length = 0
        self.init_win_bytes_fwd = 0
        self.init_win_bytes_bwd = 0
        self.min_seg_size_fwd = 20  # default IP header minimum
        self.act_data_pkt_fwd = 0

        # State flags
        self.is_terminated = False

    def add_packet(self, pkt_len: int, src_ip: str, src_port: int, timestamp: float = None,
                   tcp_flags: dict = None, header_len: int = 20, win_size: int = 0, payload_len: int = 0):
        """
        Incorporate a new packet into this flow.
        """
        ts = timestamp or time.time()
        self.last_seen_time = ts
        self.all_timestamps.append(ts)

        # Determine direction relative to flow initiator
        is_forward = (src_ip == self.src_ip and src_port == self.src_port)

        if is_forward:
            self.fwd_packet_lengths.append(pkt_len)
            self.fwd_timestamps.append(ts)
            self.fwd_header_length += header_len
            if self.init_win_bytes_fwd == 0 and win_size > 0:
                self.init_win_bytes_fwd = win_size
            if header_len > 0 and (self.min_seg_size_fwd == 20 or header_len < self.min_seg_size_fwd):
                self.min_seg_size_fwd = header_len
            if payload_len > 0:
                self.act_data_pkt_fwd += 1
        else:
            self.bwd_packet_lengths.append(pkt_len)
            self.bwd_timestamps.append(ts)
            self.bwd_header_length += header_len
            if self.init_win_bytes_bwd == 0 and win_size > 0:
                self.init_win_bytes_bwd = win_size

        # TCP flags aggregation
        if tcp_flags:
            fin = tcp_flags.get("FIN", 0)
            syn = tcp_flags.get("SYN", 0)
            rst = tcp_flags.get("RST", 0)
            psh = tcp_flags.get("PSH", 0)
            ack = tcp_flags.get("ACK", 0)
            urg = tcp_flags.get("URG", 0)
            cwe = tcp_flags.get("CWE", 0)
            ece = tcp_flags.get("ECE", 0)

            self.fin_count += fin
            self.syn_count += syn
            self.rst_count += rst
            self.psh_count += psh
            self.ack_count += ack
            self.urg_count += urg
            self.cwe_count += cwe
            self.ece_count += ece

            if is_forward:
                self.fwd_psh_count += psh
                self.fwd_urg_count += urg
            else:
                self.bwd_psh_count += psh
                self.bwd_urg_count += urg

            # Check for connection termination flags
            if fin > 0 or rst > 0:
                self.is_terminated = True

    def to_features(self) -> dict:
        """
        Calculate and return all 77 canonical CIC-IDS2017 features.
        All units are in microseconds where applicable.
        """
        # Microseconds duration
        dur_sec = max(0.0, self.last_seen_time - self.start_time)
        flow_duration_us = float(dur_sec * 1e6)
        dur_for_rate = max(dur_sec, 0.000001)  # avoid div by zero

        total_fwd_pkts = len(self.fwd_packet_lengths)
        total_bwd_pkts = len(self.bwd_packet_lengths)
        total_pkts = total_fwd_pkts + total_bwd_pkts

        tot_len_fwd = sum(self.fwd_packet_lengths)
        tot_len_bwd = sum(self.bwd_packet_lengths)
        total_bytes = tot_len_fwd + tot_len_bwd

        # Forward packet stats
        if total_fwd_pkts > 0:
            fwd_max = float(np.max(self.fwd_packet_lengths))
            fwd_min = float(np.min(self.fwd_packet_lengths))
            fwd_mean = float(np.mean(self.fwd_packet_lengths))
            fwd_std = float(np.std(self.fwd_packet_lengths))
        else:
            fwd_max = fwd_min = fwd_mean = fwd_std = 0.0

        # Backward packet stats
        if total_bwd_pkts > 0:
            bwd_max = float(np.max(self.bwd_packet_lengths))
            bwd_min = float(np.min(self.bwd_packet_lengths))
            bwd_mean = float(np.mean(self.bwd_packet_lengths))
            bwd_std = float(np.std(self.bwd_packet_lengths))
        else:
            bwd_max = bwd_min = bwd_mean = bwd_std = 0.0

        # All packet stats
        all_lengths = self.fwd_packet_lengths + self.bwd_packet_lengths
        if all_lengths:
            pkt_min = float(np.min(all_lengths))
            pkt_max = float(np.max(all_lengths))
            pkt_mean = float(np.mean(all_lengths))
            pkt_std = float(np.std(all_lengths))
            pkt_var = float(np.var(all_lengths))
            avg_pkt_size = pkt_mean
        else:
            pkt_min = pkt_max = pkt_mean = pkt_std = pkt_var = avg_pkt_size = 0.0

        # Rates
        flow_bytes_s = float(total_bytes / dur_for_rate)
        flow_pkts_s = float(total_pkts / dur_for_rate)
        fwd_pkts_s = float(total_fwd_pkts / dur_for_rate)
        bwd_pkts_s = float(total_bwd_pkts / dur_for_rate)

        # Inter-Arrival Times (IAT) in microseconds
        flow_iats = self._calc_iats(self.all_timestamps)
        flow_iat_mean = float(np.mean(flow_iats)) if flow_iats else 0.0
        flow_iat_std = float(np.std(flow_iats)) if flow_iats else 0.0
        flow_iat_max = float(np.max(flow_iats)) if flow_iats else 0.0
        flow_iat_min = float(np.min(flow_iats)) if flow_iats else 0.0

        fwd_iats = self._calc_iats(self.fwd_timestamps)
        fwd_iat_tot = float(np.sum(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_mean = float(np.mean(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_std = float(np.std(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_max = float(np.max(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_min = float(np.min(fwd_iats)) if fwd_iats else 0.0

        bwd_iats = self._calc_iats(self.bwd_timestamps)
        bwd_iat_tot = float(np.sum(bwd_iats)) if bwd_iats else 0.0
        bwd_iat_mean = float(np.mean(bwd_iats)) if bwd_iats else 0.0
        bwd_iat_std = float(np.std(bwd_iats)) if bwd_iats else 0.0
        bwd_iat_max = float(np.max(bwd_iats)) if bwd_iats else 0.0
        bwd_iat_min = float(np.min(bwd_iats)) if bwd_iats else 0.0

        # Down/Up Ratio
        down_up_ratio = float(total_bwd_pkts / total_fwd_pkts) if total_fwd_pkts > 0 else 0.0

        # Active & Idle calculation (idle threshold = 1.0 second = 1,000,000 us)
        active_times, idle_times = self._calc_active_idle(self.all_timestamps, threshold_us=1000000.0)
        active_mean = float(np.mean(active_times)) if active_times else flow_duration_us
        active_std = float(np.std(active_times)) if active_times else 0.0
        active_max = float(np.max(active_times)) if active_times else flow_duration_us
        active_min = float(np.min(active_times)) if active_times else flow_duration_us

        idle_mean = float(np.mean(idle_times)) if idle_times else 0.0
        idle_std = float(np.std(idle_times)) if idle_times else 0.0
        idle_max = float(np.max(idle_times)) if idle_times else 0.0
        idle_min = float(np.min(idle_times)) if idle_times else 0.0

        # Build complete feature dictionary matching canonical FEATURE_NAMES
        features = {
            "Flow Duration": flow_duration_us,
            "Total Fwd Packets": total_fwd_pkts,
            "Total Backward Packets": total_bwd_pkts,
            "Total Length of Fwd Packets": float(tot_len_fwd),
            "Total Length of Bwd Packets": float(tot_len_bwd),
            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,
            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": fwd_iat_tot,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": bwd_iat_tot,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": self.fwd_psh_count,
            "Bwd PSH Flags": self.bwd_psh_count,
            "Fwd URG Flags": self.fwd_urg_count,
            "Bwd URG Flags": self.bwd_urg_count,
            "Fwd Header Length": float(self.fwd_header_length),
            "Bwd Header Length": float(self.bwd_header_length),
            "Fwd Packets/s": fwd_pkts_s,
            "Bwd Packets/s": bwd_pkts_s,
            "Min Packet Length": pkt_min,
            "Max Packet Length": pkt_max,
            "Packet Length Mean": pkt_mean,
            "Packet Length Std": pkt_std,
            "Packet Length Variance": pkt_var,
            "FIN Flag Count": self.fin_count,
            "SYN Flag Count": self.syn_count,
            "RST Flag Count": self.rst_count,
            "PSH Flag Count": self.psh_count,
            "ACK Flag Count": self.ack_count,
            "URG Flag Count": self.urg_count,
            "CWE Flag Count": self.cwe_count,
            "ECE Flag Count": self.ece_count,
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_pkt_size,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": float(total_fwd_pkts),
            "Subflow Fwd Bytes": float(tot_len_fwd),
            "Subflow Bwd Packets": float(total_bwd_pkts),
            "Subflow Bwd Bytes": float(tot_len_bwd),
            "Init_Win_bytes_forward": float(self.init_win_bytes_fwd),
            "Init_Win_bytes_backward": float(self.init_win_bytes_bwd),
            "act_data_pkt_fwd": float(self.act_data_pkt_fwd),
            "min_seg_size_forward": float(self.min_seg_size_fwd),
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,
        }

        # Validate that all canonical features exist
        for k in FEATURE_NAMES:
            if k not in features:
                features[k] = 0.0

        return features

    @staticmethod
    def _calc_iats(timestamps: list) -> list:
        """Calculate inter-arrival times in microseconds."""
        if len(timestamps) < 2:
            return []
        sorted_ts = sorted(timestamps)
        return [(sorted_ts[i] - sorted_ts[i - 1]) * 1e6 for i in range(1, len(sorted_ts))]

    @staticmethod
    def _calc_active_idle(timestamps: list, threshold_us: float = 1000000.0) -> tuple:
        """Partition durations into active and idle microsecond periods."""
        if len(timestamps) < 2:
            return [], []

        sorted_ts = sorted(timestamps)
        active_periods = []
        idle_periods = []

        cur_active_start = sorted_ts[0]
        prev_ts = sorted_ts[0]

        for ts in sorted_ts[1:]:
            iat_us = (ts - prev_ts) * 1e6
            if iat_us > threshold_us:
                # Idle threshold crossed
                active_dur = (prev_ts - cur_active_start) * 1e6
                if active_dur > 0:
                    active_periods.append(active_dur)
                idle_periods.append(iat_us)
                cur_active_start = ts
            prev_ts = ts

        final_active = (prev_ts - cur_active_start) * 1e6
        if final_active > 0:
            active_periods.append(final_active)

        return active_periods, idle_periods
