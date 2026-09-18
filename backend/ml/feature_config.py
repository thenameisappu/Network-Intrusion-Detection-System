"""
Feature configuration for network-flow data.
Defines expected features, their types, and column name variations
for CIC-IDS2017 and compatible datasets.
"""

# The canonical feature list used by the model.
# Order matters — must match the trained feature set.
FEATURE_NAMES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Column name aliases — maps lower-cased variants to canonical names
COLUMN_ALIASES = {
    "flow duration": "Flow Duration",
    "total fwd packets": "Total Fwd Packets",
    "total backward packets": "Total Backward Packets",
    "totlen fwd packets": "Total Length of Fwd Packets",
    "totlen bwd packets": "Total Length of Bwd Packets",
    "total length of fwd packets": "Total Length of Fwd Packets",
    "total length of bwd packets": "Total Length of Bwd Packets",
    "fwd packet length max": "Fwd Packet Length Max",
    "fwd packet length min": "Fwd Packet Length Min",
    "fwd packet length mean": "Fwd Packet Length Mean",
    "fwd packet length std": "Fwd Packet Length Std",
    "bwd packet length max": "Bwd Packet Length Max",
    "bwd packet length min": "Bwd Packet Length Min",
    "bwd packet length mean": "Bwd Packet Length Mean",
    "bwd packet length std": "Bwd Packet Length Std",
    "flow bytes/s": "Flow Bytes/s",
    "flow packets/s": "Flow Packets/s",
    "flow iat mean": "Flow IAT Mean",
    "flow iat std": "Flow IAT Std",
    "flow iat max": "Flow IAT Max",
    "flow iat min": "Flow IAT Min",
    "fwd iat total": "Fwd IAT Total",
    "fwd iat mean": "Fwd IAT Mean",
    "fwd iat std": "Fwd IAT Std",
    "fwd iat max": "Fwd IAT Max",
    "fwd iat min": "Fwd IAT Min",
    "bwd iat total": "Bwd IAT Total",
    "bwd iat mean": "Bwd IAT Mean",
    "bwd iat std": "Bwd IAT Std",
    "bwd iat max": "Bwd IAT Max",
    "bwd iat min": "Bwd IAT Min",
    "fwd psh flags": "Fwd PSH Flags",
    "bwd psh flags": "Bwd PSH Flags",
    "fwd urg flags": "Fwd URG Flags",
    "bwd urg flags": "Bwd URG Flags",
    "fwd header length": "Fwd Header Length",
    "bwd header length": "Bwd Header Length",
    "fwd packets/s": "Fwd Packets/s",
    "bwd packets/s": "Bwd Packets/s",
    "min packet length": "Min Packet Length",
    "max packet length": "Max Packet Length",
    "packet length mean": "Packet Length Mean",
    "packet length std": "Packet Length Std",
    "packet length variance": "Packet Length Variance",
    "fin flag count": "FIN Flag Count",
    "syn flag count": "SYN Flag Count",
    "rst flag count": "RST Flag Count",
    "psh flag count": "PSH Flag Count",
    "ack flag count": "ACK Flag Count",
    "urg flag count": "URG Flag Count",
    "cwe flag count": "CWE Flag Count",
    "ece flag count": "ECE Flag Count",
    "down/up ratio": "Down/Up Ratio",
    "average packet size": "Average Packet Size",
    "avg fwd segment size": "Avg Fwd Segment Size",
    "avg bwd segment size": "Avg Bwd Segment Size",
    "fwd avg bytes/bulk": "Fwd Avg Bytes/Bulk",
    "fwd avg packets/bulk": "Fwd Avg Packets/Bulk",
    "fwd avg bulk rate": "Fwd Avg Bulk Rate",
    "bwd avg bytes/bulk": "Bwd Avg Bytes/Bulk",
    "bwd avg packets/bulk": "Bwd Avg Packets/Bulk",
    "bwd avg bulk rate": "Bwd Avg Bulk Rate",
    "subflow fwd packets": "Subflow Fwd Packets",
    "subflow fwd bytes": "Subflow Fwd Bytes",
    "subflow bwd packets": "Subflow Bwd Packets",
    "subflow bwd bytes": "Subflow Bwd Bytes",
    "init_win_bytes_forward": "Init_Win_bytes_forward",
    "init_win_bytes_backward": "Init_Win_bytes_backward",
    "act_data_pkt_fwd": "act_data_pkt_fwd",
    "min_seg_size_forward": "min_seg_size_forward",
    "active mean": "Active Mean",
    "active std": "Active Std",
    "active max": "Active Max",
    "active min": "Active Min",
    "idle mean": "Idle Mean",
    "idle std": "Idle Std",
    "idle max": "Idle Max",
    "idle min": "Idle Min",
}

# Possible label column names
LABEL_COLUMNS = [
    "Label",
    "label",
    " Label",
    "Class",
    "class",
    "Attack",
    "attack",
    "Category",
]

# Columns to drop before training (metadata, IPs, ports)
DROP_COLUMNS = [
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "SimillarHTTP",
    "Inbound",
]

# Minimum required features for a valid prediction
MIN_REQUIRED_FEATURES = 10


def map_columns(df_columns: list) -> dict:
    """
    Build a rename map from uploaded CSV columns to canonical feature names.
    Returns {original_col: canonical_col}
    """
    rename_map = {}
    for col in df_columns:
        stripped = col.strip()
        key = stripped.lower()
        if key in COLUMN_ALIASES:
            rename_map[col] = COLUMN_ALIASES[key]
        elif stripped in FEATURE_NAMES:
            rename_map[col] = stripped
        elif stripped.lower() in [f.lower() for f in FEATURE_NAMES]:
            for f in FEATURE_NAMES:
                if f.lower() == stripped.lower():
                    rename_map[col] = f
                    break
    return rename_map


def find_label_column(df_columns: list) -> str:
    """Find the label column in dataset columns."""
    for col in df_columns:
        if col.strip() in LABEL_COLUMNS:
            return col
    return None
