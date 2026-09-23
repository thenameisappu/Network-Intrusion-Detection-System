"""
Attack label normalization taxonomy.
Maps raw CIC-IDS2017 labels (and variants) to normalized categories.
Unknown labels are reported — never silently misclassified.
"""
import logging

logger = logging.getLogger(__name__)

# Raw label → normalized category
LABEL_MAP = {
    # Benign
    "benign": "BENIGN",
    "normal": "BENIGN",
    # DoS variants
    "dos hulk": "DoS",
    "dos goldeneye": "DoS",
    "dos slowloris": "DoS",
    "dos slowhttptest": "DoS",
    "dos": "DoS",
    "heartbleed": "DoS",
    # DDoS variants
    "ddos": "DDoS",
    "ddos attack-hoic": "DDoS",
    "ddos attack-loic-udp": "DDoS",
    "ddos attack-loic-http": "DDoS",
    # PortScan
    "portscan": "PortScan",
    "port scan": "PortScan",
    "ftp-patator": "Brute Force",
    "ssh-patator": "Brute Force",
    "brute force": "Brute Force",
    "brute-force": "Brute Force",
    # Bot
    "bot": "Bot",
    # Web attacks
    "web attack  brute force": "Web Attack",
    "web attack  xss": "Web Attack",
    "web attack  sql injection": "Web Attack",
    "web attack – brute force": "Web Attack",
    "web attack – xss": "Web Attack",
    "web attack – sql injection": "Web Attack",
    "web attack-brute force": "Web Attack",
    "web attack-xss": "Web Attack",
    "web attack-sql injection": "Web Attack",
    "web attack": "Web Attack",
    # Infiltration
    "infiltration": "Infiltration",
}


def normalize_label(raw_label: str) -> tuple:
    """
    Normalize a raw label string.
    Returns (normalized_label, is_known).
    """
    if raw_label is None:
        return "Unknown", False
    key = str(raw_label).strip().lower()
    normalized = LABEL_MAP.get(key)
    if normalized:
        return normalized, True
    # Partial match fallback
    for pattern, category in LABEL_MAP.items():
        if pattern in key or key in pattern:
            return category, True
    return "Unknown", False


def normalize_labels_series(series):
    """Apply normalize_label to a pandas Series. Returns normalized Series."""
    result = series.apply(lambda x: normalize_label(x)[0])
    unknown_mask = result == "Unknown"
    if unknown_mask.any():
        unknowns = series[unknown_mask].unique().tolist()
        logger.warning(f"Unknown labels found in dataset: {unknowns}")
    return result
