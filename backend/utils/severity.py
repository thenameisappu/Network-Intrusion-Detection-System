"""
Severity assignment rules for detected attacks.
Rules are configuration-driven — not random values.

Severity levels: LOW, MEDIUM, HIGH, CRITICAL
"""
from typing import Dict

# Attack-type → base severity mapping
_ATTACK_SEVERITY: Dict[str, str] = {
    "BENIGN": "LOW",
    "DoS": "HIGH",
    "DDoS": "CRITICAL",
    "PortScan": "MEDIUM",
    "Brute Force": "HIGH",
    "Bot": "HIGH",
    "Web Attack": "HIGH",
    "Infiltration": "CRITICAL",
    "Unknown": "MEDIUM",
}

# Confidence thresholds for severity escalation
_HIGH_CONFIDENCE = 0.85
_LOW_CONFIDENCE = 0.55


def assign_severity(attack_type: str, confidence: float = 1.0) -> str:
    """
    Assign severity based on attack type + model confidence.
    - If confidence is low, cap severity at MEDIUM.
    - If confidence is high for CRITICAL/HIGH, keep as-is.
    """
    base = _ATTACK_SEVERITY.get(attack_type, "MEDIUM")

    if attack_type == "BENIGN":
        return "LOW"

    # Low-confidence detections should not trigger CRITICAL alerts
    if confidence < _LOW_CONFIDENCE:
        if base in ("CRITICAL", "HIGH"):
            return "MEDIUM"
        return "LOW"

    return base
