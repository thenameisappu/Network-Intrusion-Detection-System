"""
Generate synthetic CIC-IDS2017 format CSV for demonstration.
This creates a realistic training dataset with proper class balance.
Run: python scripts/generate_sample_data.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
import random

np.random.seed(42)
random.seed(42)

OUTPUT_DIR = "dataset/sample"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "sample_nids_data.csv")
N_SAMPLES = 10000

os.makedirs(OUTPUT_DIR, exist_ok=True)

ATTACK_CLASSES = {
    "BENIGN": 0.50,
    "DoS Hulk": 0.12,
    "PortScan": 0.10,
    "DDoS": 0.08,
    "DoS GoldenEye": 0.05,
    "FTP-Patator": 0.05,
    "SSH-Patator": 0.04,
    "DoS slowloris": 0.03,
    "DoS Slowhttptest": 0.02,
    "Bot": 0.01,
}

FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

METADATA = [
    "Flow ID", "Source IP", "Destination IP", "Source Port",
    "Destination Port", "Protocol", "Timestamp",
]

def random_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_benign_features():
    # 45% of real network benign flows are UDP or short-lived traffic (DNS, mDNS, SSDP, DHCP, NTP, ping)
    is_udp_or_short = np.random.random() < 0.45

    if is_udp_or_short:
        has_response = np.random.random() < 0.70
        fwd_pkts = np.random.randint(1, 6)
        bwd_pkts = np.random.randint(1, 6) if has_response else 0
        tot_fwd_len = fwd_pkts * np.random.randint(32, 250)
        tot_bwd_len = bwd_pkts * np.random.randint(40, 600) if bwd_pkts > 0 else 0
        dur = np.random.exponential(15000)

        return {
            "Flow Duration": max(10.0, dur),
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": float(tot_fwd_len),
            "Total Length of Bwd Packets": float(tot_bwd_len),
            "Fwd Packet Length Max": float(tot_fwd_len / fwd_pkts),
            "Fwd Packet Length Min": float(tot_fwd_len / fwd_pkts * 0.8),
            "Fwd Packet Length Mean": float(tot_fwd_len / fwd_pkts),
            "Fwd Packet Length Std": 0.0 if fwd_pkts == 1 else float(np.random.uniform(0, 40)),
            "Bwd Packet Length Max": float(tot_bwd_len / bwd_pkts) if bwd_pkts else 0.0,
            "Bwd Packet Length Min": float(tot_bwd_len / bwd_pkts * 0.8) if bwd_pkts else 0.0,
            "Bwd Packet Length Mean": float(tot_bwd_len / bwd_pkts) if bwd_pkts else 0.0,
            "Bwd Packet Length Std": float(np.random.uniform(0, 50)) if bwd_pkts > 1 else 0.0,
            "Flow Bytes/s": float((tot_fwd_len + tot_bwd_len) / max(dur / 1e6, 0.0001)),
            "Flow Packets/s": float((fwd_pkts + bwd_pkts) / max(dur / 1e6, 0.0001)),
            "Flow IAT Mean": float(np.random.exponential(2000)),
            "Flow IAT Std": float(np.random.uniform(0, 1000)),
            "Flow IAT Max": float(np.random.exponential(8000)),
            "Flow IAT Min": float(np.random.uniform(0, 200)),
            "Fwd IAT Total": float(np.random.exponential(10000)),
            "Fwd IAT Mean": float(np.random.exponential(2000)),
            "Fwd IAT Std": float(np.random.uniform(0, 1000)),
            "Fwd IAT Max": float(np.random.exponential(6000)),
            "Fwd IAT Min": float(np.random.uniform(0, 200)),
            "Bwd IAT Total": float(np.random.exponential(10000)) if bwd_pkts else 0.0,
            "Bwd IAT Mean": float(np.random.exponential(2000)) if bwd_pkts else 0.0,
            "Bwd IAT Std": float(np.random.uniform(0, 1000)) if bwd_pkts else 0.0,
            "Bwd IAT Max": float(np.random.exponential(6000)) if bwd_pkts else 0.0,
            "Bwd IAT Min": float(np.random.uniform(0, 200)) if bwd_pkts else 0.0,
            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "Fwd Header Length": float(fwd_pkts * 28),
            "Bwd Header Length": float(bwd_pkts * 28),
            "Fwd Packets/s": float(fwd_pkts / max(dur / 1e6, 0.0001)),
            "Bwd Packets/s": float(bwd_pkts / max(dur / 1e6, 0.0001)),
            "Min Packet Length": float(tot_fwd_len / fwd_pkts * 0.8),
            "Max Packet Length": float(max(tot_fwd_len / fwd_pkts, tot_bwd_len / max(1, bwd_pkts))),
            "Packet Length Mean": float((tot_fwd_len + tot_bwd_len) / (fwd_pkts + max(1, bwd_pkts))),
            "Packet Length Std": float(np.random.uniform(0, 60)),
            "Packet Length Variance": float(np.random.uniform(0, 3600)),
            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Down/Up Ratio": float(bwd_pkts / fwd_pkts),
            "Average Packet Size": float((tot_fwd_len + tot_bwd_len) / (fwd_pkts + max(1, bwd_pkts))),
            "Avg Fwd Segment Size": float(tot_fwd_len / fwd_pkts),
            "Avg Bwd Segment Size": float(tot_bwd_len / bwd_pkts) if bwd_pkts else 0.0,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": float(fwd_pkts),
            "Subflow Fwd Bytes": float(tot_fwd_len),
            "Subflow Bwd Packets": float(bwd_pkts),
            "Subflow Bwd Bytes": float(tot_bwd_len),
            "Init_Win_bytes_forward": 0.0,
            "Init_Win_bytes_backward": 0.0,
            "act_data_pkt_fwd": float(fwd_pkts),
            "min_seg_size_forward": 20.0,
            "Active Mean": float(dur),
            "Active Std": 0.0,
            "Active Max": float(dur),
            "Active Min": float(dur),
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }

    # Standard TCP benign flows
    return {
        "Flow Duration": np.random.exponential(50000),
        "Total Fwd Packets": np.random.randint(2, 30),
        "Total Backward Packets": np.random.randint(1, 25),
        "Total Length of Fwd Packets": np.random.randint(100, 5000),
        "Total Length of Bwd Packets": np.random.randint(50, 4000),
        "Fwd Packet Length Max": np.random.randint(40, 1500),
        "Fwd Packet Length Min": np.random.randint(20, 60),
        "Fwd Packet Length Mean": np.random.uniform(30, 800),
        "Fwd Packet Length Std": np.random.uniform(0, 300),
        "Bwd Packet Length Max": np.random.randint(40, 1500),
        "Bwd Packet Length Min": np.random.randint(20, 60),
        "Bwd Packet Length Mean": np.random.uniform(30, 800),
        "Bwd Packet Length Std": np.random.uniform(0, 300),
        "Flow Bytes/s": np.random.uniform(100, 50000),
        "Flow Packets/s": np.random.uniform(1, 100),
        "Flow IAT Mean": np.random.exponential(5000),
        "Flow IAT Std": np.random.uniform(0, 3000),
        "Flow IAT Max": np.random.exponential(20000),
        "Flow IAT Min": np.random.uniform(0, 500),
        "Fwd IAT Total": np.random.exponential(40000),
        "Fwd IAT Mean": np.random.exponential(4000),
        "Fwd IAT Std": np.random.uniform(0, 2000),
        "Fwd IAT Max": np.random.exponential(15000),
        "Fwd IAT Min": np.random.uniform(0, 500),
        "Bwd IAT Total": np.random.exponential(30000),
        "Bwd IAT Mean": np.random.exponential(3000),
        "Bwd IAT Std": np.random.uniform(0, 1500),
        "Bwd IAT Max": np.random.exponential(12000),
        "Bwd IAT Min": np.random.uniform(0, 400),
        "Fwd PSH Flags": np.random.randint(0, 3),
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,
        "Fwd Header Length": np.random.randint(20, 60) * np.random.randint(1, 10),
        "Bwd Header Length": np.random.randint(20, 60) * np.random.randint(1, 10),
        "Fwd Packets/s": np.random.uniform(0.5, 50),
        "Bwd Packets/s": np.random.uniform(0.3, 40),
        "Min Packet Length": np.random.randint(20, 64),
        "Max Packet Length": np.random.randint(500, 1500),
        "Packet Length Mean": np.random.uniform(100, 600),
        "Packet Length Std": np.random.uniform(50, 300),
        "Packet Length Variance": np.random.uniform(100, 5000),
        "FIN Flag Count": np.random.randint(0, 3),
        "SYN Flag Count": np.random.randint(0, 3),
        "RST Flag Count": np.random.randint(0, 2),
        "PSH Flag Count": np.random.randint(0, 5),
        "ACK Flag Count": np.random.randint(1, 20),
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": np.random.uniform(0.5, 3.0),
        "Average Packet Size": np.random.uniform(100, 700),
        "Avg Fwd Segment Size": np.random.uniform(100, 700),
        "Avg Bwd Segment Size": np.random.uniform(80, 600),
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": np.random.randint(1, 20),
        "Subflow Fwd Bytes": np.random.randint(100, 4000),
        "Subflow Bwd Packets": np.random.randint(1, 15),
        "Subflow Bwd Bytes": np.random.randint(50, 3000),
        "Init_Win_bytes_forward": np.random.choice([1024, 2048, 4096, 8192, 16384, 32768, 65535]),
        "Init_Win_bytes_backward": np.random.choice([1024, 2048, 4096, 8192, 16384, 32768]),
        "act_data_pkt_fwd": np.random.randint(1, 15),
        "min_seg_size_forward": 20,
        "Active Mean": np.random.uniform(0, 1000),
        "Active Std": np.random.uniform(0, 500),
        "Active Max": np.random.uniform(100, 3000),
        "Active Min": 0,
        "Idle Mean": np.random.uniform(0, 5000),
        "Idle Std": np.random.uniform(0, 2000),
        "Idle Max": np.random.uniform(500, 20000),
        "Idle Min": 0,
    }

def generate_dos_features():
    f = generate_benign_features()
    f.update({
        "Flow Duration": np.random.uniform(1000, 50000),
        "Total Fwd Packets": np.random.randint(100, 2000),
        "Flow Bytes/s": np.random.uniform(50000, 5000000),
        "Flow Packets/s": np.random.uniform(100, 5000),
        "SYN Flag Count": np.random.randint(50, 500),
        "RST Flag Count": np.random.randint(0, 50),
        "ACK Flag Count": np.random.randint(0, 100),
        "Fwd Packet Length Mean": np.random.uniform(0, 60),
        "Fwd Packet Length Std": np.random.uniform(0, 10),
        "Total Backward Packets": 0,
        "Init_Win_bytes_forward": np.random.choice([0, 1, 2, 4]),
    })
    return f

def generate_portscan_features():
    f = generate_benign_features()
    f.update({
        "Flow Duration": np.random.uniform(0, 500),
        "Total Fwd Packets": 1,
        "Total Backward Packets": np.random.randint(0, 2),
        "Flow Bytes/s": np.random.uniform(100, 2000),
        "Flow Packets/s": np.random.uniform(1000, 10000),
        "SYN Flag Count": 1,
        "ACK Flag Count": 0,
        "RST Flag Count": np.random.randint(0, 2),
        "FIN Flag Count": 0,
        "Fwd Packet Length Mean": np.random.uniform(20, 60),
        "Fwd Packet Length Max": np.random.randint(40, 80),
    })
    return f

def generate_brute_force_features():
    f = generate_benign_features()
    f.update({
        "Total Fwd Packets": np.random.randint(10, 100),
        "Flow Duration": np.random.uniform(100000, 2000000),
        "Fwd IAT Mean": np.random.uniform(100, 10000),
        "Flow Packets/s": np.random.uniform(0.5, 20),
        "SYN Flag Count": np.random.randint(2, 20),
        "FIN Flag Count": np.random.randint(2, 20),
        "ACK Flag Count": np.random.randint(5, 50),
    })
    return f

ATTACK_GENERATORS = {
    "BENIGN": generate_benign_features,
    "DoS Hulk": generate_dos_features,
    "DoS GoldenEye": generate_dos_features,
    "DoS slowloris": generate_dos_features,
    "DoS Slowhttptest": generate_dos_features,
    "DDoS": generate_dos_features,
    "PortScan": generate_portscan_features,
    "FTP-Patator": generate_brute_force_features,
    "SSH-Patator": generate_brute_force_features,
    "Bot": generate_brute_force_features,
}

print(f"Generating {N_SAMPLES} samples...")
rows = []
import datetime

labels = random.choices(
    list(ATTACK_CLASSES.keys()),
    weights=list(ATTACK_CLASSES.values()),
    k=N_SAMPLES,
)

protocols = [6, 17, 0]  # TCP, UDP, ICMP
base_time = datetime.datetime(2017, 7, 7, 10, 0, 0)

for i, label in enumerate(labels):
    gen = ATTACK_GENERATORS.get(label, generate_benign_features)
    features = gen()
    # Add metadata columns
    ts = base_time + datetime.timedelta(seconds=i * 0.5 + random.random())
    row = {
        "Flow ID": f"flow-{i:06d}",
        "Source IP": random_ip(),
        "Destination IP": random_ip(),
        "Source Port": random.randint(1024, 65535),
        "Destination Port": random.choice([80, 443, 22, 21, 53, 8080, 3389, 23]),
        "Protocol": random.choice(protocols),
        "Timestamp": ts.strftime("%d/%m/%Y %I:%M:%S %p"),
    }
    row.update(features)
    row[" Label"] = label
    rows.append(row)

df = pd.DataFrame(rows)
# Ensure all numeric columns are proper floats
for col in FEATURES:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).clip(lower=0)

df.to_csv(OUTPUT_FILE, index=False)
print(f"\n[OK] Sample dataset saved: {OUTPUT_FILE}")
print(f"   Total rows: {len(df)}")
print(f"   Columns: {len(df.columns)}")
print("\nLabel distribution:")
for label, count in df[" Label"].value_counts().items():
    print(f"   {label}: {count} ({count/len(df)*100:.1f}%)")
print("\nYou can now upload this file in the NIDS dashboard under Datasets.")
