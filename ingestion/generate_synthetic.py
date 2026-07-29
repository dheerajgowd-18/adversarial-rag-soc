"""
ingestion/generate_synthetic.py — Synthetic alert generator for testing.

Generates realistic fake CICIDS2017-style alerts WITHOUT needing the
real dataset. Used for:

  1. Testing the full pipeline (ingestion → agent → eval) while waiting
     for the real dataset download.
  2. Unit testing all downstream components.
  3. Demonstrating the project to reviewers without data access.

The synthetic alerts conform to EXACTLY the same schema as real alerts.
Downstream code cannot tell the difference — the schema is identical.

Run:
    python ingestion/generate_synthetic.py
    python ingestion/generate_synthetic.py --count 500  # generate 500 alerts

Output:
    Same files as build_alerts.py:
    data/alerts/clean_alerts.json
    data/alerts/suspicious_queue.json
    data/alerts/eval_fixed_set.json
    logs/synthetic_generation.log
"""

import sys
import json
import logging
import argparse
import random
from datetime import datetime
from pathlib import Path

# ── Force UTF-8 console output on Windows ─────────────────────────────────
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import cfg
from ingestion.schema import Alert, ATTACK_TYPE_MAP, SEVERITY_MAP, make_alert_id
from ingestion.build_alerts import build_eval_set, save_alerts, setup_logging


# ── Realistic IP pools ────────────────────────────────────────────────────────
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 50)]
EXTERNAL_IPS = [
    "45.33.32.156", "104.21.44.89", "198.51.100.42", "203.0.113.17",
    "185.220.101.47", "91.108.4.183", "172.217.169.68", "13.226.200.25",
    "151.101.1.140", "54.230.88.10", "66.220.144.0", "31.13.76.68",
]
WELL_KNOWN_PORTS = [80, 443, 22, 21, 3306, 5432, 8080, 8443, 53, 25]
HIGH_PORTS = list(range(1024, 65535, 100))

# ── Attack type distribution (mimics CICIDS2017 Wednesday + Friday) ──────────
ATTACK_DISTRIBUTION = {
    "benign":       0.55,   # majority benign
    "dos":          0.20,   # DoS is most common attack
    "ddos":         0.08,
    "portscan":     0.07,
    "brute_force":  0.05,
    "heartbleed":   0.02,
    "web_attack":   0.02,
    "botnet":       0.01,
}

# Reverse map: attack_type → example label
LABEL_MAP = {
    "benign":       "BENIGN",
    "dos":          "DoS Hulk",
    "ddos":         "DDoS",
    "portscan":     "PortScan",
    "brute_force":  "SSH-Patator",
    "heartbleed":   "Heartbleed",
    "web_attack":   "Web Attack – XSS",
    "botnet":       "Bot",
}


def weighted_choice(distribution: dict) -> str:
    """Choose a key from a dict weighted by its float values."""
    keys = list(distribution.keys())
    weights = list(distribution.values())
    return random.choices(keys, weights=weights, k=1)[0]


def random_ip(pool: list) -> str:
    return random.choice(pool)


def generate_synthetic_alert(index: int, seed_offset: int = 0) -> Alert:
    """Generate one synthetic alert with realistic values."""
    random.seed(42 + index + seed_offset)

    attack_type = weighted_choice(ATTACK_DISTRIBUTION)
    is_malicious = attack_type != "benign"
    label = LABEL_MAP[attack_type]
    severity = SEVERITY_MAP[attack_type]

    # Network features vary by attack type
    if attack_type == "benign":
        src_ip = random_ip(INTERNAL_IPS)
        dst_ip = random_ip(EXTERNAL_IPS)
        src_port = random.choice(HIGH_PORTS)
        dst_port = random.choice(WELL_KNOWN_PORTS)
        protocol = random.choice(["TCP", "TCP", "TCP", "UDP"])
        flow_duration = random.uniform(1000, 5_000_000)
        fwd_packets = random.randint(5, 200)
        bwd_packets = random.randint(3, 150)
        flow_bps = random.uniform(100, 50_000)
        pkt_mean = random.uniform(40, 1400)
        syn = random.randint(1, 3)
        fin = random.randint(1, 3)
        rst = 0

    elif attack_type == "dos":
        src_ip = random_ip(EXTERNAL_IPS)
        dst_ip = random_ip(INTERNAL_IPS)
        src_port = random.choice(HIGH_PORTS)
        dst_port = random.choice([80, 443, 8080])
        protocol = "TCP"
        flow_duration = random.uniform(10, 500_000)
        fwd_packets = random.randint(500, 50_000)
        bwd_packets = random.randint(0, 10)
        flow_bps = random.uniform(100_000, 10_000_000)
        pkt_mean = random.uniform(40, 100)
        syn = random.randint(100, 10_000)
        fin = 0
        rst = random.randint(0, 5)

    elif attack_type == "ddos":
        src_ip = random_ip(EXTERNAL_IPS)
        dst_ip = random_ip(INTERNAL_IPS)
        src_port = random.choice(HIGH_PORTS)
        dst_port = random.choice([80, 443])
        protocol = random.choice(["TCP", "UDP"])
        flow_duration = random.uniform(1, 100_000)
        fwd_packets = random.randint(1000, 100_000)
        bwd_packets = random.randint(0, 5)
        flow_bps = random.uniform(1_000_000, 100_000_000)
        pkt_mean = random.uniform(40, 60)
        syn = random.randint(1000, 50_000)
        fin = 0
        rst = 0

    elif attack_type == "portscan":
        src_ip = random_ip(EXTERNAL_IPS)
        dst_ip = random_ip(INTERNAL_IPS)
        src_port = random.choice(HIGH_PORTS)
        dst_port = random.randint(1, 65535)
        protocol = "TCP"
        flow_duration = random.uniform(1, 5_000)
        fwd_packets = random.randint(1, 3)
        bwd_packets = random.randint(0, 1)
        flow_bps = random.uniform(100, 5_000)
        pkt_mean = random.uniform(40, 60)
        syn = 1
        fin = 0
        rst = random.randint(0, 1)

    elif attack_type == "brute_force":
        src_ip = random_ip(EXTERNAL_IPS)
        dst_ip = random_ip(INTERNAL_IPS)
        src_port = random.choice(HIGH_PORTS)
        dst_port = random.choice([22, 21])
        protocol = "TCP"
        flow_duration = random.uniform(100_000, 1_000_000)
        fwd_packets = random.randint(10, 100)
        bwd_packets = random.randint(8, 80)
        flow_bps = random.uniform(500, 10_000)
        pkt_mean = random.uniform(50, 200)
        syn = random.randint(5, 50)
        fin = random.randint(5, 50)
        rst = 0

    elif attack_type == "heartbleed":
        src_ip = random_ip(EXTERNAL_IPS)
        dst_ip = random_ip(INTERNAL_IPS)
        src_port = random.choice(HIGH_PORTS)
        dst_port = 443
        protocol = "TCP"
        flow_duration = random.uniform(50_000, 500_000)
        fwd_packets = random.randint(5, 20)
        bwd_packets = random.randint(3, 15)
        flow_bps = random.uniform(1_000, 50_000)
        pkt_mean = random.uniform(100, 300)
        syn = 1
        fin = 0
        rst = 0

    else:  # web_attack, botnet, unknown
        src_ip = random_ip(EXTERNAL_IPS)
        dst_ip = random_ip(INTERNAL_IPS)
        src_port = random.choice(HIGH_PORTS)
        dst_port = random.choice([80, 443, 8080])
        protocol = "TCP"
        flow_duration = random.uniform(10_000, 2_000_000)
        fwd_packets = random.randint(20, 500)
        bwd_packets = random.randint(10, 300)
        flow_bps = random.uniform(1_000, 100_000)
        pkt_mean = random.uniform(60, 800)
        syn = random.randint(1, 10)
        fin = random.randint(1, 10)
        rst = random.randint(0, 3)

    fwd_bytes = fwd_packets * int(pkt_mean)
    bwd_bytes = bwd_packets * int(pkt_mean * 0.8)

    from ingestion.build_alerts import make_notes_field
    row_dict = {
        "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port,
        "dst_port": dst_port, "protocol": protocol,
        "flow_duration": flow_duration, "fwd_packets": fwd_packets,
        "bwd_packets": bwd_packets, "flow_bytes_per_sec": flow_bps,
    }
    notes = make_notes_field(row_dict, attack_type, label)

    return Alert(
        alert_id=make_alert_id("synthetic", index),
        source_file="synthetic",
        row_index=index,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        flow_duration_us=flow_duration,
        fwd_packets=fwd_packets,
        bwd_packets=bwd_packets,
        total_bytes=fwd_bytes + bwd_bytes,
        flow_bytes_per_sec=flow_bps,
        packet_length_mean=pkt_mean,
        syn_flag_count=syn,
        fin_flag_count=fin,
        rst_flag_count=rst,
        label_ground_truth=label,
        attack_type=attack_type,
        severity=severity,
        is_malicious=is_malicious,
        notes_field=notes,
        condition="baseline",
        injection_payload=None,
        injection_category=None,
        timestamp_ingested=datetime.utcnow().isoformat() + "Z",
    )


def main(count: int, logger: logging.Logger) -> None:
    logger.info(f"Generating {count} synthetic alerts...")

    alerts = [generate_synthetic_alert(i) for i in range(count)]

    # Stats
    dist = {}
    for a in alerts:
        dist[a.attack_type] = dist.get(a.attack_type, 0) + 1
    logger.info("Class distribution:")
    for k, v in sorted(dist.items(), key=lambda x: -x[1]):
        logger.info(f"  {k:<20} {v:>5} ({100*v/count:.1f}%)")

    # Save outputs
    save_alerts(alerts, cfg.CLEAN_ALERTS_PATH, logger)

    suspicious = [a for a in alerts if a.is_malicious]
    save_alerts(suspicious, cfg.SUSPICIOUS_QUEUE_PATH, logger)

    eval_set = build_eval_set(alerts, target_size=min(200, count // 5), logger=logger)
    save_alerts(eval_set, cfg.EVAL_FIXED_SET_PATH, logger)

    logger.info("\n" + "=" * 50)
    logger.info("Synthetic generation COMPLETE ✅")
    logger.info(f"  clean_alerts.json     : {len(alerts)}")
    logger.info(f"  suspicious_queue.json : {len(suspicious)}")
    logger.info(f"  eval_fixed_set.json   : {len(eval_set)}")
    logger.info("  NOTE: Replace with real CICIDS2017 data before paper runs")
    logger.info("=" * 50)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate synthetic alerts for testing")
    parser.add_argument("--count", type=int, default=1000,
                        help="Number of alerts to generate (default: 1000)")
    args = parser.parse_args()

    logger = setup_logging()
    cfg.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Use a dedicated log file for synthetic
    for h in logger.handlers:
        if isinstance(h, logging.FileHandler):
            h.close()
            logger.removeHandler(h)

    fh = logging.FileHandler(cfg.LOGS_DIR / "synthetic_generation.log", mode="w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s"))
    logger.addHandler(fh)

    logger.info("=" * 50)
    logger.info("Synthetic Alert Generator")
    logger.info(f"  Count : {args.count}")
    logger.info("=" * 50)

    main(args.count, logger)
