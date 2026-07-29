"""
agents/run_detection.py — Phase 2 runner script.

Loads alerts from clean_alerts.json, runs every alert through the
DetectionAgent, and produces:

  data/alerts/detection_results.json   — full per-alert results
  data/alerts/suspicious_queue.json    — SUSPICIOUS alerts only (overwrite)
  logs/detection.log                   — detailed run log + performance metrics

Run:
    python agents/run_detection.py
    python agents/run_detection.py --threshold 0.4   # stricter threshold
    python agents/run_detection.py --input data/alerts/eval_fixed_set.json
"""

import sys
import json
import logging
import argparse
import time
from pathlib import Path
from collections import defaultdict

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import cfg
from ingestion.schema import Alert
from agents.detection_agent import DetectionAgent, SUSPICION_THRESHOLD


# ── Logging setup ─────────────────────────────────────────────────────────────
def setup_logging() -> logging.Logger:
    cfg.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_file = cfg.LOGS_DIR / "detection.log"
    logger = logging.getLogger("detection")
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    ))
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def load_alerts(path: Path, logger: logging.Logger) -> list[Alert]:
    """Load alerts from a JSON file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    alerts = [Alert.from_dict(d) for d in data]
    logger.info(f"Loaded {len(alerts)} alerts from {path.name}")
    return alerts


def compute_metrics(
    alerts: list[Alert],
    results: list,
    logger: logging.Logger,
) -> dict:
    """
    Compute detection performance metrics.

    For a rule-based system we measure:
    - True Positive (TP):  malicious alert correctly flagged SUSPICIOUS
    - True Negative (TN):  benign alert correctly flagged BENIGN
    - False Positive (FP): benign alert wrongly flagged SUSPICIOUS
    - False Negative (FN): malicious alert wrongly flagged BENIGN (MISSED ATTACK)

    In security: FN (missed attack) is worse than FP (false alarm).
    """
    tp = tn = fp = fn = 0
    attack_type_breakdown: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fn": 0, "total": 0})

    for alert, result in zip(alerts, results):
        is_attack = alert.is_malicious
        is_suspicious = result.verdict == "SUSPICIOUS"

        attack_type_breakdown[alert.attack_type]["total"] += 1

        if is_attack and is_suspicious:
            tp += 1
            attack_type_breakdown[alert.attack_type]["tp"] += 1
        elif not is_attack and not is_suspicious:
            tn += 1
        elif not is_attack and is_suspicious:
            fp += 1
        else:  # is_attack and not is_suspicious — MISSED
            fn += 1
            attack_type_breakdown[alert.attack_type]["fn"] += 1

    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # False positive rate

    logger.info("")
    logger.info("=== DETECTION PERFORMANCE METRICS ===")
    logger.info(f"  Total alerts  : {total}")
    logger.info(f"  TP (caught)   : {tp}")
    logger.info(f"  TN (correct)  : {tn}")
    logger.info(f"  FP (false alm): {fp}")
    logger.info(f"  FN (MISSED)   : {fn}  <- attacks that slipped through")
    logger.info("")
    logger.info(f"  Precision     : {precision:.3f}  (of flagged alerts, how many real?)")
    logger.info(f"  Recall        : {recall:.3f}  (of real attacks, how many caught?)")
    logger.info(f"  F1-score      : {f1:.3f}")
    logger.info(f"  Accuracy      : {accuracy:.3f}")
    logger.info(f"  False Pos Rate: {fpr:.3f}")
    logger.info("")
    logger.info("=== PER ATTACK TYPE ===")
    for atype, stats in sorted(attack_type_breakdown.items()):
        total_t = stats["total"]
        caught = stats["tp"]
        missed = stats["fn"]
        rate = caught / total_t if total_t > 0 else 0
        marker = "OK" if missed == 0 else "MISS"
        logger.info(f"  [{marker:4}] {atype:<20} caught={caught}/{total_t} ({100*rate:.0f}%)")

    return {
        "total": total, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
        "per_attack_type": {
            k: {**v, "detection_rate": round(v["tp"] / v["total"], 4) if v["total"] > 0 else 0}
            for k, v in attack_type_breakdown.items()
        },
    }


def main(args: argparse.Namespace, logger: logging.Logger) -> None:
    input_path = Path(args.input)
    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        sys.exit(1)

    # Load alerts
    alerts = load_alerts(input_path, logger)

    # Initialize detection agent
    agent = DetectionAgent(threshold=args.threshold)
    logger.info(f"DetectionAgent initialized (threshold={args.threshold})")
    logger.info(f"Running {len(alerts)} alerts through {len(agent._rules)} detection rules...")

    # Score all alerts
    t_start = time.time()
    results = agent.score_batch(alerts)
    elapsed = time.time() - t_start

    # Attach detection results back onto alerts (for full output)
    suspicious_alerts = []
    full_output = []
    score_dist = {"0.0-0.2": 0, "0.2-0.4": 0, "0.4-0.6": 0, "0.6-0.8": 0, "0.8-1.0": 0}

    for alert, result in zip(alerts, results):
        record = alert.to_dict()
        record.update(result.to_dict())
        full_output.append(record)

        if result.verdict == "SUSPICIOUS":
            suspicious_alerts.append(record)

        s = result.anomaly_score
        if s < 0.2:   score_dist["0.0-0.2"] += 1
        elif s < 0.4: score_dist["0.2-0.4"] += 1
        elif s < 0.6: score_dist["0.4-0.6"] += 1
        elif s < 0.8: score_dist["0.6-0.8"] += 1
        else:         score_dist["0.8-1.0"] += 1

    suspicious_count = len(suspicious_alerts)
    benign_count = len(alerts) - suspicious_count

    logger.info(f"Detection complete in {elapsed:.2f}s ({1000*elapsed/len(alerts):.2f}ms/alert avg)")
    logger.info("")
    logger.info("=== VERDICT SUMMARY ===")
    logger.info(f"  SUSPICIOUS : {suspicious_count} ({100*suspicious_count/len(alerts):.1f}%)")
    logger.info(f"  BENIGN     : {benign_count} ({100*benign_count/len(alerts):.1f}%)")
    logger.info("")
    logger.info("=== SCORE DISTRIBUTION ===")
    for band, count in score_dist.items():
        bar = "#" * (count // max(1, len(alerts) // 40))
        logger.info(f"  [{band}] {count:>5}  {bar}")

    # Compute metrics if we have ground truth
    has_ground_truth = any(a.label_ground_truth for a in alerts)
    metrics = {}
    if has_ground_truth:
        metrics = compute_metrics(alerts, results, logger)

    # Save detection results
    results_path = cfg.ALERTS_DIR / "detection_results.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2, default=str)
    logger.info(f"Saved full results -> {results_path} ({results_path.stat().st_size//1024} KB)")

    # Overwrite suspicious queue with detection-scored version
    with open(cfg.SUSPICIOUS_QUEUE_PATH, "w", encoding="utf-8") as f:
        json.dump(suspicious_alerts, f, indent=2, default=str)
    logger.info(f"Updated suspicious_queue.json -> {len(suspicious_alerts)} alerts")

    # Save metrics report
    metrics_path = cfg.EVAL_DIR / "detection_metrics.json"
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "phase": "Phase 2 - Detection Agent",
        "input_file": str(input_path),
        "total_alerts": len(alerts),
        "threshold": args.threshold,
        "suspicious_count": suspicious_count,
        "benign_count": benign_count,
        "latency_ms_per_alert": round(1000 * elapsed / len(alerts), 3),
        "metrics": metrics,
    }
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Saved metrics -> {metrics_path}")

    logger.info("")
    logger.info("=" * 50)
    logger.info("Phase 2 - Detection Agent COMPLETE")
    logger.info(f"  Input  : {len(alerts)} alerts")
    logger.info(f"  Output : {suspicious_count} SUSPICIOUS  |  {benign_count} BENIGN")
    if metrics:
        logger.info(f"  Recall : {metrics.get('recall', 0):.3f}  (attack catch rate)")
        logger.info(f"  F1     : {metrics.get('f1', 0):.3f}")
    logger.info("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run detection agent on alert store")
    parser.add_argument(
        "--input", default=str(cfg.CLEAN_ALERTS_PATH),
        help="Path to input alerts JSON file"
    )
    parser.add_argument(
        "--threshold", type=float, default=SUSPICION_THRESHOLD,
        help=f"Anomaly score threshold for SUSPICIOUS verdict (default: {SUSPICION_THRESHOLD})"
    )
    args = parser.parse_args()

    logger = setup_logging()
    logger.info("=" * 50)
    logger.info("Phase 2 - Detection Agent")
    logger.info(f"  Input     : {args.input}")
    logger.info(f"  Threshold : {args.threshold}")
    logger.info("=" * 50)

    main(args, logger)
