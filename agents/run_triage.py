"""
agents/run_triage.py — Phase 4 Batch Runner & Evaluation Engine

Executes the Phase 4 Triage Agent (LLM + RAG) over:
  1. The suspicious queue (alerts flagged by Phase 2 rule gate)
  2. Or the fixed evaluation set (data/alerts/eval_fixed_set.json)

Computes full evaluation metrics:
  - Precision, Recall, F1-score, Accuracy, False Positive Rate
  - Per attack-type breakdown (specifically tracking DDoS and Heartbleed recovery)
  - Latency statistics (avg, min, max, total)

Outputs:
  - data/alerts/triage_results.json (Full triage outputs)
  - eval/baseline_triage_metrics.json (Performance evaluation report)

Usage:
    python agents/run_triage.py --input data/alerts/suspicious_queue.json
    python agents/run_triage.py --input data/alerts/eval_fixed_set.json --limit 50
"""

import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import cfg
from ingestion.schema import Alert
from agents.triage_agent import TriageAgent, TriageResult


def setup_logging() -> logging.Logger:
    cfg.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("run_triage")
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(cfg.LOGS_DIR / "triage.log", mode="w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s"))
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


def calculate_metrics(alerts: list[Alert], results: list[TriageResult]) -> dict:
    """Calculate binary classification and per-attack-type metrics."""
    result_map = {r.alert_id: r for r in results}

    tp = tn = fp = fn = 0
    per_attack = {}

    for a in alerts:
        res = result_map.get(a.alert_id)
        if not res:
            continue

        actual_malicious = a.is_malicious
        pred_malicious = (res.verdict == "SUSPICIOUS")

        atype = a.attack_type or "unknown"
        if atype not in per_attack:
            per_attack[atype] = {"total": 0, "caught": 0, "correct_benign": 0}
        per_attack[atype]["total"] += 1

        if actual_malicious and pred_malicious:
            tp += 1
            per_attack[atype]["caught"] += 1
        elif not actual_malicious and not pred_malicious:
            tn += 1
            per_attack[atype]["correct_benign"] += 1
        elif not actual_malicious and pred_malicious:
            fp += 1
        elif actual_malicious and not pred_malicious:
            fn += 1

    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (tp + tn) / total if total > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    attack_breakdown = {}
    for atype, stats in sorted(per_attack.items()):
        tot = stats["total"]
        if atype == "benign":
            corr = stats["correct_benign"]
            pct = round(100.0 * corr / tot, 1) if tot > 0 else 0.0
            attack_breakdown[atype] = f"correct={corr}/{tot} ({pct}%)"
        else:
            cgt = stats["caught"]
            pct = round(100.0 * cgt / tot, 1) if tot > 0 else 0.0
            attack_breakdown[atype] = f"caught={cgt}/{tot} ({pct}%)"

    latencies = [r.latency_ms for r in results]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_alerts": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
        "average_latency_ms": round(avg_latency, 2),
        "per_attack_type": attack_breakdown,
    }


def main():
    parser = argparse.ArgumentParser(description="Run Phase 4 Triage Agent")
    parser.add_argument("--input", type=str, default=str(cfg.SUSPICIOUS_QUEUE_PATH),
                        help="Path to alerts JSON file to triage")
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of alerts to process (0 = all)")
    parser.add_argument("--workers", type=int, default=1,
                        help="Number of concurrent worker threads (default: 1)")
    parser.add_argument("--delay", type=float, default=5.0,
                        help="Delay in seconds between requests to avoid Groq rate limits (default: 5.0s)")
    parser.add_argument("--output", type=str, default=str(cfg.ALERTS_DIR / "triage_results.json"),
                        help="Path to save triage results JSON")
    args = parser.parse_args()

    logger = setup_logging()
    input_path = Path(args.input)

    logger.info("=" * 60)
    logger.info("Phase 4 - Triage Reasoning Agent (LLM + RAG)")
    logger.info(f"  Input     : {input_path}")
    logger.info(f"  LLM Model : {cfg.LLM_MODEL} ({cfg.LLM_PROVIDER})")
    logger.info(f"  Top K RAG : {cfg.RETRIEVAL_TOP_K}")
    logger.info("=" * 60)

    if not input_path.exists():
        logger.error(f"Input file not found: {input_path}")
        sys.exit(1)

    with open(input_path, "r", encoding="utf-8") as f:
        alerts_raw = json.load(f)

    alerts = [Alert.from_dict(a) for a in alerts_raw]
    if args.limit > 0:
        alerts = alerts[: args.limit]

    logger.info(f"Loaded {len(alerts)} alerts for triage...")

    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    agent = TriageAgent(top_k=cfg.RETRIEVAL_TOP_K)
    # Warm load retriever once before starting thread pool
    if agent.retriever.is_available() and alerts:
        logger.info("Warming up RAG retriever and embedding model...")
        agent.retriever.retrieve(alerts[0], k=1)

    t_start = datetime.now()
    results: list[TriageResult] = [None] * len(alerts)
    completed_count = 0

    def process_item(idx_and_alert):
        idx, alert = idx_and_alert
        if args.delay > 0:
            time.sleep(args.delay * (idx % args.workers))
        anomaly_score = getattr(alert, "anomaly_score", 0.35)
        res = agent.triage(alert, anomaly_score=anomaly_score)
        return idx, res

    import time
    for idx, alert in enumerate(alerts):
        _, res = process_item((idx, alert))
        results[idx] = res
        completed_count += 1
        time.sleep(0.35)
        if completed_count % 20 == 0 or completed_count == len(alerts):
            logger.info(
                f"  [{completed_count:4d}/{len(alerts)}] alert_id={alert.alert_id} | "
                f"verdict={res.verdict:10s} | severity={res.severity:8s} | "
                f"conf={res.confidence:.2f} | lat={res.latency_ms:.0f}ms | source={res.verdict_source}"
            )

    t_duration = (datetime.now() - t_start).total_seconds()
    logger.info(f"Triage complete in {t_duration:.2f}s ({1000 * t_duration / len(alerts):.0f}ms/alert avg)")

    # Save results
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in results], f, indent=2)
    logger.info(f"Saved full results -> {output_path}")

    # Compute metrics
    metrics = calculate_metrics(alerts, results)
    metrics_path = cfg.EVAL_DIR / "baseline_triage_metrics.json"
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    logger.info(f"Saved evaluation metrics -> {metrics_path}")

    logger.info("")
    logger.info("=== TRIAGE PERFORMANCE METRICS ===")
    logger.info(f"  Total processed : {metrics['total_alerts']}")
    logger.info(f"  Precision       : {metrics['precision']}")
    logger.info(f"  Recall          : {metrics['recall']}")
    logger.info(f"  F1-Score        : {metrics['f1_score']}")
    logger.info(f"  Accuracy        : {metrics['accuracy']}")
    logger.info(f"  False Pos Rate  : {metrics['false_positive_rate']}")
    logger.info(f"  Avg Latency     : {metrics['average_latency_ms']} ms")
    logger.info("")
    logger.info("=== PER ATTACK TYPE BREAKDOWN ===")
    for atype, stats in metrics["per_attack_type"].items():
        logger.info(f"  [{atype:12s}] {stats}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
