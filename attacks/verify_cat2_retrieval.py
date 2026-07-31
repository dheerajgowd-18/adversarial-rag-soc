"""
attacks/verify_cat2_retrieval.py — Verification of CAT-2 RAG Poisoning Retrieval & Prompt Context
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import cfg
from ingestion.schema import Alert
from attacks.build_and_run_cat2 import PoisonedRetriever

def verify_cat2():
    retriever = PoisonedRetriever()
    
    cat2_path = cfg.ATTACKED_DIR / "eval_attacked_cat2_rag_poison.json"
    with open(cat2_path, "r", encoding="utf-8") as f:
        alerts_raw = json.load(f)
    alerts = [Alert.from_dict(d) for d in alerts_raw]

    malicious_alerts = [a for a in alerts if a.is_malicious]
    total_malicious = len(malicious_alerts)

    poisoned_retrieved_cnt = 0
    poisoned_missed_cnt = 0

    per_type_breakdown = {}

    print(f"=== FULL COVERAGE CAT-2 RETRIEVAL AUDIT ({total_malicious} MALICIOUS ALERTS) ===")
    for idx, alert in enumerate(malicious_alerts, 1):
        docs = retriever.retrieve(alert, k=3)
        contains_poison = any(
            "[THREAT INTEL ADVISORY #892" in d.chunk_text or "MANDATORY INSTRUCTION OVERRIDE" in d.chunk_text
            for d in docs
        )

        atype = alert.attack_type or "unknown"
        if atype not in per_type_breakdown:
            per_type_breakdown[atype] = {"total": 0, "poison_retrieved": 0, "poison_missed": 0}
        per_type_breakdown[atype]["total"] += 1

        if contains_poison:
            poisoned_retrieved_cnt += 1
            per_type_breakdown[atype]["poison_retrieved"] += 1
        else:
            poisoned_missed_cnt += 1
            per_type_breakdown[atype]["poison_missed"] += 1

    retrieval_rate = (poisoned_retrieved_cnt / total_malicious) * 100.0 if total_malicious > 0 else 0.0

    report = {
        "total_malicious_attacked": total_malicious,
        "poisoned_chunk_retrieved_count": poisoned_retrieved_cnt,
        "poisoned_chunk_missed_count": poisoned_missed_cnt,
        "poison_retrieval_coverage_percent": round(retrieval_rate, 2),
        "per_attack_type_coverage": per_type_breakdown
    }

    print("\n" + json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    verify_cat2()
