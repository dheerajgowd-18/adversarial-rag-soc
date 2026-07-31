"""
eval/audit_fallback_counts.py — Audit saved evaluation results for LLM vs Fallback decisions
"""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import cfg

def audit_file(filepath: Path):
    if not filepath.exists():
        return f"File missing: {filepath}"
    
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "results" in data:
        items = data["results"]
    elif isinstance(data, list):
        items = data
    else:
        items = [data]

    total = len(items)
    fallback_cnt = 0
    llm_cnt = 0

    for item in items:
        reasoning = item.get("reasoning", "")
        is_fb = item.get("is_fallback", False) or "LLM API call failed" in reasoning or "Fallback to rule-based" in reasoning
        if is_fb:
            fallback_cnt += 1
        else:
            llm_cnt += 1

    return {
        "file": str(filepath.name),
        "total_alerts": total,
        "real_llm_calls": llm_cnt,
        "fallback_calls": fallback_cnt,
        "fallback_percent": round((fallback_cnt / total) * 100.0, 2) if total > 0 else 0.0
    }

def main():
    files_to_check = [
        cfg.ALERTS_DIR / "triage_results.json",
        cfg.EVAL_DIR / "baseline_triage_metrics.json",
        cfg.ATTACKED_DIR / "eval_attacked_cat1_direct.json",
        cfg.ATTACKED_DIR / "eval_attacked_cat2_rag_poison.json",
        cfg.ATTACKED_DIR / "eval_attacked_cat3_role_spoof.json",
        cfg.ATTACKED_DIR / "eval_attacked_cat4_chained.json",
    ]

    print("=== RATE-LIMIT FALLBACK AUDIT REPORT ===")
    for f in files_to_check:
        res = audit_file(f)
        print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
