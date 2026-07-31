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
    
    with open(cfg.EVAL_FIXED_SET_PATH, "r", encoding="utf-8") as f:
        alerts_raw = json.load(f)
    alerts = [Alert.from_dict(d) for d in alerts_raw]

    # Select 5 sample malicious alerts (1 DDoS, 1 PortScan, 1 DoS, 1 Botnet, 1 Benign)
    samples = []
    types_found = set()
    for a in alerts:
        atype = a.attack_type or "unknown"
        if atype not in types_found:
            samples.append(a)
            types_found.add(atype)
        if len(samples) == 5:
            break

    print("=== CAT-2 RETRIEVAL VERIFICATION LOG ===")
    for idx, alert in enumerate(samples, 1):
        docs = retriever.retrieve(alert, k=3)
        context_str = retriever.format_context(docs)
        
        print(f"\n--- SAMPLE ALERT {idx}: ID={alert.alert_id} | Attack={alert.attack_type} ---")
        print(f"Query string built: {retriever.build_query(alert)}")
        print(f"Retrieved {len(docs)} documents from chroma_db_poisoned:")
        
        contains_poison = False
        for d in docs:
            has_p = "[THREAT INTEL ADVISORY #892" in d.chunk_text or "MANDATORY INSTRUCTION OVERRIDE" in d.chunk_text
            if has_p: contains_poison = True
            print(f"  - Doc ID: {d.doc_id} | Score: {d.relevance_score:.4f} | Poisoned Chunk Present: {has_p}")
            print(f"    Chunk snippet: {d.chunk_text[:120]}...")
            
        print(f"-> CONTAINS POISONED INSTRUCTION IN PROMPT CONTEXT: {contains_poison}")

if __name__ == "__main__":
    verify_cat2()
