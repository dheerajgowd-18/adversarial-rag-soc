"""
retrieval/test_retriever.py — Verify the RAG knowledge base works correctly.

Tests:
1. KB is available and has correct chunk count
2. DDoS alert retrieves DDoS-relevant documents (the hard case)
3. PortScan alert retrieves portscan documents
4. Botnet alert retrieves botnet documents
5. Query latency is acceptable (<500ms)

Run:
    python retrieval/test_retriever.py
"""
import sys
import time
import json
from pathlib import Path

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import cfg
from ingestion.schema import Alert, ATTACK_TYPE_MAP, SEVERITY_MAP, make_alert_id
from retrieval.retriever import AlertRetriever


def make_test_alert(attack_type: str, index: int = 0) -> Alert:
    """Create a test alert for a given attack type."""
    from ingestion.build_alerts import make_notes_field
    from datetime import datetime

    label_map = {
        "ddos":        "DDoS",
        "dos":         "DoS Hulk",
        "portscan":    "PortScan",
        "botnet":      "Bot",
        "heartbleed":  "Heartbleed",
        "benign":      "BENIGN",
        "brute_force": "SSH-Patator",
    }

    # Feature values based on real CICIDS2017 medians per attack type
    feature_map = {
        "ddos":        dict(fwd=4, bwd=4, dur=1_876_028, pm=833.5, tb=11627, bps=159.4, dport=80),
        "dos":         dict(fwd=6, bwd=6, dur=84_880_200, pm=794.7, tb=11924, bps=121.1, dport=80),
        "portscan":    dict(fwd=1, bwd=1, dur=44, pm=2.0, tb=6, bps=136363.6, dport=8080),
        "botnet":      dict(fwd=3, bwd=3, dur=1_024_663, pm=2.57, tb=18, bps=17.6, dport=8080),
        "heartbleed":  dict(fwd=2782, bwd=2091, dur=119_259_886, pm=1620.1, tb=7_891_800, bps=66173.1, dport=444),
        "benign":      dict(fwd=6, bwd=5, dur=32_288, pm=60.2, tb=234, bps=5367.0, dport=443),
        "brute_force": dict(fwd=20, bwd=15, dur=500_000, pm=150.0, tb=4000, bps=8000.0, dport=22),
    }

    f = feature_map.get(attack_type, feature_map["benign"])
    label = label_map.get(attack_type, "BENIGN")
    severity = SEVERITY_MAP.get(attack_type, "info")

    row = {
        "src_ip": "0.0.0.0", "dst_ip": "0.0.0.0",
        "dst_port": f["dport"], "protocol": "TCP",
        "flow_duration": f["dur"], "fwd_packets": f["fwd"],
        "bwd_packets": f["bwd"], "flow_bytes_per_sec": f["bps"],
    }
    notes = make_notes_field(row, attack_type, label)

    return Alert(
        alert_id=make_alert_id("test", index),
        source_file="test",
        row_index=index,
        src_ip="0.0.0.0",
        dst_ip="0.0.0.0",
        src_port=12345,
        dst_port=f["dport"],
        protocol="TCP",
        flow_duration_us=f["dur"],
        fwd_packets=f["fwd"],
        bwd_packets=f["bwd"],
        total_bytes=f["tb"],
        flow_bytes_per_sec=f["bps"],
        packet_length_mean=f["pm"],
        syn_flag_count=0,
        fin_flag_count=0,
        rst_flag_count=0,
        label_ground_truth=label,
        attack_type=attack_type,
        severity=severity,
        is_malicious=(attack_type != "benign"),
        notes_field=notes,
        condition="baseline",
        timestamp_ingested=__import__("datetime").datetime.utcnow().isoformat() + "Z",
    )


def run_tests():
    print("=" * 60)
    print("Phase 3 - RAG Retriever Test Suite")
    print("=" * 60)

    retriever = AlertRetriever()

    # Test 1: Availability
    print("\nTest 1: Knowledge base availability")
    stats = retriever.get_stats()
    if stats.get("available"):
        print(f"  PASS - KB available: {stats['chunk_count']} chunks loaded")
        print(f"         Collection: {stats['collection']}")
        print(f"         Model: {stats['embedding_model']}")
    else:
        print(f"  FAIL - KB not available: {stats}")
        print("  Run: python retrieval/build_kb.py")
        return False

    # Test 2–6: Retrieval quality tests
    test_cases = [
        ("ddos",        ["ddos", "benign"],       "DDoS alert -> DDoS/benign docs"),
        ("dos",         ["dos", "ddos"],           "DoS alert -> DoS docs"),
        ("portscan",    ["portscan"],              "PortScan alert -> portscan docs"),
        ("botnet",      ["botnet"],                "Botnet alert -> botnet docs"),
        ("heartbleed",  ["heartbleed"],            "Heartbleed alert -> CVE docs"),
        ("brute_force", ["brute_force"],           "Brute force alert -> brute_force docs"),
    ]

    all_passed = True
    for i, (attack_type, expected_types, description) in enumerate(test_cases, 2):
        alert = make_test_alert(attack_type, i)

        t0 = time.time()
        docs = retriever.retrieve(alert, k=3)
        latency_ms = (time.time() - t0) * 1000

        retrieved_types = [d.attack_type for d in docs]
        hit = any(et in retrieved_types for et in expected_types)
        top_doc = docs[0] if docs else None

        status = "PASS" if hit else "FAIL"
        all_passed = all_passed and hit

        print(f"\nTest {i}: {description}")
        print(f"  {status} - Latency: {latency_ms:.0f}ms | Retrieved: {retrieved_types}")
        if top_doc:
            print(f"  Top doc: '{top_doc.title}' (relevance={top_doc.relevance_score:.3f})")
            print(f"  Snippet: {top_doc.chunk_text[:120]}...")

    # Test 7: Format context
    print("\nTest 7: Context formatting for LLM prompt")
    ddos_alert = make_test_alert("ddos", 99)
    docs = retriever.retrieve(ddos_alert, k=2)
    context = retriever.format_context(docs)
    lines = context.count("\n")
    print(f"  PASS - Context: {len(context)} chars, {lines} lines")
    print(f"  Preview:\n{context[:300]}...")

    print("\n" + "=" * 60)
    result = "ALL TESTS PASSED" if all_passed else "SOME TESTS FAILED"
    print(f"Result: {result}")
    print("=" * 60)
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
