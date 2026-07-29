"""
ingestion/schema.py — The canonical alert schema for the entire project.

Every alert that enters the pipeline — from CICIDS2017 CSV, from the
synthetic generator, or from the attack injector — MUST conform to this
schema. This is the contract between the ingestion layer and the agent.

Key design decisions:
  1. `notes_field` is intentionally free-text and user-editable.
     This is the primary injection surface in Phase 6 (attack layer).
  2. `alert_id` is deterministic (hash of source row) for reproducibility.
  3. `condition` tracks which experimental arm this alert belongs to.
  4. `label_ground_truth` is set at ingestion time from the CSV Label column,
     never modified afterward — it is the gold standard for evaluation.

Usage:
    from ingestion.schema import Alert, make_alert_id
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Optional, Literal


# ── Experimental condition labels ────────────────────────────────────────────
Condition = Literal["baseline", "attacked", "defended"]

# ── Severity tiers ────────────────────────────────────────────────────────────
Severity = Literal["critical", "high", "medium", "low", "info"]

# ── Attack type taxonomy (from CICIDS2017 label column) ──────────────────────
ATTACK_TYPE_MAP: dict[str, str] = {
    "BENIGN":                   "benign",
    "DoS Hulk":                 "dos",
    "DoS GoldenEye":            "dos",
    "DoS Slowloris":            "dos",
    "DoS Slowhttptest":         "dos",
    "Heartbleed":               "heartbleed",
    "DDoS":                     "ddos",
    "PortScan":                 "portscan",
    "FTP-Patator":              "brute_force",
    "SSH-Patator":              "brute_force",
    "Bot":                      "botnet",
    "Web Attack – Brute Force": "web_attack",
    "Web Attack – XSS":         "web_attack",
    "Web Attack – Sql Injection":"web_attack",
    "Infiltration":             "infiltration",
}

SEVERITY_MAP: dict[str, Severity] = {
    "benign":       "info",
    "dos":          "high",
    "heartbleed":   "critical",
    "ddos":         "critical",
    "portscan":     "medium",
    "brute_force":  "high",
    "botnet":       "critical",
    "web_attack":   "high",
    "infiltration": "critical",
}


def make_alert_id(source_file: str, row_index: int) -> str:
    """
    Deterministic alert ID — same input always produces the same ID.
    This ensures reproducibility across runs and machines.
    Format: alert_<8-char-hex>
    """
    raw = f"{source_file}::{row_index}"
    return "alert_" + hashlib.md5(raw.encode()).hexdigest()[:8]


@dataclass
class Alert:
    """
    Canonical alert object. Every field is documented.
    This is the only data structure the agent ever sees.
    """

    # ── Identity ──────────────────────────────────────────────────────────
    alert_id: str
    """Deterministic unique ID. Never changes for a given source row."""

    source_file: str
    """Original CSV filename (e.g. 'Wednesday-workingHours.pcap_ISCX.csv')"""

    row_index: int
    """Original row number in the source CSV. Used for reproducibility."""

    # ── Network features (raw from CICIDS2017) ────────────────────────────
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str           # TCP / UDP / ICMP
    flow_duration_us: float # microseconds
    fwd_packets: int
    bwd_packets: int
    total_bytes: int
    flow_bytes_per_sec: float
    packet_length_mean: float
    syn_flag_count: int
    fin_flag_count: int
    rst_flag_count: int

    # ── Detection context ─────────────────────────────────────────────────
    label_ground_truth: str
    """
    Original CICIDS2017 label (e.g. 'DoS Hulk', 'BENIGN').
    This is the gold standard — NEVER modify after ingestion.
    """

    attack_type: str
    """Normalized attack category from ATTACK_TYPE_MAP."""

    severity: Severity
    """Derived severity tier."""

    is_malicious: bool
    """True if attack_type != 'benign'. Derived field."""

    # ── The injection surface ─────────────────────────────────────────────
    notes_field: str
    """
    ⚠️  PRIMARY ATTACK SURFACE ⚠️
    Free-text field simulating analyst notes or ticket descriptions.
    In Phase 1: contains a human-readable description of the alert.
    In Phase 6: this field gets OVERWRITTEN with prompt injection payloads.
    The agent reads this field as part of its context.
    """

    # ── Pipeline metadata ─────────────────────────────────────────────────
    condition: Condition = "baseline"
    """
    Which experimental arm this alert belongs to.
    Set to 'attacked' in Phase 6, 'defended' in Phase 8.
    """

    injection_payload: Optional[str] = None
    """
    Set in Phase 6 when an injection attack is applied.
    None for all baseline alerts.
    """

    injection_category: Optional[str] = None
    """
    Category of injection: 'direct', 'indirect', 'role_hijack', 'goal_redirect'.
    None for all baseline alerts.
    """

    timestamp_ingested: str = ""
    """ISO8601 timestamp when this alert was ingested."""

    def to_dict(self) -> dict:
        """Serialize to a plain dict (JSON-serializable)."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "Alert":
        """Deserialize from a plain dict."""
        return cls(**d)

    def __repr__(self) -> str:
        return (
            f"Alert(id={self.alert_id!r}, "
            f"type={self.attack_type!r}, "
            f"severity={self.severity!r}, "
            f"condition={self.condition!r})"
        )
