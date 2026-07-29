"""
agents/detection_agent.py — Rule-based detection gate (Phase 2)

Architecture:
    Every alert passes through a set of named detection rules.
    Each rule inspects network features and returns a score (0.0 to 1.0).
    Scores are weighted and summed into a final anomaly_score.
    Alerts above the SUSPICION_THRESHOLD are routed to the suspicious queue.

Why rule-based (not ML)?
    - Zero API cost — runs on CPU instantly
    - Fully interpretable — every decision has a named reason
    - Reproducible — same input ALWAYS gives same output
    - Establishes baseline before LLM triage in Phase 4
    - Mirrors real SOC: rule engines (Snort/Suricata) triage first,
      analysts (LLM) handle suspicious only

Rules calibrated against real CICIDS2017 data (4995 alerts):
    PortScan:   duration=44us,   pkt_mean=2.0,    fwd_packets=1
    Botnet:     duration=1M us,  pkt_mean=2.57,   total_bytes=18
    DDoS:       duration=8M us,  pkt_mean=897,    flow_bps=1439
    DoS:        duration=7.7Mus, pkt_mean=809,    total_bytes=12142
    Heartbleed: duration=119Mus, pkt_mean=1620,   fwd_packets=2782!
    Unknown:    duration=51us,   pkt_mean=5.3,    syn_flag=1

Scoring model:
    anomaly_score = weighted_sum(rule_scores) / max_possible_weight
    Range: 0.0 (clearly benign) to 1.0 (clearly malicious)
    SUSPICION_THRESHOLD = 0.30

Usage:
    from agents.detection_agent import DetectionAgent
    agent = DetectionAgent()
    result = agent.score(alert)
"""

from __future__ import annotations
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).parent.parent))
from ingestion.schema import Alert


# ── Detection verdict constants ───────────────────────────────────────────────
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_BENIGN = "BENIGN"

# ── Threshold ─────────────────────────────────────────────────────────────────
# Set conservatively to favour recall (catch more attacks, accept more FPs).
# In a SOC pipeline, missed attacks (FN) are worse than false alarms (FP).
SUSPICION_THRESHOLD = 0.28


class RuleResult(NamedTuple):
    name: str       # Rule identifier
    fired: bool     # Did this rule trigger?
    score: float    # Contribution 0.0–1.0
    weight: float   # Rule importance weight
    reason: str     # Human-readable explanation


@dataclass
class DetectionResult:
    alert_id: str
    anomaly_score: float
    verdict: str
    triggered_rules: list[str] = field(default_factory=list)
    detection_reasons: list[str] = field(default_factory=list)
    rule_details: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "alert_id":          self.alert_id,
            "anomaly_score":     round(self.anomaly_score, 4),
            "verdict":           self.verdict,
            "triggered_rules":   self.triggered_rules,
            "detection_reasons": self.detection_reasons,
        }


class DetectionAgent:
    """
    Rule-based detection gate. Stateless and thread-safe.
    All rules calibrated against real CICIDS2017 feature distributions.
    """

    def __init__(self, threshold: float = SUSPICION_THRESHOLD):
        self.threshold = threshold
        self._rules = [
            self._rule_ultra_short_flow,
            self._rule_micro_packet_size,
            self._rule_massive_packet_count,
            self._rule_high_flow_rate,
            self._rule_one_way_traffic,
            self._rule_tiny_total_bytes,
            self._rule_port_scan_signature,
            self._rule_botnet_beacon,
            self._rule_syn_probe,
            self._rule_high_bps_low_payload,
            self._rule_volumetric_attack,
        ]

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def score(self, alert: Alert) -> DetectionResult:
        """Score one alert and return a DetectionResult."""
        results: list[RuleResult] = [rule(alert) for rule in self._rules]

        total_weight = sum(r.weight for r in results)
        weighted_score = sum(r.score * r.weight for r in results if r.fired)
        anomaly_score = min(1.0, max(0.0,
            weighted_score / total_weight if total_weight > 0 else 0.0
        ))

        fired = [r for r in results if r.fired]
        verdict = VERDICT_SUSPICIOUS if anomaly_score >= self.threshold else VERDICT_BENIGN

        return DetectionResult(
            alert_id=alert.alert_id,
            anomaly_score=anomaly_score,
            verdict=verdict,
            triggered_rules=[r.name for r in fired],
            detection_reasons=[r.reason for r in fired],
            rule_details=[
                {"rule": r.name, "fired": r.fired,
                 "score": round(r.score, 3), "weight": r.weight}
                for r in results
            ],
        )

    def score_batch(self, alerts: list[Alert]) -> list[DetectionResult]:
        return [self.score(a) for a in alerts]

    # ─────────────────────────────────────────────────────────────────────────
    # Detection Rules — Calibrated to real CICIDS2017 distributions
    # ─────────────────────────────────────────────────────────────────────────

    def _rule_ultra_short_flow(self, a: Alert) -> RuleResult:
        """
        Ultra-short flow duration is the strongest PortScan/probe indicator.
        Real data: PortScan median duration = 44 microseconds.
        Benign flows: typically 32,000+ microseconds.
        Weight: 3.0 (most discriminating single feature in this dataset)
        """
        dur = a.flow_duration_us
        if dur <= 0:
            return RuleResult("ultra_short_flow", False, 0.0, 3.0, "Zero/negative duration (artifact)")
        if dur < 100:
            return RuleResult("ultra_short_flow", True, 1.0, 3.0,
                f"Extreme probe: flow only {dur:.0f}us — portscan/exploit signature")
        elif dur < 1_000:
            return RuleResult("ultra_short_flow", True, 0.85, 3.0,
                f"Very short flow: {dur:.0f}us (benign median ~32,000us)")
        elif dur < 10_000:
            return RuleResult("ultra_short_flow", True, 0.55, 3.0,
                f"Short flow: {dur:.0f}us — possible probe")
        return RuleResult("ultra_short_flow", False, 0.0, 3.0, "Flow duration normal")

    def _rule_micro_packet_size(self, a: Alert) -> RuleResult:
        """
        Micro packet mean size = flood/scan packets with no meaningful payload.
        Real data: PortScan pkt_mean=2.0, Botnet=2.57, Unknown=5.3
        Benign median packet_length_mean = 60 bytes.
        Weight: 3.0 (second strongest discriminator)
        """
        pm = a.packet_length_mean
        total = a.fwd_packets + a.bwd_packets
        if pm <= 0 or total < 2:
            return RuleResult("micro_packet_size", False, 0.0, 3.0, "Insufficient data")
        if pm < 5:
            return RuleResult("micro_packet_size", True, 1.0, 3.0,
                f"Micro packets: {pm:.1f}B mean — scan/flood signature (benign ~60B)")
        elif pm < 15:
            return RuleResult("micro_packet_size", True, 0.8, 3.0,
                f"Very small packets: {pm:.1f}B mean")
        elif pm < 30:
            return RuleResult("micro_packet_size", True, 0.5, 3.0,
                f"Small packets: {pm:.1f}B mean (benign ~60B)")
        return RuleResult("micro_packet_size", False, 0.0, 3.0, "Packet size normal")

    def _rule_massive_packet_count(self, a: Alert) -> RuleResult:
        """
        Heartbleed: fwd=2782, bwd=2091 — total 4873 packets.
        This is 10x+ higher than any benign flow in the dataset.
        Also catches any volumetric DDoS/DoS with extreme packet counts.
        Weight: 3.0 (Heartbleed is only alert in dataset with >1000 packets)
        """
        total = a.fwd_packets + a.bwd_packets
        if total > 1000:
            return RuleResult("massive_packet_count", True, 1.0, 3.0,
                f"Extreme packet volume: {total} total — Heartbleed/volumetric attack")
        elif total > 300:
            return RuleResult("massive_packet_count", True, 0.7, 3.0,
                f"High packet count: {total}")
        elif total > 100:
            return RuleResult("massive_packet_count", True, 0.35, 3.0,
                f"Elevated packet count: {total}")
        return RuleResult("massive_packet_count", False, 0.0, 3.0, "Packet count normal")

    def _rule_high_flow_rate(self, a: Alert) -> RuleResult:
        """
        Flows with high bytes/sec relative to their duration.
        PortScan: flow_bps=136,363 in 44us — extremely high rate.
        Real benign: typically <50,000 B/s median.
        Weight: 2.0
        """
        bps = a.flow_bytes_per_sec
        if bps <= 0:
            return RuleResult("high_flow_rate", False, 0.0, 2.0, "Non-positive rate (artifact)")
        if bps > 5_000_000:
            return RuleResult("high_flow_rate", True, 1.0, 2.0,
                f"Extreme rate: {bps/1e6:.1f} MB/s")
        elif bps > 100_000:
            return RuleResult("high_flow_rate", True, 0.75, 2.0,
                f"High rate: {bps/1e3:.0f} KB/s (benign typical <50 KB/s)")
        elif bps > 50_000:
            return RuleResult("high_flow_rate", True, 0.4, 2.0,
                f"Elevated rate: {bps/1e3:.0f} KB/s")
        return RuleResult("high_flow_rate", False, 0.0, 2.0, "Flow rate normal")

    def _rule_one_way_traffic(self, a: Alert) -> RuleResult:
        """
        Flood attacks: huge fwd packet count, zero or near-zero bwd.
        Server cannot respond = overwhelmed (DoS) or port closed (scan).
        Weight: 1.5
        """
        fwd, bwd = a.fwd_packets, a.bwd_packets
        total = fwd + bwd
        if total < 5:
            return RuleResult("one_way_traffic", False, 0.0, 1.5, "Too few packets")
        if bwd == 0 and fwd > 10:
            return RuleResult("one_way_traffic", True, 0.9, 1.5,
                f"Unidirectional flood: {fwd} fwd, 0 bwd — server not responding")
        ratio = bwd / total
        if fwd > 50 and ratio < 0.05:
            return RuleResult("one_way_traffic", True, 0.65, 1.5,
                f"Highly asymmetric: {fwd} fwd vs {bwd} bwd ({100*ratio:.1f}% backward)")
        return RuleResult("one_way_traffic", False, 0.0, 1.5, "Traffic direction balanced")

    def _rule_tiny_total_bytes(self, a: Alert) -> RuleResult:
        """
        Extremely small total payload in a completed flow = probe/scan.
        PortScan: total_bytes=6 (just headers, no data).
        Botnet beacon: total_bytes=18.
        Benign flows carry real data: median ~234 bytes.
        Weight: 2.0
        """
        tb = a.total_bytes
        dur = a.flow_duration_us
        if tb < 0:
            return RuleResult("tiny_total_bytes", False, 0.0, 2.0, "Negative bytes (artifact)")
        # Only meaningful if flow completed (not ultra-short — covered elsewhere)
        if dur > 10_000:  # longer flows with tiny bytes = suspicious
            if tb < 30:
                return RuleResult("tiny_total_bytes", True, 1.0, 2.0,
                    f"Persistent minimal-data flow: {tb}B over {dur/1e6:.1f}s — C2/beacon")
            elif tb < 100:
                return RuleResult("tiny_total_bytes", True, 0.65, 2.0,
                    f"Very low payload: {tb}B over {dur/1e6:.1f}s")
        elif tb < 10:  # short flows with near-zero bytes = header-only probes
            return RuleResult("tiny_total_bytes", True, 0.85, 2.0,
                f"Header-only probe: {tb}B total bytes")
        return RuleResult("tiny_total_bytes", False, 0.0, 2.0, "Total bytes normal")

    def _rule_port_scan_signature(self, a: Alert) -> RuleResult:
        """
        Classic port scan: fwd=1, bwd=0 or 1, ultra-short duration.
        PortScan sample: fwd=1, bwd=1, duration=44us, pkt_mean=2.0
        Weight: 2.5
        """
        fwd, bwd = a.fwd_packets, a.bwd_packets
        dur = a.flow_duration_us
        pm = a.packet_length_mean

        if fwd <= 2 and pm < 10 and dur < 1_000:
            return RuleResult("port_scan_signature", True, 1.0, 2.5,
                f"Port scan: {fwd} pkt, {pm:.1f}B mean, {dur:.0f}us — exact match")
        elif fwd <= 3 and dur < 5_000 and pm < 20:
            return RuleResult("port_scan_signature", True, 0.75, 2.5,
                f"Scan probe: {fwd} pkts, {pm:.1f}B, {dur:.0f}us")
        elif fwd <= 5 and bwd == 0 and dur < 50_000:
            return RuleResult("port_scan_signature", True, 0.5, 2.5,
                f"Unanswered probe: {fwd} fwd, 0 bwd, {dur:.0f}us")
        return RuleResult("port_scan_signature", False, 0.0, 2.5, "Not a port scan pattern")

    def _rule_botnet_beacon(self, a: Alert) -> RuleResult:
        """
        Botnet C2 beaconing: periodic small data, very small packet_mean,
        longer flow duration (periodic check-in).
        Botnet sample: pkt_mean=2.57, total_bytes=18, duration=1M us
        Weight: 2.0
        """
        pm = a.packet_length_mean
        tb = a.total_bytes
        dur = a.flow_duration_us

        # Long-lived flow with tiny payload = C2 heartbeat
        if dur > 100_000 and pm < 10 and tb < 50:
            return RuleResult("botnet_beacon", True, 1.0, 2.0,
                f"C2 beacon: {pm:.1f}B pkts, {tb}B total, {dur/1e6:.1f}s flow")
        elif dur > 50_000 and pm < 20 and tb < 200:
            return RuleResult("botnet_beacon", True, 0.65, 2.0,
                f"Possible beacon: {pm:.1f}B mean, {tb}B over {dur/1e6:.1f}s")
        return RuleResult("botnet_beacon", False, 0.0, 2.0, "No botnet beacon pattern")

    def _rule_syn_probe(self, a: Alert) -> RuleResult:
        """
        SYN flag set with very short flow = TCP SYN probe/scan.
        Unknown sample: syn=1, duration=51us, pkt_mean=5.3
        Weight: 1.5
        """
        syn = a.syn_flag_count
        dur = a.flow_duration_us
        pm = a.packet_length_mean

        if syn >= 1 and dur < 1_000 and pm < 20:
            return RuleResult("syn_probe", True, 0.9, 1.5,
                f"SYN probe: syn={syn}, {dur:.0f}us, {pm:.1f}B — half-open scan")
        elif syn >= 1 and dur < 10_000:
            return RuleResult("syn_probe", True, 0.5, 1.5,
                f"Short SYN flow: {dur:.0f}us")
        return RuleResult("syn_probe", False, 0.0, 1.5, "SYN pattern normal")

    def _rule_high_bps_low_payload(self, a: Alert) -> RuleResult:
        """
        High bytes/sec rate but very small total bytes = ultra-short burst.
        Signature: quick high-rate probes (portscan, exploit attempt).
        PortScan: bps=136,363, total_bytes=6
        Weight: 1.5
        """
        bps = a.flow_bytes_per_sec
        tb = a.total_bytes

        if bps > 50_000 and tb < 50:
            return RuleResult("high_bps_low_payload", True, 1.0, 1.5,
                f"High-rate minimal probe: {bps/1e3:.0f} KB/s, only {tb}B payload")
        elif bps > 10_000 and tb < 100:
            return RuleResult("high_bps_low_payload", True, 0.6, 1.5,
                f"Burst probe: {bps/1e3:.0f} KB/s, {tb}B total")
        return RuleResult("high_bps_low_payload", False, 0.0, 1.5, "Rate/payload ratio normal")

    def _rule_volumetric_attack(self, a: Alert) -> RuleResult:
        """
        DDoS/DoS: total_bytes in 10K-14K range + high packet_length_mean.
        Real data: DDoS median total_bytes=11,627, pkt_mean=833
                   DoS  median total_bytes=11,924, pkt_mean=794
        This band is distinct from benign (median ~234 bytes).
        Note: DDoS/DoS look like legitimate HTTPS — this rule catches the
        specific byte-count band. The LLM in Phase 4 handles remaining cases.
        Weight: 2.0
        """
        tb  = a.total_bytes
        pm  = a.packet_length_mean
        dur = a.flow_duration_us

        # Characteristic DDoS/DoS band: large payload per packet, bounded total
        if 8_000 < tb < 14_000 and pm > 500 and dur > 1_000_000:
            return RuleResult("volumetric_attack", True, 0.85, 2.0,
                f"DoS/DDoS band: {tb}B total, {pm:.0f}B/pkt, {dur/1e6:.1f}s flow")
        elif 5_000 < tb < 14_000 and pm > 400:
            return RuleResult("volumetric_attack", True, 0.55, 2.0,
                f"Possible volumetric: {tb}B total, {pm:.0f}B mean pkt")
        return RuleResult("volumetric_attack", False, 0.0, 2.0,
            "Traffic not in DoS/DDoS byte-count band")
