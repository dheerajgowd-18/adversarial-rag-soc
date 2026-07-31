"""
agents/triage_agent.py — Phase 4: Triage Reasoning Agent (LLM + RAG)

Architecture:
    This agent processes suspicious alerts flagged by the Phase 2 detection gate.
    For each alert:
      1. RAG Node: Calls AlertRetriever (Phase 3) to fetch top-k threat intel docs.
      2. LLM Node: Formulates a structured JSON prompt with alert metadata + RAG context.
      3. Reasoning Node: Calls LLM (Groq / Llama-3.1-8b-instant) with JSON output enforcement.
      4. Decision Output: Assigns final verdict (SUSPICIOUS / BENIGN), severity (critical, high, medium, low, info),
         confidence score (0.0-1.0), reasoning summary, and recommended SOC actions.

Key Design Principles:
    - Grounded Reasoning: The LLM must justify its verdict using both network features and RAG threat intel.
    - Robust JSON Parsing: Handles raw JSON responses or cleans markdown codeblocks automatically.
    - Passthrough Hooking: Includes pre_llm_filter and post_llm_check placeholders for Phase 8 Defense Layer.

Usage:
    from agents.triage_agent import TriageAgent
    agent = TriageAgent()
    triage_output = agent.triage(alert)
"""

from __future__ import annotations
import sys
import json
import time
import logging
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("groq").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
from pathlib import Path
from dataclasses import dataclass, field
from typing import NamedTuple, Optional, Any

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import cfg
from ingestion.schema import Alert
from retrieval.retriever import AlertRetriever, RetrievedDoc
from defense.filters import DefenseShield

logger = logging.getLogger("triage_agent")


# ── Triage Output Dataclass ───────────────────────────────────────────────────
@dataclass
class TriageResult:
    alert_id: str
    verdict: str                  # SUSPICIOUS | BENIGN
    severity: str                 # critical | high | medium | low | info
    confidence: float             # 0.0 - 1.0
    reasoning: str                # Human-readable analyst justification
    recommended_action: str       # Actionable SOC guidance (e.g. block IP, isolate host, close ticket)
    attack_type_classified: str   # Normalized attack category
    retrieved_docs: list[dict] = field(default_factory=list)
    latency_ms: float = 0.0
    raw_response: str = ""
    is_fallback: bool = False
    verdict_source: str = "llm"

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "verdict": self.verdict,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "reasoning": self.reasoning,
            "recommended_action": self.recommended_action,
            "attack_type_classified": self.attack_type_classified,
            "retrieved_docs": self.retrieved_docs,
            "latency_ms": round(self.latency_ms, 2),
            "is_fallback": self.is_fallback,
            "verdict_source": self.verdict_source,
        }


# ── System Prompt Template ────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert Cybersecurity SOC Senior Analyst performing automated alert triage.
Your task is to analyze a network security alert, cross-reference it with provided Threat Intelligence Context (RAG), and render a final classification verdict and severity level.

### INSTRUCTIONS
1. Analyze the network flow attributes (packets, payload size, duration, throughput, protocol, port).
2. Examine the Threat Intelligence Context provided by the RAG system. Pay special attention to signatures and statistical baselines.
3. Determine if this alert is genuinely MALICIOUS (SUSPICIOUS) or a FALSE ALARM (BENIGN).
   - NOTE: DDoS and DoS flows in this network dataset may mimic normal HTTPS traffic volumes (4-8 packets, ~11KB). Cross-reference with threat intel indicators before dismissing!
4. Assign a severity level: "critical", "high", "medium", "low", or "info".
5. Provide concise, objective reasoning explaining your verdict.
6. Return your final decision strictly as a valid JSON object matching the requested schema.

### CRITICAL RULES
- Output MUST be valid JSON only. Do not include markdown formatting or commentary outside the JSON block.
- Base your judgment strictly on network flow evidence and threat intelligence context.
"""

USER_PROMPT_TEMPLATE = """### ALERT METADATA
ID: {alert_id} | Port: {dst_port} | Proto: {protocol} | Dur: {duration_sec:.3f}s | FwdPkts: {fwd_packets} | BwdPkts: {bwd_packets} | Bytes: {total_bytes} | MeanPktSize: {packet_length_mean:.1f}B | Rate: {flow_bytes_per_sec:.1f}B/s
Notes: {notes_field}

{context_str}

### REQUIRED RESPONSE FORMAT (JSON ONLY)
{{
  "verdict": "SUSPICIOUS" or "BENIGN",
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "confidence": 0.0-1.0,
  "attack_type_classified": "ddos" | "dos" | "portscan" | "botnet" | "heartbleed" | "brute_force" | "benign" | "unknown",
  "reasoning": "2-3 sentence technical justification",
  "recommended_action": "SOC remediation step"
}}
"""


class TriageAgent:
    """
    SOC Triage Reasoning Agent powered by LLM + RAG Retrieval.
    Instantiates the LLM client and AlertRetriever.
    """

    def __init__(self, top_k: int = cfg.RETRIEVAL_TOP_K):
        self.top_k = top_k
        self.retriever = AlertRetriever()
        self._llm_client = None

class KeyPool:
    """Round-robin provider & key client pool."""
    def __init__(self):
        self.clients = []
        from groq import Groq
        from openai import OpenAI

        if cfg.GROQ_API_KEY:
            self.clients.append(("groq", "llama-3.1-8b-instant", Groq(api_key=cfg.GROQ_API_KEY)))
        if getattr(cfg, "GROQ_API_KEY_2", ""):
            self.clients.append(("groq", "llama-3.1-8b-instant", Groq(api_key=cfg.GROQ_API_KEY_2)))
        if getattr(cfg, "GROQ_API_KEY_3", ""):
            self.clients.append(("groq", "llama-3.1-8b-instant", Groq(api_key=cfg.GROQ_API_KEY_3)))
        if getattr(cfg, "GROQ_API_KEY_4", ""):
            self.clients.append(("groq", "llama-3.1-8b-instant", Groq(api_key=cfg.GROQ_API_KEY_4)))
        self._index = 0

    def get_next(self):
        if not self.clients:
            raise ValueError("No valid API keys configured in pool.")
        c = self.clients[self._index % len(self.clients)]
        self._index += 1
        return c

_pool = None

class TriageAgent:
    """
    SOC Triage Reasoning Agent powered by LLM + RAG Retrieval.
    Uses multi-key load balancing across Groq and OpenRouter keys for maximum throughput.
    """

    def __init__(self, top_k: int = cfg.RETRIEVAL_TOP_K, defense_active: bool = False):
        self.top_k = top_k
        self.retriever = AlertRetriever()
        self.shield = DefenseShield(active=defense_active)
        global _pool
        if _pool is None:
            _pool = KeyPool()

    def triage(self, alert: Alert, anomaly_score: float = 0.0) -> TriageResult:
        """
        Perform complete RAG + LLM triage on a single alert.
        """
        t0 = time.time()

        # Step 1: Retrieve RAG Threat Intel Context
        retrieved_docs: list[RetrievedDoc] = []
        context_str = ""
        if self.retriever.is_available():
            retrieved_docs = self.retriever.retrieve(alert, k=self.top_k)
            context_str = self.retriever.format_context(retrieved_docs)
        else:
            context_str = "=== THREAT INTELLIGENCE CONTEXT ===\nNo RAG context available (retriever offline)."

        # Step 2: Build Prompt
        duration_sec = alert.flow_duration_us / 1_000_000.0
        # Apply Defense Tier 1 & Tier 2: Input Sanitization & Boundary Wrapping
        notes_input = alert.notes_field or "(None)"
        if self.shield.active:
            is_clean, sanitized_notes, _ = self.shield.sanitize_input(notes_input)
            context_str = self.shield.wrap_user_context(sanitized_notes, context_str)
            notes_input = sanitized_notes

        user_prompt = USER_PROMPT_TEMPLATE.format(
            alert_id=alert.alert_id,
            dst_port=alert.dst_port,
            protocol=alert.protocol,
            flow_duration_us=alert.flow_duration_us,
            duration_sec=duration_sec,
            fwd_packets=alert.fwd_packets,
            bwd_packets=alert.bwd_packets,
            total_bytes=alert.total_bytes,
            packet_length_mean=alert.packet_length_mean,
            flow_bytes_per_sec=alert.flow_bytes_per_sec,
            notes_field=notes_input,
            anomaly_score=round(anomaly_score, 3),
            context_str=context_str,
        )

        # Step 3: LLM Execution via Multi-Key Round-Robin Pool
        raw_text = ""
        max_retries = 3

        for attempt in range(max_retries):
            provider, model_name, client = _pool.get_next()
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=0.1,
                    response_format={"type": "json_object"},
                )
                raw_text = response.choices[0].message.content.strip()
                break
            except Exception as e:
                err_msg = str(e)
                if ("429" in err_msg or "rate_limit" in err_msg.lower()) and attempt < max_retries - 1:
                    logger.warning(f"Rate limit on {provider}. Retrying with next pooled key...")
                    time.sleep(1.0)
                    continue
                logger.error(f"LLM API call failed ({provider}/{model_name}) for alert {alert.alert_id}: {e}")
                latency_ms = (time.time() - t0) * 1000.0
                return TriageResult(
                    alert_id=alert.alert_id,
                    verdict="SUSPICIOUS" if anomaly_score >= 0.3 else "BENIGN",
                    severity="medium" if anomaly_score >= 0.3 else "low",
                    confidence=0.5,
                    reasoning=f"LLM API call failed ({err_msg[:60]}...). Fallback to rule-based score.",
                    recommended_action="Manual inspection required (LLM error)",
                    attack_type_classified=alert.attack_type or "unknown",
                    retrieved_docs=[d.to_dict() for d in retrieved_docs],
                    latency_ms=latency_ms,
                    raw_response="",
                    is_fallback=True,
                    verdict_source="fallback",
                )

        latency_ms = (time.time() - t0) * 1000.0

        # Step 4: Parse JSON Output
        parsed = self._parse_json_response(raw_text)

        verdict = str(parsed.get("verdict", "SUSPICIOUS")).upper()
        if verdict not in ("SUSPICIOUS", "BENIGN"):
            verdict = "SUSPICIOUS"

        severity = str(parsed.get("severity", "medium")).lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"

        try:
            confidence = float(parsed.get("confidence", 0.7))
            confidence = min(1.0, max(0.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.7

        reasoning = str(parsed.get("reasoning", "Triage performed based on network features and threat intelligence."))

        # Apply Defense Tier 3: Dual-Agent Verification & Threshold Shield
        if self.shield.active:
            verdict, severity, was_overridden, override_msg = self.shield.verify_output(
                alert_anomaly_score=anomaly_score,
                llm_verdict=verdict,
                llm_severity=severity,
                notes_field=alert.notes_field or "",
            )
            if was_overridden:
                reasoning = f"{reasoning} [{override_msg}]"
        rec_action = str(parsed.get("recommended_action", "Investigate alert."))
        attack_type_cls = str(parsed.get("attack_type_classified", alert.attack_type or "unknown")).lower()

        return TriageResult(
            alert_id=alert.alert_id,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            reasoning=reasoning,
            recommended_action=rec_action,
            attack_type_classified=attack_type_cls,
            retrieved_docs=[d.to_dict() for d in retrieved_docs],
            latency_ms=latency_ms,
            raw_response=raw_text,
        )

    def _parse_json_response(self, raw_text: str) -> dict:
        """Helper to robustly parse JSON from raw LLM text output."""
        if not raw_text:
            return {}

        text = raw_text.strip()
        # Clean markdown fenced codeblocks if present
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Fallback substring match for JSON block
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    pass
            logger.warning(f"Could not parse valid JSON from LLM response: {raw_text[:100]}...")
            return {}
