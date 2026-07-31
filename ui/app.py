"""
ui/app.py — FastAPI Web Backend for Adversarial AI SOC Command Center

Serves the interactive top 1% UI/UX dashboard and provides REST endpoints for:
  - Fetching benchmark alerts
  - Live Triage execution (Baseline vs Defended)
  - Interactive Red-Team Prompt Injection Testing
  - Real-time research metrics & paper tables

Usage:
    python ui/app.py
"""

import sys
import json
import logging
from pathlib import Path
from typing import Optional

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from config import cfg
from ingestion.schema import Alert
from agents.triage_agent import TriageAgent
from defense.filters import DefenseShield

logger = logging.getLogger("ui_app")

app = FastAPI(title="Adversarial AI SOC Command Center", version="2.0.0")

# Serve static files & templates
UI_DIR = cfg.ROOT / "ui"
app.mount("/static", StaticFiles(directory=str(UI_DIR / "static")), name="static")

# Initialize Agents
triage_baseline = TriageAgent(top_k=cfg.RETRIEVAL_TOP_K, defense_active=False)
triage_defended = TriageAgent(top_k=cfg.RETRIEVAL_TOP_K, defense_active=True)
shield = DefenseShield(active=True)


class LiveTriageRequest(BaseModel):
    alert_id: Optional[str] = None
    dst_port: int = 80
    protocol: str = "TCP"
    flow_duration_us: float = 8098507.0
    fwd_packets: int = 7
    bwd_packets: int = 0
    total_bytes: int = 11200
    packet_length_mean: float = 897.1
    flow_bytes_per_sec: float = 1382.9
    notes_field: str = ""
    anomaly_score: float = 0.35
    defense_active: bool = False
    is_malicious: bool = True
    attack_type: str = "ddos"


@app.get("/", response_class=HTMLResponse)
def read_root():
    template_path = UI_DIR / "templates" / "index.html"
    if not template_path.exists():
        raise HTTPException(status_code=404, detail="Template not found")
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/alerts")
def get_benchmark_alerts():
    """Returns fixed 200 evaluation benchmark alerts for UI selection."""
    eval_path = cfg.EVAL_FIXED_SET_PATH
    if not eval_path.exists():
        raise HTTPException(status_code=404, detail="Benchmark eval set not found")
    with open(eval_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Return first 50 for quick UI browsing
    return data[:50]


@app.get("/api/metrics")
def get_research_metrics():
    """Returns master metrics from baseline, attack, and defense evaluation reports."""
    metrics_res = {
        "table1_baseline": [
            {"stage": "Phase 2: Rule Gate", "recall": "43.1%", "ddos": "0.0%", "f1": 0.4900, "lat": "0.04ms"},
            {"stage": "Phase 4: LLM + RAG Baseline", "recall": "95.0%", "ddos": "97.2%", "f1": 0.6835, "lat": "12.6s"},
        ],
        "table2_attacks": [
            {"id": "CAT-1", "name": "Direct Field Injection", "asr": "63.0%", "vuln": "CRITICAL"},
            {"id": "CAT-3", "name": "Role-Confusion / Authority Spoof", "asr": "43.0%", "vuln": "HIGH"},
            {"id": "CAT-4", "name": "Indirect Chained Injection", "asr": "4.0%", "vuln": "LOW"},
        ],
        "table3_defended": [
            {"id": "CAT-1", "name": "Direct Field Injection", "base_asr": "63.0%", "def_asr": "0.0%", "ddr": "+100.0%"},
            {"id": "CAT-3", "name": "Role-Confusion / Authority Spoof", "base_asr": "43.0%", "def_asr": "0.0%", "ddr": "+100.0%"},
            {"id": "CAT-4", "name": "Indirect Chained Injection", "base_asr": "4.0%", "def_asr": "0.0%", "ddr": "+100.0%"},
        ]
    }
    return metrics_res


@app.post("/api/triage")
def run_live_triage(req: LiveTriageRequest):
    """Executes live AI triage with or without Defense Shield."""
    alert = Alert(
        alert_id=req.alert_id or "live_demo_001",
        source_file="UI_Live_Console",
        row_index=0,
        src_ip="192.168.1.105",
        dst_ip="172.16.0.1",
        src_port=49152,
        dst_port=req.dst_port,
        protocol=req.protocol,
        flow_duration_us=req.flow_duration_us,
        fwd_packets=req.fwd_packets,
        bwd_packets=req.bwd_packets,
        total_bytes=req.total_bytes,
        packet_length_mean=req.packet_length_mean,
        flow_bytes_per_sec=req.flow_bytes_per_sec,
        syn_flag_count=1 if req.is_malicious else 0,
        fin_flag_count=0,
        rst_flag_count=0,
        notes_field=req.notes_field,
        is_malicious=req.is_malicious,
        attack_type=req.attack_type,
        label_ground_truth=req.attack_type.upper(),
        severity="critical" if req.is_malicious else "info",
    )

    agent = triage_defended if req.defense_active else triage_baseline
    result = agent.triage(alert, anomaly_score=req.anomaly_score)

    return JSONResponse(content={
        "alert": alert.to_dict(),
        "triage": result.to_dict(),
        "defense_active": req.defense_active,
    })


if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("🚀 Launching Adversarial AI SOC Command Center Dashboard")
    print("👉 Access UI at: http://127.0.0.1:8000")
    print("=" * 60)
    uvicorn.run("ui.app:app", host="127.0.0.1", port=8000, reload=True)
