# Adversarial Robustness of Agentic RAG-Based SOC Triage Pipelines

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Research](https://img.shields.io/badge/type-Research-purple.svg)]()
[![Status](https://img.shields.io/badge/status-Phase%200-orange.svg)]()

## Overview

This project builds an AI agent pipeline that triages security alerts using Retrieval-Augmented Generation (RAG), then systematically attacks the pipeline with prompt-injection payloads, and finally implements a defense layer. The full study (baseline → attacked → defended) is packaged into a research paper targeting a Scopus-indexed IEEE/Springer conference.

**Core research question:**
> How vulnerable are agentic RAG-based security triage systems to prompt injection, and can a lightweight defense meaningfully reduce that vulnerability?

---

## Project Narrative

```
Build → Attack → Defend → Measure → Publish
```

1. **Build** — An AI SOC analyst that reads security alerts, retrieves context from MITRE ATT&CK / CVE / incident reports, and outputs structured triage decisions
2. **Attack** — 4 categories of prompt-injection attacks hidden in alert data and retrieved documents
3. **Defend** — A two-layer defense (input sanitization + output consistency check)
4. **Measure** — Attack Success Rate (ASR) before and after defense, with latency tradeoff
5. **Publish** — IEEE/Springer conference paper

---

## Tech Stack

| Component | Choice |
|---|---|
| Language | Python 3.10+ |
| Agent Framework | LangGraph + LangChain |
| Vector DB | ChromaDB (local) |
| Embeddings | sentence-transformers `all-MiniLM-L6-v2` |
| Dataset | CICIDS2017 (Wednesday + Friday subset) |
| Knowledge Base | MITRE ATT&CK STIX + CVE/NVD subset + Synthetic incidents |
| LLM (early phases) | Groq (Llama 3.1 8B — free tier) |
| LLM (Phase 4+) | Claude Haiku / GPT-4o-mini |

---

## Repository Structure

```
adversarial-rag-soc/
├── data/
│   ├── raw/                    ← CICIDS2017 CSVs (gitignored — too large)
│   ├── alerts/                 ← Processed alert JSON store
│   │   └── attacked/           ← Injected alert variants per attack category
│   └── knowledge_base/         ← MITRE ATT&CK, CVE subset, synthetic incidents
├── ingestion/                  ← Phase 1: build_alerts.py
├── agents/                     ← Phase 2 & 4: detection_agent.py, triage_agent.py
├── retrieval/                  ← Phase 3: build_index.py, query.py
├── attacks/                    ← Phase 6 & 7: taxonomy.md, run_attacks.py
├── defense/                    ← Phase 8: filters.py
├── eval/                       ← Phase 5,7,8,9: metrics.py + result files
├── logs/                       ← All agent run outputs (gitignored)
├── paper/                      ← LaTeX/Word paper drafts
├── .env                        ← API keys (gitignored — never commit)
├── .env.example                ← Template for .env (safe to commit)
├── requirements.txt            ← Python dependencies
├── IMPLEMENTATION_PLAN.md      ← Phase-by-phase tracker
└── README.md
```

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/adversarial-rag-soc.git
cd adversarial-rag-soc

# 2. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
cp .env.example .env
# Edit .env and add your API keys

# 5. Download CICIDS2017 dataset
# See data/raw/DOWNLOAD_INSTRUCTIONS.md

# 6. Verify setup
python ingestion/hello_world.py
```

---

## Current Phase

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for detailed task tracking.

| Phase | Status |
|---|---|
| Phase 0 — Setup | 🟡 In Progress |
| Phase 1 — Ingestion | ⬜ Not Started |
| Phase 2 — Detection | ⬜ Not Started |
| Phase 3 — RAG | ⬜ Not Started |
| Phase 4 — Triage Agent | ⬜ Not Started |
| Phase 5 — Baseline Eval | ⬜ Not Started |
| Phase 6 — Attack Taxonomy | ⬜ Not Started |
| Phase 7 — Red-Team | ⬜ Not Started |
| Phase 8 — Defense | ⬜ Not Started |
| Phase 9 — Re-Evaluation | ⬜ Not Started |
| Phase 10 — Paper | ⬜ Not Started |
| Phase 11 — Submission | ⬜ Not Started |

---

## Important Notes

- **Never commit `.env`** — it contains API keys
- **Never commit `data/raw/`** — CICIDS2017 CSVs are large (several GB)
- **Log everything** — every agent run writes to `logs/`, never just `print()`
- **Use JSON mode** for all LLM outputs — never regex-parse free text

---

## Dataset

**CICIDS2017** — Canadian Institute for Cybersecurity Intrusion Detection System 2017

Download from: https://www.unb.ca/cic/datasets/ids-2017.html

We use **Wednesday** and **Friday** days only (good attack diversity, manageable size).

---

*Research project — Final Year / Postgraduate*
