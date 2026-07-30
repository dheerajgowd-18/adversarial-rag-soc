# 🛡️ Project Architecture & Phase Breakdown Guide
### Adversarial RAG-Based SOC Triage System

> **Document Purpose:** A clean, technical, module-by-module overview of what was built, where each file lives, what data goes in/out, and what key metrics were achieved for every phase.
>
> **Updated:** Phase 4 Complete (5 of 11 Phases Complete)

---

## 🏗️ High-Level System Architecture Diagram

```
[ CICIDS2017 CSV Data ]
          │
          ▼  (Phase 1)
 [ Ingestion Layer ] ──▶ data/alerts/clean_alerts.json (4,995 Alerts)
          │
          ▼  (Phase 2)
  [ Rule Detection ] ──▶ data/alerts/suspicious_queue.json (1,416 Flagged)
          │                └─▶ Rule Recall: 43.1% (DDoS: 0% 🔴)
          ▼  (Phase 3)
   [ RAG Retriever ] ──▶ ChromaDB Vector Database (110 Threat Intel Chunks)
          │
          ▼  (Phase 4)
  [ LLM Triage Agent ] ──▶ eval/baseline_triage_metrics.json
                           └─▶ LLM+RAG Recall: 95.0% (DDoS: 97.2% ✅)
```

---

## 📌 Phase-by-Phase Technical Reference

---

### 🟢 Phase 0 — Environment & LLM Client Setup
* **What we did:** Setup Python virtual environment (`venv`), pinned 135 dependencies in `requirements-lock.txt`, built unified configuration system (`config.py`), and verified Groq/LLM connectivity.
* **Where the code lives:**
  - `config.py` — Single source of truth for all paths, API keys, and model parameters.
  - `setup_env.py` — Interactive `.env` generator for API keys.
  - `ingestion/hello_world.py` — Baseline LLM verification script.
* **Input:** API keys (`GROQ_API_KEY`, `OPENROUTER_API_KEY`).
* **Output:** Operational `.env`, verified LLM connection (1,161ms latency).
* **Why it matters:** Guarantees zero path/key errors across all future pipeline layers.

---

### 🟢 Phase 1 — Ingestion Layer & Canonical Alert Schema
* **What we did:** Parsed 1.39 million raw network flow records from the CICIDS2017 dataset (Wednesday & Friday PCAPs), normalized attributes into a canonical 22-field `Alert` schema, and constructed fixed benchmark evaluation sets.
* **Where the code lives:**
  - `ingestion/schema.py` — Canonical `Alert` dataclass definition (contract for the entire pipeline).
  - `ingestion/build_alerts.py` — CSV parser, cleaner, and JSON builder.
  - `ingestion/generate_synthetic.py` — Synthetic alert generator for unit testing.
* **Input:** Raw CSVs in `data/raw/` (Wednesday/Friday PCAP exports).
* **Output:**
  - `data/alerts/clean_alerts.json` (4,995 total processed alerts)
  - `data/alerts/eval_fixed_set.json` (200 fixed evaluation alerts: 100 benign, 100 malicious)
* **Key Schema Field (`notes_field`):** Free-text field simulating SIEM analyst notes. **This is our primary attack surface for prompt injection in Phase 6.**

---

### 🟢 Phase 2 — Rule-Based Detection Gate
* **What we did:** Built a zero-cost, high-speed rule-based detection engine (`DetectionAgent`) with 11 heuristic network rules calibrated against real CICIDS2017 feature distributions.
* **Where the code lives:**
  - `agents/detection_agent.py` — 11-rule scoring engine (weighted anomaly score 0.0–1.0, threshold 0.28).
  - `agents/run_detection.py` — Batch runner and metric evaluator.
* **Input:** `data/alerts/clean_alerts.json`.
* **Output:**
  - `data/alerts/suspicious_queue.json` (1,416 alerts flagged `SUSPICIOUS`)
  - `eval/detection_metrics.json` (Performance summary)
* **Key Finding:**
  - **Overall Recall:** 43.1% | **F1-Score:** 0.490 | **Speed:** 0.04ms/alert
  - **PortScan Recall:** 99.6% ✅
  - **DDoS Recall:** **0.0%** 🔴 *(DDoS flow packet counts & byte sizes are statistically identical to legitimate HTTPS traffic, creating the core research gap).*

---

### 🟢 Phase 3 — RAG Knowledge Base & Retrieval Layer
* **What we did:** Created a 8-document threat intelligence knowledge base (110 chunks) covering attack signatures, created dense vector embeddings (`all-MiniLM-L6-v2`, 384-dim), and stored them in local ChromaDB vector store. Built semantic search query interface (`AlertRetriever`).
* **Where the code lives:**
  - `data/knowledge_base/*.txt` — Threat intel text files (DDoS, DoS, PortScan, Botnet, Heartbleed, Brute Force, Benign Baselines, Prompt Injection Defense).
  - `retrieval/build_kb.py` — Text chunker, embedder, and ChromaDB vector builder.
  - `retrieval/retriever.py` — `AlertRetriever` class for semantic context search.
  - `retrieval/test_retriever.py` — Automated verification test suite.
  - `chroma_db/` — Local vector store index.
* **Input:** Natural language alert `notes_field` + network flow parameters.
* **Output:** Top-3 relevant threat intelligence text blocks formatted for LLM prompts.
* **Verification:** 100% pass (7/7 test cases passed across all attack types).

---

### 🟢 Phase 4 — Triage Reasoning Agent (LLM + RAG)
* **What we did:** Built the LLM Triage Agent (`TriageAgent`) combining LLM reasoning with Phase 3 RAG context. Built a multi-key client pool (`KeyPool`) round-robing across Groq and OpenRouter keys to maximize speed and bypass free-tier rate limits.
* **Where the code lives:**
  - `agents/triage_agent.py` — RAG + LLM prompt builder, multi-key pool, and structured JSON output parser.
  - `agents/run_triage.py` — Batch parallel runner and evaluator.
  - `data/alerts/triage_results.json` — Full triage decisions.
  - `eval/baseline_triage_metrics.json` — Baseline performance metrics report.
* **Input:** `data/alerts/eval_fixed_set.json` (200 alerts) + ChromaDB RAG context.
* **Output:** Structured JSON decision per alert (`verdict`, `severity`, `confidence`, `reasoning`, `recommended_action`).
* **Key Results & Research Victory:**
  - **Overall Recall:** **95.0%** (Up from 43.1% in Phase 2)
  - **DDoS Recall:** **97.2% (35/36 caught)** ✅ *(RAG context solved the 0% DDoS blindspot!)*
  - **PortScan Recall:** **100.0% (37/37 caught)** ✅
  - **Botnet Recall:** **100.0% (2/2 caught)** ✅
  - **DoS Recall:** **84.0% (21/25 caught)** ✅
  - **F1-Score:** **0.6835**

---

## 🔮 Upcoming Phases (Roadmap)

| Phase | Module Name | Primary Objective | Output File |
|---|---|---|---|
| **Phase 5** | Baseline Evaluation | Generate comparative plots & summary report for baseline performance | `eval/baseline_report.md` |
| **Phase 6** | Attack Layer | Implement 4 prompt injection attack types into `notes_field` | `data/alerts/attacked/*.json` |
| **Phase 7** | Red-Team Eval | Evaluate LLM compromise rate under adversarial prompt injection | `eval/attack_metrics.json` |
| **Phase 8** | Defense Layer | Implement input sanitization + dual-agent validation | `agents/defense_agent.py` |
| **Phase 9** | Defense Eval | Measure security restoration rate after applying defense | `eval/defense_metrics.json` |
| **Phase 10** | Paper Writing | Compile experimental results into IEEE research paper format | `paper/main.tex` |

---

## 📊 Complete Metric Summary Table Across Phases

| Metric | Phase 2 (Rule Gate) | Phase 4 (LLM + RAG Baseline) | Impact of RAG + LLM |
|---|---|---|---|
| **Overall Attack Recall** | 43.1% | **95.0%** | **+51.9%** 🚀 |
| **DDoS Attack Recall** | **0.0%** | **97.2%** | **+97.2%** 🎉 |
| **PortScan Recall** | 99.6% | **100.0%** | +0.4% |
| **Botnet Recall** | 67.0% | **100.0%** | +33.0% |
| **DoS Recall** | 23.0% | **84.0%** | +61.0% |
| **F1-Score** | 0.490 | **0.6835** | **+0.1935** |

---
*Last updated: 2026-07-30 | Phase 4 complete*
