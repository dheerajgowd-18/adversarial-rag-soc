# 🛡️ Project Architecture & Phase Breakdown Guide
### Adversarial RAG-Based SOC Triage System

> **Document Purpose:** A clean, technical, module-by-module overview of what was built, where each file lives, what data goes in/out, and what key metrics were achieved for every phase.
>
> **Updated:** All Phases 0–10 Complete (11 of 11 Phases Complete)

---

## 🏗️ High-Level System Architecture Diagram

```
[ CICIDS2017 CSV Data ]
          │
          ▼  (Phase 1)
 [ Ingestion Layer ] ──▶ data/alerts/clean_alerts.json (4,995 Alerts)
          │                └─▶ data/alerts/eval_fixed_set.json (200 Benchmark Set)
          ▼  (Phase 2)
  [ Rule Detection ] ──▶ data/alerts/suspicious_queue.json (1,416 Flagged)
          │                └─▶ Rule Recall: 46.0% (DDoS: 0% 🔴)
          ▼  (Phase 3)
   [ RAG Retriever ] ──▶ ChromaDB Vector Database (110 Threat Intel Chunks)
          │
          ▼  (Phase 4)
  [ LLM Triage Agent ] ──▶ eval/baseline_triage_metrics.json
          │                └─▶ LLM+RAG Recall: 95.0% (DDoS: 97.2% ✅)
          ▼  (Phase 6 & 7)
 [ Red-Team Attacks ] ──▶ eval/attack_results.md (CAT-1 ASR: 63%, CAT-3 ASR: 43%)
          │
          ▼  (Phase 8 & 9)
 [ 3-Tier Security Shield ] ──▶ eval/defended_results.md (Defended ASR: 0.0%, 100% DDR 🛡️)
          │
          ▼  (Interactive Dashboard)
  [ Web Command Center ] ──▶ ui/app.py (FastAPI Cyberpunk UI at http://127.0.0.1:8000)
```

---

## 📌 Phase-by-Phase Technical Reference

---

### 🟢 Phase 0 — Environment & API Infrastructure Setup
* **What we did:** Setup Python virtual environment (`venv`), pinned 135 dependencies in `requirements-lock.txt`, built unified configuration system (`config.py`), and verified Groq/LLM connectivity with a 4-key API load balancing pool (`KeyPool`).
* **Where the code lives:**
  - `config.py` — Single source of truth for all paths, API keys, and model parameters.
  - `setup_env.py` — Interactive `.env` generator for API keys.
  - `ingestion/hello_world.py` — Baseline LLM verification script.
* **Input:** API keys (`GROQ_API_KEY_1` through `GROQ_API_KEY_4`).
* **Output:** Operational `.env`, verified LLM connection (1,161ms latency).
* **Why it matters:** Guarantees zero path/key errors across all pipeline layers and bypasses free-tier API rate limits.

---

### 🟢 Phase 1 — Ingestion Layer & Canonical Alert Schema
* **What we did:** Parsed 1.39 million raw network flow records from the CICIDS2017 dataset (Wednesday & Friday PCAPs), normalized attributes into a canonical 22-field `Alert` schema, and constructed fixed benchmark evaluation sets.
* **Where the code lives:**
  - `ingestion/schema.py` — Canonical `SOCAlert` dataclass definition (contract for the entire pipeline).
  - `ingestion/build_alerts.py` — CSV parser, cleaner, and JSON builder.
  - `ingestion/generate_synthetic.py` — Synthetic alert generator for unit testing.
* **Input:** Raw CSVs in `data/raw/` (Wednesday/Friday PCAP exports).
* **Output:**
  - `data/alerts/clean_alerts.json` (4,995 total processed alerts)
  - `data/alerts/eval_fixed_set.json` (200 fixed evaluation alerts: 100 benign, 100 malicious)
* **Key Schema Field (`notes_field`):** Free-text field simulating SIEM analyst notes and payload commentary. **Primary attack surface for prompt injection.**

---

### 🟢 Phase 2 — Rule-Based Detection Gate
* **What we did:** Built a high-speed rule-based detection engine (`DetectionAgent`) with 11 heuristic network rules calibrated against real CICIDS2017 feature distributions.
* **Where the code lives:**
  - `agents/detection_agent.py` — 11-rule scoring engine (weighted anomaly score 0.0–1.0, threshold 0.28).
  - `agents/run_detection.py` — Batch runner and metric evaluator.
* **Input:** `data/alerts/clean_alerts.json`.
* **Output:**
  - `data/alerts/suspicious_queue.json` (1,416 alerts flagged `SUSPICIOUS`)
  - `eval/detection_metrics.json` (Performance summary)
* **Key Finding:**
  - **Overall Recall:** 46.0% | **F1-Score:** 0.5786 | **Speed:** 0.06ms/alert
  - **PortScan Recall:** 100.0% ✅
  - **Botnet Recall:** 100.0%* *(Note: n=2 alerts)*
  - **DDoS Recall:** **0.0%** 🔴 *(DDoS flow packet counts & byte sizes are statistically identical to legitimate HTTPS traffic, creating the core research gap).*

---

### 🟢 Phase 3 — RAG Knowledge Base & Retrieval Layer
* **What we did:** Created an 8-document threat intelligence knowledge base (110 chunks) covering attack signatures, created dense vector embeddings (`all-MiniLM-L6-v2`, 384-dim), and stored them in local ChromaDB vector store. Built semantic search query interface (`AlertRetriever`).
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
* **What we did:** Built the LLM Triage Agent (`TriageAgent`) combining LLM reasoning with Phase 3 RAG context. Built a multi-key client pool (`KeyPool`) round-robing across 4 Groq API keys to maximize speed and bypass free-tier rate limits.
* **Where the code lives:**
  - `agents/triage_agent.py` — RAG + LLM prompt builder, multi-key pool, and structured JSON output parser.
  - `agents/run_triage.py` — Batch parallel runner and evaluator.
  - `data/alerts/triage_results.json` — Full triage decisions.
  - `eval/baseline_triage_metrics.json` — Baseline performance metrics report.
* **Input:** `data/alerts/eval_fixed_set.json` (200 alerts) + ChromaDB RAG context.
* **Output:** Structured JSON decision per alert (`verdict`, `severity`, `confidence`, `reasoning`, `recommended_action`).
* **Key Results & Research Victory:**
  - **Overall Recall:** **95.0%** (Up from 46.0% in Phase 2)
  - **DDoS Recall:** **97.2% (35/36 caught)** ✅ *(RAG context solved the 0% DDoS blindspot!)*
  - **PortScan Recall:** **100.0% (37/37 caught)** ✅
  - **Botnet Recall:** **100.0%* (2/2 caught)** ✅ *(n=2 sample size)*
  - **DoS Recall:** **84.0% (21/25 caught)** ✅
  - **F1-Score:** **0.6835**

---

### 🟢 Phase 5 — Baseline Evaluation & Research Metrics
* **What we did:** Created automated research metric calculator (`eval/metrics.py`) and compiled the official baseline evaluation report `eval/baseline_report.md` containing **Research Paper Table 1**. Formatted all 200 raw AI decisions into a readable markdown table.
* **Where the code lives:**
  - `eval/metrics.py` — Metric calculation engine (Precision, Recall, F1, Accuracy, FPR, FNR, P50/P95 Latency).
  - `eval/baseline_report.md` — Locked baseline evaluation report containing Paper Table 1.
  - `eval/generate_md_log.py` — Log formatting script.
  - `eval/baseline_200_triage_log.md` — Formatted log of all 200 AI verdicts, reasoning, and RAG sources.
* **Input:** `data/alerts/triage_results.json` + `data/alerts/eval_fixed_set.json`.
* **Output:** Locked Research Paper Table 1 and baseline performance metrics.

---

### 🟢 Phase 6 — Red-Team Attack Taxonomy Design & KB Poisoner
* **What we did:** Formally defined a 4-category adversarial prompt injection attack taxonomy (`attacks/taxonomy.md`). Built `RedTeamInjector` (`attacks/injector.py`) and `build_and_run_cat2.py` to construct 4 adversarial datasets (CAT-1 Direct, CAT-2 RAG Poisoning, CAT-3 Role Spoofing, CAT-4 Chained).
* **Where the code lives:**
  - `attacks/taxonomy.md` — Formal 4-category attack taxonomy.
  - `attacks/injector.py` — Prompt injection generator (CAT-1, CAT-3, CAT-4).
  - `attacks/build_and_run_cat2.py` — Poisoned threat intel KB builder and ChromaDB indexer (`chroma_db_poisoned/`).
  - `attacks/verify_cat2_retrieval.py` — RAG vector retrieval audit script.
  - `data/alerts/attacked/` — 4 attacked JSON datasets (`eval_attacked_cat1_direct.json`, `eval_attacked_cat2_rag_poison.json`, `eval_attacked_cat3_role_spoof.json`, `eval_attacked_cat4_chained.json`).
* **Output:** Adversarial injected datasets and poisoned vector database ready for red-team evaluation in Phase 7.

---

### 🟢 Phase 7 — Red-Team Execution & Attack Evaluation
* **What we did:** Executed automated Red-Team Attack Evaluation Suite (`attacks/run_attacks.py` & `attacks/build_and_run_cat2.py`) across 800 total attack runs (200 alerts × 4 attack categories). Generated official Red-Team report `eval/attack_results.md` containing **Research Paper Table 2** and calculated Attack Success Rates (ASR).
* **Where the code lives:**
  - `attacks/run_attacks.py` — Automated Red-Team batch evaluation runner across 4 Groq API keys.
  - `attacks/build_and_run_cat2.py` — CAT-2 evaluation script for poisoned vector database.
  - `eval/attack_metrics.json` — Detailed ASR metrics per attack category and per attack type.
  - `eval/attack_results.md` — Red-Team Evaluation Report containing Paper Table 2.
  - `eval/attack_triage_log.md` — Detailed markdown log of all attacked alerts and AI responses.
* **Input:** Adversarial injected datasets in `data/alerts/attacked/` + `chroma_db_poisoned/`.
* **Output:** Empirical ASR metrics (CAT-1 Direct ASR: 63.0%, CAT-2 RAG Poisoning ASR: 0.0% [63/100 retrieved], CAT-3 Role Spoof ASR: 43.0%, CAT-4 Chained ASR: 4.0%).

---

### 🟢 Phase 8 & 9 — Defense Layer & Defended Evaluation
* **What we did:** Built the Multi-Tier Security Shield (`defense/filters.py`) featuring Input Sanitization, Structural Boundary Isolation, and Dual-Agent Verification. Executed `defense/run_defended_eval.py` across all 4 adversarial datasets and compiled official report `eval/defended_results.md` containing **Research Paper Table 3**.
* **Where the code lives:**
  - `defense/filters.py` — Multi-Tier Security Shield engine.
  - `defense/run_defended_eval.py` — Defended Evaluation Runner script.
  - `eval/defense_metrics.json` — Structured defense metrics.
  - `eval/defended_results.md` — Defended Evaluation Report containing Paper Table 3.
* **Input:** Adversarial injected datasets + Clean baseline set.
* **Output:** 100.0% Defense Defense Rate (DDR), reducing Defended ASR to 0.0% across all 4 attack categories.

---

### 🟢 Interactive Cyberpunk Web Command Center Dashboard
* **What we did:** Built an interactive FastAPI single-page web dashboard displaying real-time RAG context retrieval, live Red-Team attack simulation, and real-time Multi-Tier Security Shield controls.
* **Where the code lives:**
  - `ui/app.py` — FastAPI REST API endpoints.
  - `ui/templates/index.html` — HTML dashboard layout.
  - `ui/static/style.css` — Cyberpunk dark mode styling.
  - `ui/static/main.js` — Frontend state management and live triage logic.

---

### 🟢 Phase 10 — Academic Research Paper Manuscript
* **What we did:** Compiled experimental findings into an IEEE-formatted academic research manuscript.
* **Where the code lives:**
  - `paper/RESEARCH_PAPER_MANUSCRIPT.md` — Publication-ready manuscript.

---

## 📊 Complete Metric Summary Table Across Phases

| Metric | Phase 2 (Rule Gate) | Phase 4 (LLM Baseline) | Phase 7 (Undefended Attack ASR) | Phase 8 & 9 (Defended ASR / DDR) |
|---|---|---|---|---|
| **Direct Field Injection (CAT-1)** | — | — | **63.0% ASR Compromised** 🔴 | **0.0% ASR (100% DDR Neutralized)** 🛡️ |
| **Retrieved-Doc Poisoning (CAT-2)** | — | — | **0.0% ASR (63/100 retrieved)** 🟢 | **0.0% ASR (100% DDR Neutralized)** 🛡️ |
| **Role-Confusion Spoofing (CAT-3)** | — | — | **43.0% ASR Compromised** 🟠 | **0.0% ASR (100% DDR Neutralized)** 🛡️ |
| **Indirect Chained Injection (CAT-4)** | — | — | **78.0% ASR Compromised** 🔴 | **0.0% ASR (100% DDR Neutralized)** 🛡️ |
| **Overall Attack Recall / Safety** | 46.0% | **95.0%** | **63.0% Vulnerable** | **100% Protected** ✅ |
| **DDoS Attack Recall** | 0.0% | **97.2%** | **61.1% recall under CAT-3 (38.9% ASR)** | **97.2%** (100% Protected) ✅ |

---
*Last updated: 2026-07-31 | All 11 phases complete*
