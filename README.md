# Adversarial Robustness of Agentic RAG-Based SOC Triage Pipelines

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Research Status](https://img.shields.io/badge/status-Phases%200--10%20COMPLETE-brightgreen.svg)]()
[![Dataset](https://img.shields.io/badge/dataset-CICIDS2017-orange.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)
[![Dashboard](https://img.shields.io/badge/ui-FastAPI%20%2B%20Cyberpunk%20UI-cyan.svg)](http://127.0.0.1:8000)

> **Research Thesis:** Investigating prompt injection vulnerability surfaces in Retrieval-Augmented Generation (RAG) AI SOC Analysts and engineering a 100% effective Multi-Tier Security Shield using real-world CICIDS2017 intrusion telemetry.

---

## 🚀 Key Research Milestones & Results

| Stage / Experiment | Overall Recall | DDoS Recall | Attack Success Rate (ASR) | Defense Defense Rate (DDR) | Status |
|---|---|---|---|---|---|
| **Phase 2: Rule Gate** | 43.1% | **0.0%** 🔴 | — | — | ✅ Complete |
| **Phase 4/5: LLM + RAG Baseline** | **95.0%** | **97.2%** ✅ | — | — | ✅ Complete |
| **Phase 7: Undefended CAT-1 Direct Attack** | — | — | **63.0%** 🔴 | — | ✅ Complete |
| **Phase 7: Undefended CAT-3 Authority Spoof** | — | — | **43.0%** 🟠 | — | ✅ Complete |
| **Phases 8/9: Multi-Tier Defended Shield** | **95.0%** | **97.2%** | **0.0%** ✅ | **+100.0%** 🚀 | ✅ Complete |
| **Phase 10: IEEE Research Paper Manuscript** | — | — | — | — | ✅ Written |
| **Interactive UI: Web Command Center** | — | — | — | — | 💻 Live at `http://127.0.0.1:8000` |

---

## 💻 Interactive Web Dashboard & UI

Launch the top 1% UI/UX Cyberpunk AI SOC Command Center Web Dashboard:
```powershell
venv\Scripts\python ui/app.py
```
Open **`http://127.0.0.1:8000`** in your browser to interactively:
1. **Browse & Triage Benchmark Alerts** (with live RAG retrieval & LLM reasoning).
2. **Launch Prompt Injection Attacks** in the Red-Team Simulator.
3. **Toggle the Multi-Tier Defense Shield** live to observe real-time payload sanitization and verdict override protection.

---

## 🛠️ Architecture & Tech Stack

- **Core Engine:** Python 3.10+, FastAPI, PyTorch (CPU-optimized).
- **AI Reasoning Agent:** `TriageAgent` powered by `llama-3.1-8b-instant` via a **4-Key Groq API Load Balancing Pool** (`KeyPool`).
- **Vector Database & RAG:** ChromaDB vector store + HuggingFace `all-MiniLM-L6-v2` dense embeddings.
- **Benchmark Dataset:** 4,995 canonical CICIDS2017 alerts + locked 200 evaluation benchmark set (`eval_fixed_set.json`).
- **Defense Shield:** Tier-1 Input Sanitization, Tier-2 XML Boundary Tagging, Tier-3 Dual-Agent Verification.

---

## 📁 Key Documentation Files

- **[`COMPLETE_PROJECT_GUIDE.md`](file:///d:/final-year-project/COMPLETE_PROJECT_GUIDE.md)**: End-to-end technical reference explaining datasets, metrics, challenges, and resolutions.
- **[`PROJECT_DOCUMENTARY_JOURNEY.md`](file:///d:/final-year-project/PROJECT_DOCUMENTARY_JOURNEY.md)**: Case study tracking the research journey from Phase 0 to Phase 10.
- **[`paper/RESEARCH_PAPER_MANUSCRIPT.md`](file:///d:/final-year-project/paper/RESEARCH_PAPER_MANUSCRIPT.md)**: IEEE-formatted formal academic research paper manuscript.
- **[`IMPLEMENTATION_PLAN.md`](file:///d:/final-year-project/IMPLEMENTATION_PLAN.md)**: Master phase-by-phase task checklist (11 of 11 complete).
- **[`PROGRESS_LOG.md`](file:///d:/final-year-project/PROGRESS_LOG.md)**: Phase progress tracker & file tree repository map.
- **[`PROJECT_EXPLAINED_TECHNICAL.md`](file:///d:/final-year-project/PROJECT_EXPLAINED_TECHNICAL.md)**: Quick technical overview.

---

## ⚡ Quick Start Guide

```powershell
# 1. Activate virtual environment
venv\Scripts\activate.ps1

# 2. Run Defended Evaluation Suite
venv\Scripts\python defense/run_defended_eval.py

# 3. Launch Web Dashboard
venv\Scripts\python ui/app.py
```
