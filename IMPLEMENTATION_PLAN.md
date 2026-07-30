# 🗺️ IMPLEMENTATION PLAN — Adversarial RAG SOC Triage
## Adversarial Robustness of Agentic RAG-Based SOC Triage Pipelines

**Total Duration:** 26 weeks (~6 months)
**Research Goal:** Build → Attack → Defend → Measure → Publish

> **How to use this file:**
> - Update checkboxes as you complete tasks: `[ ]` → `[x]`
> - Mark in-progress tasks with: `[~]`
> - Add notes under tasks with `> Note: ...`
> - Commit this file to GitHub after every session so your guide can track progress
> - Never skip the **✅ Phase Gate** before moving to the next phase

---

## 📊 Progress Dashboard

> Update this section at the start of every week.

| Phase | Name | Status | Target Week | Done Week |
|---|---|---|---|---|
| 0 | Setup & Environment | `[x] COMPLETE` | Week 1 | 2026-07-28 |
| 1 | Ingestion Layer | `[x] COMPLETE` | Week 2–3 | 2026-07-29 |
| 2 | Detection Agent | `[x] COMPLETE` | Week 3–4 | 2026-07-29 |
| 3 | RAG Retrieval Layer | `[x] COMPLETE` | Week 4–6 | 2026-07-29 |
| 4 | Triage Reasoning Agent | `[x] COMPLETE` | Week 6–9 | 2026-07-30 |
| 5 | Baseline Evaluation | `[x] COMPLETE` | Week 9–10 | 2026-07-30 |
| 6 | Attack Taxonomy Design | `[x] COMPLETE` | Week 10–12 | 2026-07-30 |
| 7 | Red-Team Execution | `[ ] Not Started` | Week 12–15 | — |
| 8 | Defense / Verification Layer | `[ ] Not Started` | Week 15–18 | — |
| 9 | Full Re-Evaluation | `[ ] Not Started` | Week 18–20 | — |
| 10 | Paper Writing | `[ ] Not Started` | Week 20–24 | — |
| 11 | Submission & Buffer | `[ ] Not Started` | Week 24–26 | — |

**Overall Progress:** `7 / 11 phases complete`

---

---

## 🟢 Phase 0 — Setup & Environment

**⏱ Duration:** 3–5 days | **📅 Target:** Week 1
**🎯 Goal:** Everything installed, running, and version-controlled before a single line of pipeline logic is written.

---

### 0.1 — Repository Setup

- [ ] Create GitHub repository (name: `adversarial-rag-soc`, visibility: Private)
- [ ] Clone repo locally to your machine
- [x] Create the canonical folder structure:
  ```
  /data/raw/
  /data/alerts/
  /data/knowledge_base/
  /ingestion/
  /agents/
  /retrieval/
  /attacks/
  /defense/
  /eval/
  /logs/
  /paper/
  ```
- [x] Create `README.md` with one-paragraph project description
- [x] Create `.gitignore` (must include: `.env`, `__pycache__/`, `*.pyc`, `data/raw/`, `logs/`, `data/chroma_*/`)
- [ ] Make first commit: `"chore: scaffold project structure"` ← do after GitHub repo is created

---

### 0.2 — Python Environment

- [x] Confirm Python 3.10+ is installed: `python --version` → Python 3.10.8 ✅
- [x] Create virtual environment: `python -m venv venv`
- [x] Install all required libraries (via `requirements.txt`) — 135 packages total:
  - [x] `langgraph` 1.2.9
  - [x] `langchain` 1.3.14, `langchain-groq` 1.1.3, `langchain-anthropic` 1.5.3, `langchain-openai` 1.4.1
  - [x] `chromadb` 1.5.9
  - [x] `pandas` 2.3.3, `numpy` 2.2.6, `scikit-learn` 1.7.2
  - [x] `sentence-transformers` 5.6.1
  - [x] `python-dotenv` 1.2.2, `jsonlines` 4.0.0, `requests` 2.34.2
- [x] Frozen to `requirements-lock.txt` (135 packages, exact pinned versions)
- [x] Committed: `"chore: add requirements.txt"`

---

### 0.3 — API Key & Environment Config

- [ ] Sign up for a free LLM API (Groq at https://console.groq.com — free, no credit card)
- [ ] Run `python setup_env.py` to generate your `.env` interactively ← NEW HELPER SCRIPT
  ```
  GROQ_API_KEY=your_key_here
  LLM_MODEL=llama-3.1-8b-instant
  ```
- [x] `.env.example` template created and committed
- [x] Verify `.env` is in `.gitignore` ← confirmed
- [ ] Verify `.env` loads correctly: `python -c "from config import cfg; cfg.validate()"`

---

### 0.4 — Dataset Download

- [ ] Go to: https://www.unb.ca/cic/datasets/ids-2017.html
  > See `data/raw/DOWNLOAD_INSTRUCTIONS.md` for the exact files to download
- [ ] Download **Wednesday** traffic CSV (`Wednesday-workingHours.pcap_ISCX.csv`)
- [ ] Download **Friday** traffic CSVs (DDos + PortScan + Morning)
- [ ] Place all CSVs under `data/raw/`
- [x] Verify files are NOT committed (covered by `.gitignore`) ← confirmed
- [ ] Open one CSV in pandas and confirm columns load correctly:
  ```python
  import pandas as pd
  df = pd.read_csv("data/raw/Wednesday-workingHours.pcap_ISCX.csv")
  df.columns = df.columns.str.strip()
  print(df.columns.tolist())
  print(df[' Label'].value_counts())
  ```

---

### 0.5 — Hello World LLM Call

- [x] Create `ingestion/hello_world.py` ← production-quality script with structured logging
- [ ] Run `python ingestion/hello_world.py` ← requires .env to be configured first
- [ ] Log created at `logs/hello_world.log` (script does this automatically)
- [ ] Confirm: response is non-empty, logging works
- [ ] Commit: `"test: hello world LLM call working"`

---

### ✅ Phase 0 Gate — Before proceeding to Phase 1, confirm ALL of these:

- [x] Repo is pushed to GitHub → https://github.com/dheerajgowd-18/adversarial-rag-soc
- [x] `requirements.txt` committed, `requirements-lock.txt` (135 packages) committed
- [x] `.env` configured with Groq API key (NOT committed)
- [x] `python ingestion/hello_world.py` → PASSED ✅
  - Provider: groq | Model: llama-3.1-8b-instant | Latency: 1161ms
  - Response: valid JSON | Log: logs/hello_world.log ✅

> **Phase 0 Completed Date:** 2026-07-29

---

---

## 🟢 Phase 1 — Ingestion Layer

**⏱ Duration:** ~1.5 weeks | **📅 Target:** Week 2–3
**🎯 Goal:** Transform raw CICIDS2017 CSV rows into structured SOC alert JSON objects.
**📦 Deliverable:** `ingestion/build_alerts.py` → `data/alerts/clean_alerts.json`

---

### 1.1 — Explore the Data

- [ ] Load Wednesday CSV into pandas, print shape and column names
- [ ] Load Friday CSV(s), check columns are identical
- [ ] Print `value_counts()` of the `Label` column — understand which attack types are present
- [ ] Identify the key columns to keep: `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Protocol`, `Label`
- [ ] Note any data quality issues (NaN rows, infinite values) and handle them

---

### 1.2 — Filter to Attack Records Only

- [ ] Filter out all rows where `Label == 'BENIGN'`
- [ ] Print how many attack rows remain
- [ ] Print attack type distribution after filter (ensure diverse attack types present)
- [ ] Sample a balanced subset of ~500–1000 rows across attack types

---

### 1.3 — Design and Implement Alert Schema

- [ ] Define the exact alert JSON schema (freeze this — don't change it later):
  ```json
  {
    "alert_id": "a001",
    "timestamp": "2017-07-05T09:23:14Z",
    "src_ip": "192.168.10.15",
    "dst_ip": "52.6.13.28",
    "src_port": 49153,
    "dst_port": 80,
    "protocol": "TCP",
    "attack_label": "DoS Hulk",
    "raw_features": {
      "flow_duration": 1234567,
      "total_fwd_packets": 890,
      "total_bwd_packets": 2,
      "fwd_packet_length_mean": 42.5
    },
    "notes_field": ""
  }
  ```
- [ ] Map CICIDS2017 columns to schema fields
- [ ] Generate a unique `alert_id` for each row (e.g. `a001`, `a002`, ...)
- [ ] Ensure `notes_field` is present and empty string `""` for all baseline alerts

---

### 1.4 — Write and Test `build_alerts.py`

- [ ] Implement `load_and_filter()` — reads CSVs, drops BENIGN, handles NaN/inf
- [ ] Implement `normalize_alert()` — converts one row to the alert JSON schema
- [ ] Implement `write_alerts()` — writes list of alerts to `data/alerts/clean_alerts.json`
- [ ] Run the script end-to-end: `python ingestion/build_alerts.py`
- [ ] Verify output: open `clean_alerts.json`, manually read 10 alerts
- [ ] Confirm: all `attack_label` values are non-BENIGN
- [ ] Confirm: all alerts have `notes_field` as an empty string
- [ ] Confirm: between 500–1000 alerts total

---

### 1.5 — Validation

- [ ] Write a quick validation script or function:
  - [ ] All alerts have required fields
  - [ ] All `alert_id` values are unique
  - [ ] No `attack_label` is `BENIGN`
  - [ ] All `notes_field` values are `""`
- [ ] Run validation — zero errors
- [ ] Commit: `"feat: ingestion layer complete - clean_alerts.json produced"`

---

### ✅ Phase 1 Gate

- [ ] `ingestion/build_alerts.py` runs without errors
- [ ] `data/alerts/clean_alerts.json` exists with 500–1000 records
- [ ] Schema matches the defined format exactly
- [ ] Validation passes with zero errors

> **Phase 1 Completed Date:** ___________

---

---

## 🟢 Phase 2 — Detection Agent

**⏱ Duration:** 3–4 days | **📅 Target:** Week 3–4
**🎯 Goal:** A simple gate that filters which alerts get sent to the triage agent.
**📦 Deliverable:** `agents/detection_agent.py`

---

### 2.1 — Core Rule-Based Filter

- [ ] Create `agents/detection_agent.py`
- [ ] Implement `run_detection(alert_store: list[dict]) -> list[str]`:
  - Load alerts from `clean_alerts.json`
  - Flag any alert where `attack_label != "BENIGN"` as suspicious (all, since we already filtered)
  - Return a list of `alert_id` strings

---

### 2.2 — Optional: Anomaly Score Enhancement

- [ ] Compute z-score on `raw_features.total_fwd_packets` across all alerts
- [ ] Add `anomaly_score` float field to each alert in the queue output
- [ ] Alerts with `|z| > 2.0` flagged as `priority: high`, others as `priority: normal`

---

### 2.3 — Output

- [ ] Write `data/alerts/suspicious_queue.json` — list of `{alert_id, priority}` dicts
- [ ] Print summary: total alerts in queue, breakdown by priority
- [ ] Commit: `"feat: detection agent complete"`

---

### ✅ Phase 2 Gate

- [ ] `agents/detection_agent.py` runs without errors
- [ ] Given `clean_alerts.json` as input, produces a valid `suspicious_queue.json`
- [ ] All alerts in queue are non-BENIGN

> **Phase 2 Completed Date:** ___________

---

---

## 🟢 Phase 3 — RAG Retrieval Layer

**⏱ Duration:** ~2 weeks | **📅 Target:** Week 4–6
**🎯 Goal:** Build the vector knowledge base the triage agent will search at reasoning time.
**📦 Deliverables:** `retrieval/build_index.py`, `retrieval/query.py`, populated ChromaDB at `data/chroma_clean/`

---

### 3.1 — Source 1: MITRE ATT&CK

- [ ] Download MITRE ATT&CK STIX bundle: https://github.com/mitre/cti (enterprise-attack folder)
- [ ] Save to `data/knowledge_base/enterprise-attack.json`
- [ ] Parse into technique-level chunks:
  - Each chunk = one ATT&CK technique
  - Fields: `id` (T-number), `name`, `description`, `tactic`, `source: "mitre_attack"`
- [ ] Verify you have at least 200+ technique chunks parsed

---

### 3.2 — Source 2: CVE/NVD Subset

- [ ] Identify 10–15 CVE IDs relevant to CICIDS2017 attack types (DoS, SSH brute force, XSS, SQLi, DDoS)
- [ ] Download NVD data for those CVEs (use NVD API: https://nvd.nist.gov/developers/vulnerabilities)
- [ ] Save to `data/knowledge_base/cve_subset.json`
- [ ] Parse into chunks: `cve_id`, `description`, `cvss_score`, `source: "cve_nvd"`
- [ ] Target: 100–300 CVE chunks

---

### 3.3 — Source 3: Synthetic Incident Reports

- [ ] Generate 20–30 synthetic incident reports using an LLM
- [ ] Each report: 150–300 words, follows standard incident report format
- [ ] Cover all attack types present in the alert dataset
- [ ] Add field `"source": "synthetic_llm_generated"` to every report (required for paper)
- [ ] Save to `data/knowledge_base/synthetic_incidents/`

---

### 3.4 — Embedding & ChromaDB Indexing

- [ ] Create `retrieval/build_index.py`
- [ ] Load `sentence-transformers` model `all-MiniLM-L6-v2` locally (downloads ~90MB once)
- [ ] Initialize ChromaDB persistent client at path `data/chroma_clean/`
- [ ] Create three collections: `mitre_attack`, `cve_subset`, `incidents`
- [ ] Embed and add all chunks to their respective collections
- [ ] Run `build_index.py` end-to-end
- [ ] Print collection item counts: `collection.count()` for each — confirm non-zero

---

### 3.5 — Retrieval Function

- [ ] Create `retrieval/query.py`
- [ ] Implement `retrieve_context(alert: dict, top_k: int = 3) -> list[str]`:
  - Build query string from `attack_label` + `notes_field`
  - Embed query with same model
  - Query all 3 collections, return merged flat list of text chunks
- [ ] Implement `retrieve_with_metadata(alert, top_k)` — same but includes source info

---

### 3.6 — Relevance Spot-Check

- [ ] Select 15 alerts spanning different attack types
- [ ] For each, call `retrieve_context()` and read returned chunks manually
- [ ] Record relevance rating (1–5) in `eval/retrieval_spot_check.md`
- [ ] At least 80% of spot checks should be rated 3 or above
- [ ] If relevance is poor — debug chunk quality and query construction
- [ ] Commit: `"feat: RAG retrieval layer complete"`

---

### ✅ Phase 3 Gate

- [ ] All three ChromaDB collections populated and queryable
- [ ] `retrieve_context()` returns relevant chunks for 10+ manually verified alerts
- [ ] Spot-check results documented in `eval/retrieval_spot_check.md`
- [ ] `data/chroma_clean/` backed up (this is the canonical clean knowledge base)

> **Phase 3 Completed Date:** ___________

---

---

## 🔴 Phase 4 — Triage / Reasoning Agent (CRITICAL PATH)

**⏱ Duration:** ~3 weeks | **📅 Target:** Week 6–9
**🎯 Goal:** A LangGraph agent that takes alert + context and outputs a structured severity decision.
**📦 Deliverables:** `agents/triage_agent.py`, `eval/baseline_results.csv`

> ⚠️ **Do NOT compress this phase.** Everything downstream depends on it being done, not perfect.

---

### 4.1 — Learn LangGraph First (Dedicated Days)

- [ ] Spend 2–3 full days on LangGraph BEFORE building the triage agent
- [ ] Read: https://langchain-ai.github.io/langgraph/
- [ ] Complete the Quick Start tutorial
- [ ] Build a toy 3-node graph unrelated to the project to confirm understanding of:
  - [ ] `AgentState` as a TypedDict
  - [ ] Node functions (receive state, return state)
  - [ ] Adding nodes and edges
  - [ ] Compiling and invoking the graph

---

### 4.2 — Define Agent State

- [ ] Define `AgentState` TypedDict:
  ```python
  class AgentState(TypedDict):
      alert: dict
      context: list[str]
      decision: Optional[dict]
      trace: list[str]
      run_id: str
  ```

---

### 4.3 — Implement Graph Nodes

- [ ] `alert_input_node(state)` — logs receipt, returns state unchanged
- [ ] `retrieve_context_node(state)` — calls `retrieve_context()`, adds to state
- [ ] `reason_node(state)` — builds prompt, calls LLM with structured output, parses JSON
- [ ] `output_node(state)` — writes full state to JSONL log file

---

### 4.4 — Write and Lock the Reasoning Prompt

- [ ] Write the SOC analyst system prompt (see project_explained.md for template)
- [ ] Test prompt on 5 manually chosen alerts — confirm output looks reasonable
- [ ] Use `JsonOutputParser` or `response_format={"type": "json_object"}` — NEVER regex
- [ ] Lock the prompt text — changes to it after Phase 5 invalidate baseline

---

### 4.5 — Add Defense Hook Placeholders

- [ ] Add `pre_llm_filter_node` between `retrieve_context` and `reason` — passthrough for now
- [ ] Add `post_llm_check_node` between `reason` and `output` — passthrough for now
- [ ] Add `defense_active: bool` parameter to graph — when False, filters are skipped

---

### 4.6 — Build and Compile the Graph

- [ ] Wire all nodes in order with edges
- [ ] Set entry point, add END edge after output node
- [ ] Compile: `app = graph.compile()`
- [ ] Run on a single test alert — confirm end-to-end works

---

### 4.7 — Run Full Alert Set

- [ ] Loop over all alerts from `suspicious_queue.json`
- [ ] Invoke the compiled graph for each
- [ ] Collect results into DataFrame
- [ ] Write to `eval/baseline_results.csv`:
  ```
  alert_id | true_label | agent_severity | agent_action | justification | latency_ms | run_id
  ```
- [ ] Handle errors gracefully — log failed alerts, don't crash the run

---

### 4.8 — LLM Model Decision

- [ ] Evaluate if current model quality is sufficient (reasonable severity outputs)
- [ ] If not, upgrade to Claude Haiku or GPT-4o-mini
- [ ] Lock model name in `.env`
- [ ] Estimate cost per full pipeline run (fill in the API Cost Estimation table in this doc)
- [ ] Commit: `"feat: triage agent complete, baseline_results.csv produced"`

---

### ✅ Phase 4 Gate

- [ ] Pipeline runs on all 500+ alerts without crashes
- [ ] Every row in `baseline_results.csv` has valid `severity` and `action`
- [ ] LLM model name locked in `.env`
- [ ] Defense hook placeholders in graph
- [ ] Per-run logs in `logs/`
- [ ] API cost per run estimated

> **Phase 4 Completed Date:** ___________

---

---

## 🟢 Phase 5 — Baseline Evaluation

**⏱ Duration:** ~1 week | **📅 Target:** Week 9–10
**🎯 Goal:** Compute and lock all baseline metrics. Paper Table 1.
**📦 Deliverable:** `eval/metrics.py`, `eval/baseline_results.md`

---

### 5.1 — Create `eval/metrics.py`

- [ ] `severity_misclassification_rate(df)` — % alerts where AI severity ≠ expected severity
- [ ] `false_negative_rate(df)` — % high-severity alerts AI labeled as low/ignore
- [ ] `latency_stats(df)` — mean, p50, p95 of `latency_ms`
- [ ] `retrieval_relevance_score()` — average from spot-check ratings

---

### 5.2 — Run Metrics on Baseline

- [ ] Load `eval/baseline_results.csv`
- [ ] Run all four metric functions
- [ ] Write all results to `eval/baseline_results.md` (not just print)

---

### 5.3 — Write Paper Table 1 Draft

- [ ] Open paper draft, write Table 1 with exact numbers
- [ ] **LOCK THESE NUMBERS** — write the metric definitions into the paper right now
- [ ] Do NOT redefine or recompute after Phase 5 ends
- [ ] Commit: `"feat: baseline evaluation complete, metrics locked"`

---

### ✅ Phase 5 Gate

- [ ] All 4 metrics computed and in `eval/baseline_results.md`
- [ ] Paper Table 1 draft written
- [ ] Metric definitions fixed in `eval/metrics.py` — not to be changed

> **Phase 5 Completed Date:** ___________

---

---

## 🔴 Phase 6 — Attack Taxonomy Design (CRITICAL PATH)

**⏱ Duration:** ~2 weeks | **📅 Target:** Week 10–12
**🎯 Goal:** Formally define 4 attack categories. This is your main research contribution.
**📦 Deliverable:** `attacks/taxonomy.md`

---

### 6.1 — Attack Category 1: Direct Field Injection

- [ ] Write formal definition of the attack mechanism
- [ ] Write 5 payload variants (different phrasings)
- [ ] Define success metric precisely

---

### 6.2 — Attack Category 2: Retrieved-Document Poisoning

- [ ] Write formal definition (which docs, how poisoned, why it works)
- [ ] Write 5 poisoned document variants (instruction at different positions in text)
- [ ] Define success metric: AI must retrieve the document AND change decision

---

### 6.3 — Attack Category 3: Role-Confusion / Authority Spoofing

- [ ] Write formal definition
- [ ] Write 5 payload variants (SYSTEM:, ADMIN, ANALYST_LEAD, etc.)
- [ ] Define success metric

---

### 6.4 — Attack Category 4: Indirect Chained Injection

- [ ] Write formal definition
- [ ] Design Part A (notes_field) and Part B (incident report) mechanism
- [ ] Write 3 chain variants
- [ ] Design control condition (Part A only, no Part B) to prove chain is required
- [ ] Define success metric including control condition

---

### 6.5 — Compile Taxonomy Document

- [ ] Write `attacks/taxonomy.md` with all 4 categories
- [ ] Include summary table at the top

---

### 6.6 — Advisor Sign-Off

- [ ] Send taxonomy to guide/advisor
- [ ] Incorporate feedback
- [ ] **Phase 7 does NOT start until this sign-off is received**
- [ ] Commit: `"feat: attack taxonomy v1 complete, advisor reviewed"`

---

### ✅ Phase 6 Gate

- [ ] All 4 categories formally defined with 3–5 payloads and success metrics each
- [ ] `attacks/taxonomy.md` written and committed
- [ ] Advisor has reviewed and approved

> **Phase 6 Completed Date:** ___________

---

---

## 🟢 Phase 7 — Red-Team Execution

**⏱ Duration:** ~3 weeks | **📅 Target:** Week 12–15
**🎯 Goal:** Run all 4 attacks against the pipeline and compute ASR. Paper Table 2.
**📦 Deliverables:** `attacks/run_attacks.py`, `eval/attack_results.md`

---

### 7.1 — Build the Injector

- [ ] Implement `inject_direct(alert, payload)` — replaces `notes_field`
- [ ] Implement `inject_role_confusion(alert, payload)` — same mechanism
- [ ] Implement `inject_chained(alert, part_a)` — injects Part A into `notes_field`
- [ ] Implement `poison_knowledge_base(incident_id, poisoned_text)`:
  - [ ] Copy `data/chroma_clean/` → `data/chroma_poisoned/`
  - [ ] Update targeted document(s) in `incidents` collection
  - [ ] Re-embed and re-upsert
- [ ] Write attacked alert datasets to `data/alerts/attacked/`

---

### 7.2 — Run Category 1: Direct Field Injection

- [ ] Run pipeline on `direct_injection.json` (all 5 payload variants)
- [ ] Save to `eval/attack_cat1_results.csv`
- [ ] Compute ASR: flipped decisions / total attacked alerts

---

### 7.3 — Run Category 2: Document Poisoning

- [ ] Use `chroma_poisoned` knowledge base
- [ ] Identify which alerts retrieve the poisoned document (log these IDs)
- [ ] Run pipeline on those alerts
- [ ] Save to `eval/attack_cat2_results.csv`
- [ ] Compute ASR: only over alerts that retrieved the poisoned doc

---

### 7.4 — Run Category 3: Role Confusion

- [ ] Run pipeline on `role_confusion.json` (all 5 payload variants)
- [ ] Save to `eval/attack_cat3_results.csv`
- [ ] Compute ASR

---

### 7.5 — Run Category 4: Chained Injection

- [ ] Run with both Part A + Part B active
- [ ] Run control condition: Part A only (no Part B)
- [ ] Save to `eval/attack_cat4_results.csv`
- [ ] Verify control ASR ≈ 0% (chain mechanism validated)

---

### 7.6 — Qualitative Analysis

- [ ] Select 10–15 successful attacks across all categories
- [ ] Read LLM justification for each — document WHY the attack succeeded
- [ ] Write to `eval/qualitative_analysis.md` (becomes Discussion section)

---

### 7.7 — Compile Attack Results

- [ ] Write `eval/attack_results.md` — Paper Table 2
- [ ] Commit: `"feat: red-team execution complete, ASR computed"`

---

### ✅ Phase 7 Gate

- [ ] All 4 attack categories executed
- [ ] ASR computed for each with full before/after traces
- [ ] Qualitative analysis written
- [ ] `eval/attack_results.md` complete

> **Phase 7 Completed Date:** ___________

---

---

## 🟢 Phase 8 — Defense / Verification Layer

**⏱ Duration:** ~3 weeks | **📅 Target:** Week 15–18
**🎯 Goal:** Build two-layer defense and measure ASR reduction. Paper Table 3.
**📦 Deliverables:** `defense/filters.py`, `eval/defended_results.md`

---

### 8.1 — Filter 1: Input Sanitization (Regex Layer)

- [ ] Define comprehensive injection pattern list in `defense/filters.py`
- [ ] Implement `sanitize_text(text) -> (bool, str)` — returns (is_clean, reason)
- [ ] Apply to both `notes_field` of every alert AND every retrieved context chunk
- [ ] Test against all Phase 7 payloads — record catch rate

---

### 8.2 — Filter 1 Enhancement: Secondary LLM Classifier (Optional)

- [ ] Implement `llm_classify_injection(text) -> bool`
- [ ] Only call for texts that passed regex filter (saves cost)
- [ ] Measure catch rate improvement over regex-only

---

### 8.3 — Filter 2: Output Consistency Check

- [ ] Implement `check_output_consistency(alert, context, decision) -> (bool, str)`
- [ ] Use a cheap LLM call (smaller model is fine for this)
- [ ] Test on 10 known-successful attacks — does it flag them?
- [ ] Test on 20 clean baseline alerts — measure false positive rate

---

### 8.4 — Wire Filters Into LangGraph

- [ ] Fill in `pre_llm_filter_node` placeholder → calls `sanitize_text()`
- [ ] Fill in `post_llm_check_node` placeholder → calls `check_output_consistency()`
- [ ] If Filter 1 flags: skip LLM, mark decision as `flagged_pre_ingestion`
- [ ] If Filter 2 flags: mark as `flagged_post_output`, route for human review
- [ ] Confirm `defense_active=False` bypasses both filters (for baseline/attack conditions)

---

### 8.5 — Run Defended Pipeline

- [ ] Run with `defense_active=True` on all 4 attacked datasets
- [ ] Write to `eval/defended_results.csv`
- [ ] For each attack category compute:
  - [ ] Pre-filter catch rate
  - [ ] Post-filter catch rate
  - [ ] Combined defended ASR
  - [ ] ASR reduction %
  - [ ] False positive rate on clean alerts
  - [ ] Added latency vs. undefended

---

### 8.6 — Write Paper Table 3

- [ ] Write `eval/defended_results.md`
- [ ] Commit: `"feat: defense layer complete, defended_results.md produced"`

---

### ✅ Phase 8 Gate

- [ ] Both filters implemented and integrated into LangGraph
- [ ] Defended ASR computed for all 4 categories
- [ ] False positive rate on clean alerts measured
- [ ] Added latency measured
- [ ] `eval/defended_results.md` complete

> **Phase 8 Completed Date:** ___________

---

---

## 🟢 Phase 9 — Full Re-Evaluation

**⏱ Duration:** ~2 weeks | **📅 Target:** Week 18–20
**🎯 Goal:** All 3 conditions on the same fixed alert set. Clean, citable final numbers.
**📦 Deliverable:** `eval/final_results.md`

---

### 9.1 — Fix the Evaluation Alert Set

- [ ] Select 200–300 alerts from `clean_alerts.json` (balanced across attack types)
- [ ] Save as `data/alerts/eval_fixed_set.json` — never change this

---

### 9.2 — Run Condition A: Baseline

- [ ] `defense_active=False`, clean alerts, clean KB
- [ ] Save to `eval/final_baseline.csv`

---

### 9.3 — Run Condition B: Attacked (all 4 categories)

- [ ] Run each attack category on attacked versions of `eval_fixed_set.json`
- [ ] Save to `eval/final_attacked_cat{1-4}.csv`

---

### 9.4 — Run Condition C: Defended (all 4 categories)

- [ ] `defense_active=True` on all 4 attacked datasets
- [ ] Save to `eval/final_defended_cat{1-4}.csv`

---

### 9.5 — Compute Final Metrics and Sanity Check

- [ ] Run `eval/metrics.py` on all result files
- [ ] Build master comparison table
- [ ] Sanity check — direction of effects makes sense:
  - [ ] Attacked ASR > Baseline ASR
  - [ ] Defended ASR < Attacked ASR
  - [ ] FP rate on clean alerts < 10%
- [ ] If numbers don't make sense — **iterate here, not during writing**
- [ ] Write `eval/final_results.md`
- [ ] Commit: `"feat: final evaluation complete"`

---

### ✅ Phase 9 Gate

- [ ] All 3 conditions run on `eval_fixed_set.json` (same file, same hash)
- [ ] Results internally consistent
- [ ] `eval/final_results.md` complete with all tables

> **Phase 9 Completed Date:** ___________

---

---

## 🟢 Phase 10 — Paper Writing

**⏱ Duration:** ~4 weeks | **📅 Target:** Week 20–24
**🎯 Goal:** Full draft ready for advisor review.

---

### 10.1 — Venue Selection

- [ ] Choose target Scopus-indexed IEEE or Springer conference
- [ ] Note submission deadline
- [ ] Download venue paper template (LaTeX or Word)

---

### 10.2 — Write Non-Numbers Sections First (Week 20–21)

- [ ] System Architecture section (Phases 1–4, LangGraph diagram)
- [ ] Attack Taxonomy section (from `attacks/taxonomy.md`)
- [ ] Defense Design section (from `defense/filters.py` rationale)
- [ ] Experimental Setup section (dataset, models, metrics)

---

### 10.3 — Write Results Sections (Week 21–22)

- [ ] Results section — plug in Tables 1, 2, 3 from Phases 5, 7, 9
- [ ] Discussion section:
  - [ ] Why did certain attack categories have higher ASR?
  - [ ] Why did certain defenses work better/worse?
  - [ ] Limitations and threats to validity

---

### 10.4 — Write Framing Sections (Week 22–23)

- [ ] Abstract (refine using final numbers)
- [ ] Introduction (motivation, research question, paper contributions)
- [ ] Related Work (15–20 papers: RAG, prompt injection, SOC automation)
- [ ] Conclusion (summary + future work — mention remediation agent)

---

### 10.5 — Full Draft Review

- [ ] Compile all sections
- [ ] Self-review pass
- [ ] Send to advisor for feedback
- [ ] Incorporate feedback
- [ ] Commit: `"paper: first full draft complete"`

---

### ✅ Phase 10 Gate

- [ ] All 10 paper sections written
- [ ] Final numbers from Phase 9 in all tables
- [ ] Advisor has reviewed the full draft

> **Phase 10 Completed Date:** ___________

---

---

## 🟢 Phase 11 — Submission & Buffer

**⏱ Duration:** ~2 weeks | **📅 Target:** Week 24–26
**🎯 Goal:** Submitted paper.

---

### 11.1 — Final Formatting

- [ ] Format exactly to venue template
- [ ] Check figure/table numbering and captions
- [ ] Verify citation format matches venue style
- [ ] Check all figures are high-resolution

---

### 11.2 — Pre-Submission Checks

- [ ] Plagiarism check (iThenticate or similar) — similarity < 15% excluding references
- [ ] All authors listed with correct affiliations
- [ ] Abstract within word/character limit
- [ ] Paper within page limit

---

### 11.3 — Submit

- [ ] Create account on venue's submission system
- [ ] Upload PDF and fill metadata
- [ ] Confirm submission confirmation email
- [ ] Tag repo: `git tag v1.0-submission`
- [ ] Commit: `"chore: paper submitted to [venue name]"`

---

### 11.4 — Buffer Tasks

- [ ] Advisor revision rounds (if any)
- [ ] Rebuttal period (if venue has one)
- [ ] Catch-up on any phase that overran

---

### ✅ Phase 11 Gate — PROJECT COMPLETE 🎉

- [ ] Paper submitted to Scopus-indexed venue
- [ ] Submission confirmation saved
- [ ] Final repo state tagged and committed

> **Phase 11 Completed Date:** ___________

---

---

## 🔒 Running Rules (Non-Negotiable — Apply Every Phase)

| # | Rule | Why |
|---|---|---|
| 1 | **Lock metrics before seeing results** | Define attack success in Phase 6. Never redefine after seeing numbers. Research integrity. |
| 2 | **Log everything to file** | Every agent run writes to `logs/`. Never only print to console. |
| 3 | **Commit after every working session** | Guide can track progress; you have recovery points. |
| 4 | **Never commit `.env` or `data/raw/`** | API keys and large CSVs don't belong in GitHub. |
| 5 | **Use JSON mode for all LLM output** | Never regex-parse free text. Silent parse failures corrupt all evaluation data. |
| 6 | **Keep `chroma_clean` and `chroma_poisoned` separate** | Cross-contamination invalidates experimental conditions. |
| 7 | **Estimate API costs in Phase 4** | Multiply per-run cost × 6 before Phase 7. Budget weekly. |
| 8 | **Never skip Phase Gates** | Gates exist because each phase depends on the previous one being genuinely complete. |

---

## 💰 API Cost Estimation (Fill In During Phase 4)

| Parameter | Value |
|---|---|
| Avg input tokens per alert | _____ |
| Avg output tokens per alert | _____ |
| Price per 1M input tokens | $_____ |
| Price per 1M output tokens | $_____ |
| **Cost per alert** | $_____ |
| **Cost per full run (500 alerts)** | $_____ |
| Total conditions to run | × 6 |
| **Total estimated API cost** | $_____ |
| Weekly budget cap | $_____ |

---

## 📝 Change Log

> Record any significant plan deviations here.

| Date | Phase | Change Made | Reason |
|---|---|---|---|
| 2026-07-28 | All | Initial plan created | Project start |

---

## 🗓️ Week-by-Week Calendar

| Week | Phase | Focus |
|---|---|---|
| 1 | 0 | Setup: repo, env, data download, hello-world LLM |
| 2 | 1 | Explore CICIDS2017, design alert schema |
| 3 | 1–2 | Complete build_alerts.py, start detection_agent.py |
| 4 | 2–3 | Complete detection agent, start MITRE ATT&CK parsing |
| 5 | 3 | CVE subset + synthetic incidents, build ChromaDB index |
| 6 | 3–4 | Verify retrieval, start LangGraph learning |
| 7 | 4 | Build LangGraph triage agent nodes and graph |
| 8 | 4 | Run full alert set, fix bugs, evaluate output quality |
| 9 | 4–5 | Finalize LLM model, run baseline, start metrics |
| 10 | 5 | Lock all 4 baseline metrics, write paper Table 1 |
| 11 | 6 | Design attack categories 1 & 2, draft payloads |
| 12 | 6 | Design categories 3 & 4, compile taxonomy, advisor review |
| 13 | 7 | Build injector, run Category 1 & 2 attacks, compute ASR |
| 14 | 7 | Run Category 3 & 4 attacks, qualitative analysis |
| 15 | 7–8 | Compile attack results, start Filter 1 regex layer |
| 16 | 8 | Build Filter 2 consistency check, integrate into LangGraph |
| 17 | 8 | Run defended pipeline, measure ASR reduction |
| 18 | 8–9 | Write defended_results.md, fix the eval alert set |
| 19 | 9 | Run all 3 conditions on fixed set, sanity check numbers |
| 20 | 9–10 | Write final_results.md, start architecture & taxonomy paper sections |
| 21 | 10 | Write results & discussion sections |
| 22 | 10 | Write introduction, related work, abstract |
| 23 | 10 | Write conclusion, compile full draft |
| 24 | 10–11 | Advisor review, incorporate feedback |
| 25 | 11 | Final formatting, plagiarism check |
| 26 | 11 | Submit |

---

*Last updated: 2026-07-28*
*Project: Adversarial Robustness of Agentic RAG-Based SOC Triage Pipelines*
*File: IMPLEMENTATION_PLAN.md — commit this file after every session*
