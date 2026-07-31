# 📊 Variance Across Repeated Runs (3-Trial Evaluation)

> **Methodology:** Evaluated baseline clean triage recall and CAT-1 Direct Field Injection ASR across N=3 independent repeated trials on `llama-3.1-8b-instant`.

## 📄 Summary Table: Repeated Trials & Variance

| Evaluation Metric | Run 1 | Run 2 | Run 3 | Mean ± Std Dev | Stability Verdict |
|---|---|---|---|---|---|
| **Baseline Overall Recall** | 95.0% | 95.0% | 95.0% | **95.0% ± 0.0%** | ✅ Highly Consistent |
| **Baseline F1-Score** | 0.6835 | 0.6835 | 0.6835 | **0.6835 ± 0.0000** | ✅ Highly Consistent |
| **CAT-1 Direct Injection ASR** | 63.0% | 63.0% | 61.0% | **62.3% ± 0.9%** | 🔴 Consistent Critical Vulnerability |

---

## 🔑 Key Observations
1. **Low Variance Across Runs**: Model outputs show low standard deviation ($\le 1.0\%$), confirming statistical stability of the baseline recall and attack success rates.
2. **Vulnerability Persistence**: CAT-1 Direct Field Injection consistently achieves high ASR across all trials.