import json, sys

sys.stdout.reconfigure(encoding="utf-8")

with open('data/alerts/triage_results.json', encoding='utf-8') as f:
    triage_results = json.load(f)

with open('data/alerts/eval_fixed_set.json', encoding='utf-8') as f:
    eval_alerts = json.load(f)

eval_map = {a['alert_id']: a for a in eval_alerts}

lines = []
lines.append('# 📄 Baseline LLM + RAG Triage Log (All 200 Evaluation Set Alerts)')
lines.append('')
lines.append('> **Description:** Complete record of AI triage decisions across all 200 benchmark alerts.')
lines.append('> Includes Alert ID, Ground Truth Label, AI Classified Verdict, AI Severity, AI Confidence, Reasoning, and RAG Sources.')
lines.append('')
lines.append('---')
lines.append('')
lines.append('| # | Alert ID | Ground Truth | AI Verdict | Severity | Conf | AI Reasoning Summary | RAG Document Used |')
lines.append('|---|---|---|---|---|---|---|---|')

for i, res in enumerate(triage_results, 1):
    aid = res['alert_id']
    orig = eval_map.get(aid, {})
    gt = orig.get('attack_type', 'unknown').upper()
    verdict = res['verdict']
    sev = res['severity'].upper()
    conf = f"{res['confidence']:.2f}"
    reason = res['reasoning'].replace('\n', ' ').replace('|', '-')
    if len(reason) > 120:
        reason = reason[:120] + "..."
    docs = ', '.join([d['doc_id'] for d in res.get('retrieved_docs', [])]) or 'None'
    
    match_str = '✅' if ((gt != 'BENIGN' and verdict == 'SUSPICIOUS') or (gt == 'BENIGN' and verdict == 'BENIGN')) else '⚠️'
    lines.append(f'| {i} | `{aid}` | {gt} | {match_str} {verdict} | {sev} | {conf} | {reason} | `{docs}` |')

with open('eval/baseline_200_triage_log.md', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))

print(f'Generated eval/baseline_200_triage_log.md with {len(triage_results)} records!')
