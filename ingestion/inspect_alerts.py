import json, sys
sys.path.insert(0, '.')

with open('data/alerts/clean_alerts.json') as f:
    data = json.load(f)

seen = set()
for a in data:
    t = a['attack_type']
    if t != 'benign' and t not in seen:
        seen.add(t)
        print("=== " + t.upper() + " ===")
        keys = ['src_ip','dst_ip','dst_port','fwd_packets','bwd_packets',
                'flow_bytes_per_sec','packet_length_mean','flow_duration_us',
                'total_bytes','syn_flag_count','rst_flag_count']
        for k in keys:
            print("  " + k + " = " + str(a.get(k,'')))
        print()
