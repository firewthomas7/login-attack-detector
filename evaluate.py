"""
evaluate.py
Compares the detector's results (alerts.csv) with the answer key (ground_truth.csv)
and prints precision, recall and detection delay.
"""
import csv
from datetime import datetime

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
BLOCK_TYPES = ("BRUTE_FORCE", "CREDENTIAL_STUFFING")

with open("ground_truth.csv", newline="", encoding="utf-8") as f:
    truth = {row["ip"]: row for row in csv.DictReader(f)}

flagged = {}  # ip -> first alert time
with open("alerts.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if row["alert_type"] in BLOCK_TYPES and row["ip"] not in flagged:
            flagged[row["ip"]] = datetime.strptime(row["time"], TIME_FORMAT)

true_pos = set(flagged) & set(truth)
false_pos = set(flagged) - set(truth)
false_neg = set(truth) - set(flagged)

precision = len(true_pos) / len(flagged) if flagged else 0.0
recall = len(true_pos) / len(truth) if truth else 0.0

delays = []
for ip in true_pos:
    start = datetime.strptime(truth[ip]["start_time"], TIME_FORMAT)
    delays.append((flagged[ip] - start).total_seconds())

print("===== EVALUATION RESULTS =====")
print(f"Real attacker IPs         : {len(truth)}")
print(f"Detected (true positives) : {len(true_pos)}")
print(f"Missed (false negatives)  : {len(false_neg)}  {sorted(false_neg)}")
print(f"Wrongly flagged (false +) : {len(false_pos)}  {sorted(false_pos)}")
print(f"Precision                 : {precision:.0%}")
print(f"Recall                    : {recall:.0%}")
if delays:
    print(f"Average detection delay   : {sum(delays) / len(delays):.1f} seconds after attack began")

print("\nRecall by attack type:")
for kind in sorted({r["attack_type"] for r in truth.values()}):
    ips = [ip for ip, r in truth.items() if r["attack_type"] == kind]
    caught = [ip for ip in ips if ip in flagged]
    print(f"  {kind:<20} {len(caught)}/{len(ips)} detected")