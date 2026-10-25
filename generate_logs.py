"""
generate_logs.py
Creates a SAFE, fake login log (login_attempts.csv) and the answer key
(ground_truth.csv) so we can test the detector without attacking anything real.
"""
import csv
import random
from datetime import datetime, timedelta

random.seed(42)  # same data every run, so results are repeatable

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
START = datetime(2026, 10, 20, 0, 0, 0)
USERS = [f"user{i:03d}" for i in range(1, 201)]

events = []   # (time, ip, username, status)
truth = []    # (ip, attack_type, start_time)


def add(ts, ip, username, status):
    events.append((ts, ip, username, status))


# 1) Normal users: 150 people, each on their own IP, 1-4 logins a day.
#    About 7% make a typo first (401) and then succeed (200).
for i in range(150):
    ip = f"10.1.0.{i + 1}"
    user = USERS[i]
    for _ in range(random.randint(1, 4)):
        t = START + timedelta(seconds=random.randint(0, 86399))
        if random.random() < 0.07:
            add(t, ip, user, 401)
            t += timedelta(seconds=10)
        add(t, ip, user, 200)

# 2) Busy office behind ONE shared IP (tests false positives):
#    20 different staff log in within 5 minutes, 20% typo first.
office_base = START + timedelta(hours=9)
for user in random.sample(USERS, 20):
    t = office_base + timedelta(seconds=random.randint(0, 300))
    if random.random() < 0.2:
        add(t, "10.2.0.1", user, 401)
        add(t + timedelta(seconds=8), "10.2.0.1", user, 200)
    else:
        add(t, "10.2.0.1", user, 200)


def random_start():
    return START + timedelta(hours=random.randint(1, 20), minutes=random.randint(0, 59))


# 3) Brute-force attackers: 1 username, 60 guesses, one every 2 seconds.
for k in range(3):
    ip = f"203.0.113.{10 + k}"
    start = random_start()
    truth.append((ip, "BRUTE_FORCE", start))
    for n in range(60):
        status = 200 if (k == 0 and n == 59) else 401  # first attacker finally guesses right
        add(start + timedelta(seconds=2 * n), ip, "admin", status)

# 4) Credential-stuffing attackers: 80 different usernames, one every 3 seconds.
for k in range(3):
    ip = f"198.51.100.{10 + k}"
    start = random_start()
    truth.append((ip, "CREDENTIAL_STUFFING", start))
    for n, user in enumerate(random.sample(USERS, 80)):
        status = 200 if random.random() < 0.03 else 401
        add(start + timedelta(seconds=3 * n), ip, user, status)

# 5) Low-and-slow attackers: only 1 guess every 2 minutes (hard to catch).
for k in range(2):
    ip = f"192.0.2.{10 + k}"
    start = random_start()
    truth.append((ip, "LOW_AND_SLOW", start))
    for n in range(40):
        add(start + timedelta(seconds=120 * n), ip, "admin", 401)

events.sort(key=lambda e: e[0])

with open("login_attempts.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "ip", "username", "status"])
    for ts, ip, user, status in events:
        writer.writerow([ts.strftime(TIME_FORMAT), ip, user, status])

with open("ground_truth.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["ip", "attack_type", "start_time"])
    for ip, kind, start in truth:
        writer.writerow([ip, kind, start.strftime(TIME_FORMAT)])

print(f"Created login_attempts.csv with {len(events)} login events")
print(f"Created ground_truth.csv with {len(truth)} attacker IPs")