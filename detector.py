"""
detector.py
Reads a login log and detects:
  - BRUTE_FORCE            many failed logins from one IP
  - CREDENTIAL_STUFFING    one IP failing against many different usernames
  - SUCCESS_AFTER_FAILURES a successful login right after many failures (possible takeover)
Outputs: alerts.csv and blocklist.txt
"""
import argparse
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def load_events(path):
    events = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            events.append({
                "time": datetime.strptime(row["timestamp"], TIME_FORMAT),
                "ip": row["ip"],
                "username": row["username"],
                "status": int(row["status"]),
            })
    events.sort(key=lambda e: e["time"])
    return events


def detect(events, window_seconds, bf_threshold, cs_threshold, sa_threshold):
    window = timedelta(seconds=window_seconds)
    recent_failures = defaultdict(deque)  # ip -> failed attempts inside the window
    raised = set()                        # so we alert only once per ip/type
    alerts = []

    def raise_alert(event, alert_type, failures, users, key):
        if key in raised:
            return
        raised.add(key)
        alerts.append({
            "time": event["time"].strftime(TIME_FORMAT),
            "ip": event["ip"],
            "alert_type": alert_type,
            "failures_in_window": failures,
            "distinct_usernames": users,
            "username": event["username"] if alert_type == "SUCCESS_AFTER_FAILURES" else "",
        })

    for e in events:
        ip = e["ip"]
        queue = recent_failures[ip]

        # forget failures that are older than the time window
        while queue and e["time"] - queue[0]["time"] > window:
            queue.popleft()

        if e["status"] == 401:  # failed login
            queue.append(e)
            users = len({x["username"] for x in queue})
            if users >= cs_threshold:
                raise_alert(e, "CREDENTIAL_STUFFING", len(queue), users, (ip, "CS"))
            elif len(queue) >= bf_threshold:
                raise_alert(e, "BRUTE_FORCE", len(queue), users, (ip, "BF"))
        elif e["status"] == 200:
            # count only earlier failures against THIS SAME username
            same_user_failures = sum(1 for x in queue if x["username"] == e["username"])
            if same_user_failures >= sa_threshold:
                raise_alert(e, "SUCCESS_AFTER_FAILURES", same_user_failures, 1,
                            (ip, "SA", e["username"]))

    return alerts


def main():
    parser = argparse.ArgumentParser(description="Login attack detector")
    parser.add_argument("--log", default="login_attempts.csv", help="input log file")
    parser.add_argument("--window", type=int, default=300, help="time window in seconds")
    parser.add_argument("--bf", type=int, default=10, help="failures that mean brute force")
    parser.add_argument("--cs", type=int, default=8, help="distinct usernames that mean stuffing")
    parser.add_argument("--sa", type=int, default=5, help="failures before a success is suspicious")
    args = parser.parse_args()

    events = load_events(args.log)
    alerts = detect(events, args.window, args.bf, args.cs, args.sa)

    fields = ["time", "ip", "alert_type", "failures_in_window", "distinct_usernames", "username"]
    with open("alerts.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)

    blocklist = sorted({a["ip"] for a in alerts
                        if a["alert_type"] in ("BRUTE_FORCE", "CREDENTIAL_STUFFING")})
    with open("blocklist.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(blocklist) + ("\n" if blocklist else ""))

    print(f"Events analysed : {len(events)}")
    print(f"Alerts raised   : {len(alerts)}")
    print(f"IPs to block    : {len(blocklist)}")
    for a in alerts:
        print(f"  [{a['time']}] {a['alert_type']:<24} {a['ip']:<16} "
              f"failures={a['failures_in_window']} users={a['distinct_usernames']}")
    print("Saved alerts.csv and blocklist.txt")


if __name__ == "__main__":
    main()