import argparse
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import threading
import time

from app import engine
from app.models import Alert
from app.sensors.demo import random_alert
from app.store import store

PRESETS = {
    "bruteforce": dict(
        summary="SSH brute-force: 300 failed logins in 2 minutes",
        dst_ip="127.0.0.1", src_ip="203.0.113.10", severity="high",
    ),
    "portscan": dict(
        summary="Horizontal port-scan sweep across the subnet",
        dst_ip="127.0.0.1", src_ip="198.51.100.23", severity="medium",
    ),
    "c2": dict(
        summary="Outbound beacon to suspected C2 host every 60s",
        dst_ip="127.0.0.1", src_ip="203.0.113.77", severity="high",
    ),
    # --- legit / benign traffic, to see behavior on non-threats ---
    "dns": dict(
        summary="Routine DNS lookup for mirror.example.com from an internal workstation",
        dst_ip="127.0.0.1", src_ip="10.0.0.50", severity="info",
    ),
    "webtraffic": dict(
        summary="Outbound HTTPS (443) to api.example.com from a CI runner",
        dst_ip="127.0.0.1", src_ip="10.0.0.50", severity="low",
    ),
    "update": dict(
        summary="Scheduled apt package update pulling from mirror.example.com",
        dst_ip="127.0.0.1", src_ip="10.0.0.50", severity="info",
    ),
}
MALICIOUS = ("bruteforce", "portscan", "c2")
LEGIT = ("dns", "webtraffic", "update")


def build(name):
    if not name:
        return random_alert()
    if name not in PRESETS:
        print(f"unknown preset '{name}'. options: {', '.join(PRESETS)} (or omit for random)")
        sys.exit(1)
    return Alert(**PRESETS[name])


def run_one(alert):
    rec = store.add_alert(alert)
    print(f"\n=== ALERT {alert.id} ===")
    print(f"  {alert.severity.upper()}  {alert.summary}")
    print(f"  src {alert.src_ip}  ->  dst {alert.dst_ip}")
    print("--- triage (live) ---")

    t = threading.Thread(target=engine.triage, args=(rec,))
    t.start()
    seen = 0
    while t.is_alive() or seen < len(rec.recon_log):
        while seen < len(rec.recon_log):
            print(f"  . {rec.recon_log[seen]}")
            seen += 1
        time.sleep(0.25)
    t.join()

    if rec.status == "error":
        print(f"\n  ERROR: {rec.error}")
        return

    v = rec.verdict
    print("\n--- verdict ---")
    print(f"  category    {v.category}")
    print(f"  disposition {v.disposition}")
    print(f"  severity    {v.severity}   confidence {v.confidence}")
    print(f"  root cause  {v.root_cause}")
    print(f"  fix         {v.suggested_fix}")
    print(f"  action      {v.proposed_action}")
    print(f"\n  report -> {rec.report_path}")
    if rec.report_path:
        print("\n--- saved note ---")
        try:
            print(open(rec.report_path, encoding="utf-8").read())
        except OSError as e:
            print(f"  (couldn't read note: {e})")


def main():
    ap = argparse.ArgumentParser(description="Inject an alert and watch SentinelAgent triage it.")
    ap.add_argument(
        "preset", nargs="?",
        help="malicious: bruteforce|portscan|c2  legit: dns|webtraffic|update  "
             "(omit for a random demo alert)",
    )
    ap.add_argument("--repeat", type=int, default=1, help="fire the same alert N times to watch dedup")
    args = ap.parse_args()
    for i in range(args.repeat):
        if args.repeat > 1:
            print(f"\n########## run {i + 1}/{args.repeat} ##########")
        run_one(build(args.preset))


if __name__ == "__main__":
    main()
