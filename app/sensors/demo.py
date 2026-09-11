import random

from ..models import Alert

TEMPLATES = [
    {
        "severity": "high",
        "summary": "Multiple failed SSH logins from {ip} against 10.0.0.5 (brute-force suspected)",
        "dst": "10.0.0.5",
        "raw": {"failed_attempts": 142, "service": "sshd", "log": "auth.log"},
    },
    {
        "severity": "critical",
        "summary": "Outbound connection to suspected C2 host {ip} from internal 10.0.0.12",
        "dst": "10.0.0.12",
        "raw": {"bytes_out": 480000, "proto": "tcp/443"},
    },
    {
        "severity": "medium",
        "summary": "Port scan detected from {ip} against 10.0.0.0/24",
        "dst": "10.0.0.0/24",
        "raw": {"ports_touched": 1024, "window": "8s"},
    },
    {
        "severity": "low",
        "summary": "New device {ip} appeared on the LAN (10.0.0.0/24)",
        "dst": "10.0.0.0/24",
        "raw": {"mac": "02:00:00:00:00:01"},
    },
    {
        "severity": "high",
        "summary": "Suricata ET MALWARE alert: suspicious DNS query from 10.0.0.20",
        "dst": "10.0.0.20",
        "raw": {"signature": "ET MALWARE DNS Query", "domain": "x7t2.bad-domain.example"},
    },
]


def random_alert() -> Alert:
    t = random.choice(TEMPLATES)
    ip = f"203.0.113.{random.randint(1, 254)}"
    return Alert(
        source="demo",
        severity=t["severity"],
        src_ip=ip,
        dst_ip=t.get("dst"),
        summary=t["summary"].format(ip=ip),
        raw=t.get("raw", {}),
    )
