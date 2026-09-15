import json
import threading
import time

from .config import ROOT, dedup_window_seconds
from .models import Alert, AlertRecord

AUDIT = ROOT / "data" / "audit.jsonl"
APPLIED = ROOT / "data" / "applied.jsonl"


def _fingerprint(alert: Alert):
    """What makes two alerts the same event. Signature and endpoints — not the id,
    not the timestamp, not the packet."""
    return (alert.source, alert.summary, alert.src_ip, alert.dst_ip)


class Store:
    def __init__(self):
        self._records = {}
        self._by_fp = {}
        self._lock = threading.Lock()
        AUDIT.parent.mkdir(exist_ok=True)
        self._applied = self._load_applied()

    def add_alert(self, alert: Alert) -> AlertRecord:
        """A repeat of something already in the queue bumps the count on the existing
        record instead of adding a row. One nmap scan is thousands of eve.json events
        and one thing an analyst needs to look at."""
        fp = _fingerprint(alert)
        window = dedup_window_seconds()
        with self._lock:
            existing = self._records.get(self._by_fp.get(fp))
            if existing and window > 0 and alert.ts - existing.last_ts <= window:
                existing.count += 1
                existing.last_ts = alert.ts
                return existing
            rec = AlertRecord(alert=alert, last_ts=alert.ts)
            self._records[alert.id] = rec
            self._by_fp[fp] = alert.id
        self.audit("alert_received", {"id": alert.id, "summary": alert.summary})
        return rec

    def get(self, alert_id: str):
        return self._records.get(alert_id)

    def remove(self, alert_id: str) -> bool:
        """Drop an alert from the live board. The record stays in the append-only audit
        log and, if it was triaged, in the memory vault — dismissing clears the queue,
        it does not erase history."""
        with self._lock:
            rec = self._records.pop(alert_id, None)
            if rec is None:
                return False
            fp = _fingerprint(rec.alert)
            if self._by_fp.get(fp) == alert_id:
                del self._by_fp[fp]
        self.audit("alert_dismissed", {"id": alert_id})
        return True

    def clear(self) -> int:
        with self._lock:
            n = len(self._records)
            self._records.clear()
            self._by_fp.clear()
        self.audit("alerts_cleared", {"count": n})
        return n

    def all(self):
        return sorted(
            self._records.values(), key=lambda r: r.last_ts, reverse=True
        )

    @staticmethod
    def _load_applied():
        """Survives restart on purpose: a crash between applying a ban and recording it
        must not let the same command fire again on the next boot."""
        if not APPLIED.exists():
            return set()
        out = set()
        for line in APPLIED.read_text(encoding="utf-8").splitlines():
            try:
                out.add(json.loads(line)["command"])
            except (ValueError, KeyError):
                continue
        return out

    def was_applied(self, command: str) -> bool:
        return " ".join(command.split()) in self._applied

    def mark_applied(self, command: str, alert_id: str):
        command = " ".join(command.split())
        with self._lock:
            self._applied.add(command)
            with open(APPLIED, "a", encoding="utf-8") as f:
                rec = {"ts": time.time(), "command": command, "id": alert_id}
                f.write(json.dumps(rec) + "\n")

    def audit(self, event: str, data: dict):
        line = json.dumps({"ts": time.time(), "event": event, **data})
        with self._lock:
            with open(AUDIT, "a", encoding="utf-8") as f:
                f.write(line + "\n")


store = Store()
