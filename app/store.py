import json
import threading
import time

from .config import ROOT
from .models import Alert, AlertRecord

AUDIT = ROOT / "data" / "audit.jsonl"
APPLIED = ROOT / "data" / "applied.jsonl"


class Store:
    def __init__(self):
        self._records = {}
        self._lock = threading.Lock()
        AUDIT.parent.mkdir(exist_ok=True)
        self._applied = self._load_applied()

    def add_alert(self, alert: Alert) -> AlertRecord:
        rec = AlertRecord(alert=alert)
        with self._lock:
            self._records[alert.id] = rec
        self.audit("alert_received", {"id": alert.id, "summary": alert.summary})
        return rec

    def get(self, alert_id: str):
        return self._records.get(alert_id)

    def all(self):
        return sorted(
            self._records.values(), key=lambda r: r.alert.ts, reverse=True
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
