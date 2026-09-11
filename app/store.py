import json
import threading
import time

from .config import ROOT
from .models import Alert, AlertRecord

AUDIT = ROOT / "data" / "audit.jsonl"


class Store:
    def __init__(self):
        self._records = {}
        self._lock = threading.Lock()
        AUDIT.parent.mkdir(exist_ok=True)

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

    def audit(self, event: str, data: dict):
        line = json.dumps({"ts": time.time(), "event": event, **data})
        with self._lock:
            with open(AUDIT, "a", encoding="utf-8") as f:
                f.write(line + "\n")


store = Store()
