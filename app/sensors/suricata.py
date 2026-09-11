import json
import time
from datetime import datetime
from pathlib import Path

from ..config import ROOT, suricata_eve_path
from ..models import Alert
from ..store import store

# Suricata alert.severity: 1 = most severe. Map to our scale.
_SEV = {1: "high", 2: "medium", 3: "low"}
_OFFSET_FILE = ROOT / "data" / "suricata.offset"


def _ts(value):
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, TypeError):
        return time.time()


def normalize(event):
    """Map one Suricata eve.json event to an Alert. Returns None for non-alert
    events (dns/http/flow/stats/...). The full event is kept in `raw`."""
    if not isinstance(event, dict) or event.get("event_type") != "alert":
        return None
    a = event.get("alert") or {}
    sig = a.get("signature") or "Suricata alert"
    category = a.get("category")
    summary = sig + (f" [{category}]" if category else "")
    return Alert(
        source="suricata",
        ts=_ts(event.get("timestamp")),
        severity=_SEV.get(a.get("severity"), "info"),
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dest_ip"),
        summary=summary,
        raw=event,
    )


def parse_line(line):
    line = line.strip()
    if not line:
        return None
    try:
        return normalize(json.loads(line))
    except ValueError:
        return None


def read_new(path, offset=0):
    """Read new eve.json alerts from a byte offset. Returns (alerts, new_offset).
    Only complete (newline-terminated) lines are consumed — a partial trailing line
    being written is left for the next poll. Byte offsets survive restarts."""
    p = Path(path)
    if not p.exists():
        return [], offset
    with open(p, "rb") as f:
        f.seek(offset)
        data = f.read()
    nl = data.rfind(b"\n")
    if nl == -1:
        return [], offset
    complete = data[: nl + 1]
    alerts = []
    for raw in complete.split(b"\n"):
        if raw.strip():
            alert = parse_line(raw.decode("utf-8", errors="replace"))
            if alert:
                alerts.append(alert)
    return alerts, offset + len(complete)


def _load_offset():
    try:
        return int(_OFFSET_FILE.read_text())
    except (OSError, ValueError):
        return 0


def _save_offset(n):
    try:
        _OFFSET_FILE.parent.mkdir(exist_ok=True)
        _OFFSET_FILE.write_text(str(n))
    except OSError:
        pass


def watch(interval=3.0, stop=None):
    """Poll the configured eve.json and push new Suricata alerts into the dashboard
    queue. Resumes from a persisted offset so a restart doesn't reprocess. Triage
    stays manual (analyst clicks) — this only ingests, matching the demo feed."""
    path = suricata_eve_path()
    if not path:
        return
    offset = _load_offset()
    while not (stop and stop.is_set()):
        alerts, offset = read_new(path, offset)
        for alert in alerts:
            store.add_alert(alert)
        if alerts:
            _save_offset(offset)
        time.sleep(interval)
