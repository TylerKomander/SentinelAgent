import json

from .config import ROOT

_DIR = ROOT / "data" / "traces"


def write(record, steps, provider, model):
    """Dump a full per-triage trace: the prompt (incl. recalled memory), every model
    turn (reasoning text + tool calls), every tool result, and the verdict. One JSON
    file per alert under data/traces/ — readable from a shared folder for observability."""
    try:
        _DIR.mkdir(parents=True, exist_ok=True)
        v = record.verdict
        doc = {
            "alert_id": record.alert.id,
            "ts": record.alert.ts,
            "provider": provider,
            "model": model,
            "status": record.status,
            "error": record.error,
            "alert": record.alert.model_dump(),
            "recon_log": record.recon_log,
            "verdict": v.model_dump() if v else None,
            "report_path": record.report_path,
            "steps": steps,
        }
        path = _DIR / f"{record.alert.id}.json"
        path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
        return path
    except OSError:
        return None
