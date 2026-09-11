from . import memory, trace
from .ai import tools as T
from .config import active_model
from .providers import get_provider
from .store import store


def _trace(record, steps, provider):
    try:
        trace.write(record, steps, provider.NAME, active_model())
    except Exception:
        pass


def triage(record):
    provider = get_provider()
    ok, reason = provider.available()
    if not ok:
        record.status = "error"
        record.error = reason
        return record

    record.status = "triaging"
    record.error = None
    alert = record.alert
    try:
        narrator, steps = provider.investigate(record)
    except Exception as e:
        record.status = "error"
        record.error = f"{type(e).__name__}: {e}"
        return record

    if not record.verdict:
        record.status = "error"
        record.error = record.error or "Triage finished without a verdict."
        _trace(record, steps, provider)
        return record

    record.status = "triaged"
    store.audit(
        "triaged",
        {"id": alert.id, "severity": record.verdict.severity,
         "confidence": record.verdict.confidence, "provider": provider.NAME},
    )
    try:
        memory.record_triage(record, narrator)
    except Exception as e:
        store.audit(
            "vault_error",
            {"id": alert.id, "stage": "triage", "error": f"{type(e).__name__}: {e}"},
        )
    _trace(record, steps, provider)
    return record


def remediate(record):
    v = record.verdict
    if not v or not v.proposed_action:
        record.error = "No proposed action to apply."
        return record
    record.status = "remediating"
    ok, output = T.apply_fix(v.proposed_action, record)
    record.remediation = {"command": v.proposed_action, "ok": ok, "output": output}
    record.status = "remediated" if ok else "error"
    if not ok:
        record.error = output
    store.audit(
        "remediation",
        {"id": record.alert.id, "command": v.proposed_action, "ok": ok},
    )
    try:
        memory.append_remediation(record)
    except Exception as e:
        store.audit(
            "vault_error",
            {"id": record.alert.id, "stage": "remediation",
             "error": f"{type(e).__name__}: {e}"},
        )
    return record
