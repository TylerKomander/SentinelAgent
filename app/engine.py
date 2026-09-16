from . import memory, trace
from .ai import tools as T
from .config import active_model
from .providers import get_provider
from .store import store


def _verify_action_target(record):
    """An action is only justified against an IP the agent actually observed in tool
    output. The alert's own fields do not count as evidence — a synthetic or spoofed
    alert would otherwise nominate its own target. Sets verdict.action_verified."""
    v = record.verdict
    if not v or not v.proposed_action:
        return
    targets = T.IP_RE.findall(v.proposed_action)
    unseen = [ip for ip in targets if ip not in record.observed_ips]
    v.action_verified = not unseen
    if unseen:
        record.recon_log.append(
            f"[unverified] proposed action targets {', '.join(unseen)} — never seen in "
            "any tool output. Manual apply only."
        )
        store.audit(
            "action_unverified",
            {"id": record.alert.id, "command": v.proposed_action,
             "unseen": unseen, "observed": record.observed_ips},
        )


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

    _verify_action_target(record)
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


def remediate(record, mode="manual"):
    v = record.verdict
    if not v or not v.proposed_action:
        record.error = "No proposed action to apply."
        return record
    if store.was_applied(v.proposed_action):
        record.remediation = {
            "command": v.proposed_action, "ok": True, "mode": mode,
            "output": "(already applied — skipped, no change made)",
        }
        record.status = "remediated"
        store.audit(
            "remediation_skipped",
            {"id": record.alert.id, "command": v.proposed_action, "reason": "idempotent"},
        )
        return record
    record.status = "remediating"
    ok, output = T.apply_fix(v.proposed_action, record)
    record.remediation = {
        "command": v.proposed_action, "ok": ok, "output": output, "mode": mode,
    }
    if ok:
        store.mark_applied(v.proposed_action, record.alert.id)
    record.status = "remediated" if ok else "error"
    if not ok:
        record.error = output
    store.audit(
        "remediation",
        {"id": record.alert.id, "command": v.proposed_action, "ok": ok, "mode": mode},
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
