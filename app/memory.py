import os
import re
import threading
from datetime import datetime, timezone

from .config import vault_dir
from .store import store

_LOCK = threading.Lock()

SEV = ["info", "low", "medium", "high", "critical"]

SECTIONS = [
    ("Summary", "summary"),
    ("What I found", "what_i_found"),
    ("How I found it", "how_i_found_it"),
    ("Where / affected hosts", "where"),
    ("How it happened (root cause)", "how_it_happened"),
    ("How I resolved it", "how_i_resolved_it"),
    ("Trip-ups & problems", "trip_ups"),
]

def _in_scope(ip):
    from .ai.tools import in_scope
    return in_scope(ip)


def _slug(s):
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return s or "unknown"


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _max_sev(a, b):
    ra = SEV.index(a) if a in SEV else 0
    rb = SEV.index(b) if b in SEV else 0
    return a if ra >= rb else b


def ensure_vault():
    base = vault_dir()
    for sub in ("Incidents", "Hosts", "Patterns"):
        (base / sub).mkdir(parents=True, exist_ok=True)
    return base


def _safe_in_vault(rel):
    base = vault_dir().resolve()
    p = (base / rel).resolve()
    if base != p and base not in p.parents:
        raise ValueError("path escapes vault")
    return p


def _atomic_write(path, text):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _host_info(alert):
    hosts = [ip for ip in (alert.dst_ip, alert.src_ip) if ip and _in_scope(ip)]
    primary = hosts[0] if hosts else "global"
    src_ips = [alert.src_ip] if alert.src_ip and not _in_scope(alert.src_ip) else []
    return hosts, _slug(primary), src_ips


def _incident_path(cat, host_slug):
    return vault_dir() / "Incidents" / f"{cat}-{host_slug}.md"


def _parse_fm(text):
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    fm = {}
    for line in parts[1].strip().splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip(), v.strip()
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            fm[k] = [x.strip() for x in inner.split(",")] if inner else []
        else:
            fm[k] = v
    return fm, parts[2].lstrip("\n")


def _dump_fm(fm):
    lines = ["---"]
    for k, v in fm.items():
        if isinstance(v, list):
            lines.append(f"{k}: [{', '.join(v)}]")
        else:
            lines.append(f"{k}: {v}")
    lines.append("---")
    return "\n".join(lines) + "\n"


def _retag(tags, sev, disp, cat):
    base = [t for t in tags if not t.startswith("sev/") and not t.startswith("disp/")]
    for t in ("sentinel", "incident", cat):
        if t and t not in base:
            base.append(t)
    return base + [f"sev/{sev}", f"disp/{disp}"]


def upsert_stub(folder, name, title):
    p = vault_dir() / folder / f"{name}.md"
    if p.exists():
        return
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        f"# {title}\n\nIndex note. Incidents referencing this appear in backlinks.\n",
        encoding="utf-8",
    )


def _occurrence(record):
    a = record.alert
    v = record.verdict
    verdict = ""
    if v:
        cause = " ".join((v.root_cause or "").split())[:120]
        verdict = f" — verdict {v.disposition}/{v.severity}" + (f" — {cause}" if cause else "")
    return f"- {_iso(a.ts)} — alert `{a.id}`{verdict or ' — ' + a.summary}"


def _fallback_sections(record):
    v = record.verdict
    a = record.alert
    return {
        "summary": (v.suggested_fix or a.summary or "").strip() or "(no summary)",
        "what_i_found": v.root_cause,
        "how_i_found_it": "\n".join(f"- {e}" for e in record.recon_log)
        or "(no recon performed)",
        "where": ", ".join(filter(None, [a.dst_ip, a.src_ip])) or "(unknown)",
        "how_it_happened": v.root_cause,
        "how_i_resolved_it": v.proposed_action or v.suggested_fix,
        "trip_ups": "_(auto-generated fallback — report-writer call unavailable)_",
    }


def _new_note(record, fp, cat, host_slug, hosts, src_ips, sections):
    v = record.verdict
    a = record.alert
    iso = _iso(a.ts)
    fm = {
        "fingerprint": fp,
        "category": cat,
        "disposition": v.disposition,
        "severity": v.severity,
        "confidence": v.confidence,
        "hosts": hosts,
        "src_ips": src_ips,
        "first_seen": iso,
        "last_seen": iso,
        "occurrences": "1",
        "outcome": "triaged",
        "tags": _retag([], v.severity, v.disposition, cat),
    }
    body = [f"> Related: [[{host_slug}]] · [[{cat}]]", ""]
    for title, key in SECTIONS:
        body += [f"## {title}", "", (sections.get(key) or "").strip() or "_(none)_", ""]
    recon = "\n".join(f"- {e}" for e in record.recon_log) or "_(no recon performed)_"
    body += ["## Recon log", "", recon, ""]
    body += ["## Remediation", "", "_(not yet applied)_", ""]
    body += ["## Occurrences", "", _occurrence(record)]
    return _dump_fm(fm) + "\n" + "\n".join(body) + "\n"


def _update_note(path, record, escalate=True):
    fm, body = _parse_fm(path.read_text(encoding="utf-8"))
    v = record.verdict
    a = record.alert
    fm["occurrences"] = str(int(fm.get("occurrences", "1") or "1") + 1)
    fm["last_seen"] = _iso(a.ts)
    if escalate and v:
        fm["severity"] = _max_sev(fm.get("severity", "info"), v.severity)
        if v.disposition == "actionable":
            fm["disposition"] = "actionable"
    if a.src_ip and not _in_scope(a.src_ip):
        s = fm.get("src_ips") or []
        if a.src_ip not in s:
            s.append(a.src_ip)
            fm["src_ips"] = s
    fm["tags"] = _retag(
        fm.get("tags", []),
        fm.get("severity", "info"),
        fm.get("disposition", "actionable"),
        fm.get("category", ""),
    )
    body = body.rstrip() + "\n" + _occurrence(record) + "\n"
    _atomic_write(path, _dump_fm(fm) + "\n" + body)


def record_triage(record, narrator=None):
    """narrator: optional zero-arg callable returning the report sections dict
    (provider-specific). Only invoked when a NEW fingerprint note is created;
    repeats dedup with no narration call. Falls back to structured sections on
    failure so a note is always written."""
    ensure_vault()
    v = record.verdict
    a = record.alert
    cat = _slug(v.category)
    hosts, host_slug, src_ips = _host_info(a)
    fp = f"{cat}__{host_slug}"
    path = _incident_path(cat, host_slug)

    if path.exists():
        with _LOCK:
            _update_note(path, record)
    else:
        sections = None
        if narrator:
            try:
                sections = narrator()
            except Exception as e:
                store.audit(
                    "report_writer_failed",
                    {"id": a.id, "error": f"{type(e).__name__}: {e}"},
                )
        if not sections:
            sections = _fallback_sections(record)
        with _LOCK:
            if path.exists():
                _update_note(path, record)
            else:
                _atomic_write(
                    path,
                    _new_note(record, fp, cat, host_slug, hosts, src_ips, sections),
                )
    with _LOCK:
        for h in hosts:
            upsert_stub("Hosts", _slug(h), h)
        upsert_stub("Patterns", cat, v.category)
    record.report_path = str(path)
    return path


def _replace_section(body, name, new_block):
    pat = re.compile(rf"## {re.escape(name)}\n.*?(?=\n## |\Z)", re.S)
    if pat.search(body):
        return pat.sub(new_block.rstrip(), body, count=1)
    if "## Occurrences" in body:
        return body.replace(
            "## Occurrences", new_block.rstrip() + "\n\n## Occurrences", 1
        )
    return body.rstrip() + "\n\n" + new_block


def append_remediation(record):
    ensure_vault()
    v = record.verdict
    a = record.alert
    if not v:
        return
    cat = _slug(v.category)
    hosts, host_slug, src_ips = _host_info(a)
    path = _incident_path(cat, host_slug)
    rem = record.remediation or {}
    ok = rem.get("ok")
    cmd = rem.get("command", "")
    out = (rem.get("output") or "")[:3000] or "(no output)"
    iso = _iso(a.ts)
    block = (
        "## Remediation\n\n"
        f"- command: `{cmd}`\n"
        f"- result: {'success' if ok else 'failed'}\n"
        f"- applied: {iso}\n\n"
        f"```\n{out}\n```\n"
    )
    with _LOCK:
        if not path.exists():
            fp = f"{cat}__{host_slug}"
            _atomic_write(
                path,
                _new_note(
                    record, fp, cat, host_slug, hosts, src_ips,
                    _fallback_sections(record),
                ),
            )
        fm, body = _parse_fm(path.read_text(encoding="utf-8"))
        fm["outcome"] = "remediated" if ok else "failed"
        body = _replace_section(body, "Remediation", block)
        body = body.rstrip() + "\n" + (
            f"- {iso} — remediation {'applied' if ok else 'failed'}: `{cmd}`"
        ) + "\n"
        _atomic_write(path, _dump_fm(fm) + "\n" + body)


def search_memory(query, limit=10):
    ensure_vault()
    # Tokenize: keep IPs (dots) and slugs (hyphens) whole; match ANY term, rank by
    # how many distinct terms a note hits. Whole-phrase matching misses everything.
    terms = [t for t in re.split(r"[^a-z0-9.\-]+", (query or "").lower()) if len(t) >= 3]
    if not terms:
        return "(empty query)"
    scored = []
    for p in sorted(vault_dir().rglob("*.md")):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = text.lower()
        hits = {t for t in terms if t in low}
        if not hits:
            continue
        rel = p.relative_to(vault_dir()).as_posix()
        lines = [
            l.strip() for l in text.splitlines() if any(t in l.lower() for t in hits)
        ][:4]
        scored.append((len(hits), rel, lines))
    if not scored:
        return f"(no notes matching: {', '.join(terms)})"
    scored.sort(key=lambda x: -x[0])
    return "\n\n".join(f"### {rel}\n" + "\n".join(lines) for _, rel, lines in scored[:limit])


def recall(alert):
    """Deterministic memory lookup run by the app before triage — does not depend
    on the model choosing to call search_memory. Returns a prior-context block, or
    "" if nothing relevant. Searches the alert's hosts + summary in one ranked pass."""
    q = " ".join(str(x) for x in (alert.dst_ip, alert.src_ip, alert.summary) if x)
    res = search_memory(q, limit=5)
    return "" if res.startswith("(") else res


def read_note(rel):
    try:
        p = _safe_in_vault(rel)
    except ValueError:
        return "BLOCKED: path escapes the vault.", True
    if not p.exists() or p.suffix != ".md":
        return f"(no note at {rel})", False
    return p.read_text(encoding="utf-8", errors="replace")[:8000], False
