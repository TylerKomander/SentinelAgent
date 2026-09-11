import ipaddress
import re
import shutil
import socket
import subprocess

from .. import memory
from ..config import ROOT, scope_allowlist
from ..store import store

LOGS_DIR = ROOT / "data" / "logs"

DENY = [
    "rm -rf", "mkfs", "dd if=", ":(){", "shutdown", "reboot",
    "> /dev/sd", "format ", "del /", "deltree",
]

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def in_scope(target: str) -> bool:
    if not target:
        return False
    allow = scope_allowlist()
    if not allow:
        return False
    if target in allow:
        return True
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    for entry in allow:
        try:
            allowed = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if net == allowed or net.subnet_of(allowed):
            return True
    return False


def _run(cmd, timeout=120):
    exe = cmd[0]
    if shutil.which(exe) is None:
        return (
            f"(tool '{exe}' is not installed on this host — install it in the "
            f"Kali/Linux environment to enable this recon. Skipping.)"
        )
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        return out[:6000] or "(no output)"
    except subprocess.TimeoutExpired:
        return f"(command timed out after {timeout}s)"


def _log(record, entry):
    record.recon_log.append(entry)


TRIAGE_TOOLS = [
    {
        "name": "port_scan",
        "description": "Run an nmap service scan (nmap -sV -Pn) against a single "
        "in-scope host to see open ports and running services.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "IP or hostname"}},
            "required": ["target"],
        },
    },
    {
        "name": "ping_sweep",
        "description": "Run an nmap ping sweep (nmap -sn) over an in-scope CIDR to "
        "list which hosts are live.",
        "input_schema": {
            "type": "object",
            "properties": {"cidr": {"type": "string", "description": "e.g. 10.0.0.0/24"}},
            "required": ["cidr"],
        },
    },
    {
        "name": "dns_lookup",
        "description": "Resolve a hostname to an IP, or reverse-resolve an IP to a "
        "hostname. Read-only; no scope restriction.",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}},
            "required": ["host"],
        },
    },
    {
        "name": "whois_lookup",
        "description": "Run whois on a domain or IP for ownership/registration info.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "read_log",
        "description": "Read a log file from the local logs directory by filename "
        "(no paths). Optionally filter to lines containing a substring.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "contains": {"type": "string"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "search_memory",
        "description": "Search the operator's incident memory vault for prior related "
        "cases. Use this BEFORE active recon: query the destination host, source IP, "
        "and likely category. Returns matching note paths + snippets.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "read_note",
        "description": "Read a full note from the memory vault by its relative path "
        "(e.g. 'Incidents/ssh-bruteforce-10-0-0-5.md') as returned by search_memory.",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "submit_verdict",
        "description": "Submit your final triage verdict. Call exactly once.",
        "input_schema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                },
                "category": {
                    "type": "string",
                    "description": "Short stable lowercase slug for the incident type, "
                    "e.g. 'ssh-bruteforce', 'port-scan', 'c2-beacon'. Reuse the exact "
                    "category of a matching prior incident if one exists in memory.",
                },
                "disposition": {
                    "type": "string",
                    "enum": ["actionable", "benign"],
                    "description": "'benign' for a false positive / true negative needing "
                    "no action; 'actionable' for a real issue.",
                },
                "root_cause": {"type": "string"},
                "suggested_fix": {
                    "type": "string",
                    "description": "Human-readable recommended fix.",
                },
                "proposed_action": {
                    "type": ["string", "null"],
                    "description": "A single concrete shell command that applies the "
                    "fix, targeting only in-scope hosts, or null if none is safe.",
                },
                "confidence": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                },
            },
            "required": [
                "severity", "category", "disposition",
                "root_cause", "suggested_fix", "confidence",
            ],
        },
    },
]


def execute(name, inp, record):
    """Run a recon tool. Returns (output_text, is_error)."""
    if name == "port_scan":
        t = inp.get("target", "")
        if not in_scope(t):
            store.audit("scope_block", {"id": record.alert.id, "tool": name, "target": t})
            _log(record, f"[blocked] port_scan {t} — out of scope")
            return f"BLOCKED: {t} is not in the authorized scope. Refusing.", True
        _log(record, f"port_scan {t}")
        return _run(["nmap", "-sV", "-Pn", t]), False

    if name == "ping_sweep":
        c = inp.get("cidr", "")
        if not in_scope(c):
            store.audit("scope_block", {"id": record.alert.id, "tool": name, "target": c})
            _log(record, f"[blocked] ping_sweep {c} — out of scope")
            return f"BLOCKED: {c} is not in the authorized scope. Refusing.", True
        _log(record, f"ping_sweep {c}")
        return _run(["nmap", "-sn", c]), False

    if name == "dns_lookup":
        h = inp.get("host", "")
        _log(record, f"dns_lookup {h}")
        try:
            if IP_RE.fullmatch(h):
                return socket.gethostbyaddr(h)[0], False
            return socket.gethostbyname(h), False
        except OSError as e:
            return f"(lookup failed: {e})", False

    if name == "whois_lookup":
        q = inp.get("query", "")
        _log(record, f"whois_lookup {q}")
        return _run(["whois", q]), False

    if name == "search_memory":
        q = inp.get("query", "")
        _log(record, f"search_memory {q}")
        return memory.search_memory(q), False

    if name == "read_note":
        rel = inp.get("path", "")
        _log(record, f"read_note {rel}")
        return memory.read_note(rel)

    if name == "read_log":
        fname = inp.get("name", "")
        safe = (LOGS_DIR / fname).name
        path = LOGS_DIR / safe
        _log(record, f"read_log {safe}")
        if not path.exists():
            return f"(no log file named {safe})", False
        text = path.read_text(encoding="utf-8", errors="replace")
        sub = inp.get("contains")
        if sub:
            text = "\n".join(l for l in text.splitlines() if sub in l)
        return text[:6000] or "(empty / no matching lines)", False

    return f"(unknown tool {name})", True


def apply_fix(command, record):
    """Execute a remediation command, gated by deny list + scope. Returns (ok, output)."""
    low = command.lower()
    for d in DENY:
        if d in low:
            store.audit(
                "remediation_blocked",
                {"id": record.alert.id, "command": command, "reason": d},
            )
            return False, f"BLOCKED by deny list (matched '{d}'). Not executed."
    for ip in IP_RE.findall(command):
        if not in_scope(ip):
            store.audit(
                "remediation_blocked",
                {"id": record.alert.id, "command": command, "reason": f"oos {ip}"},
            )
            return False, f"BLOCKED: command targets {ip}, which is out of scope."
    try:
        p = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=120
        )
        ok = p.returncode == 0
        out = ((p.stdout or "") + (p.stderr or "")).strip()[:6000]
        return ok, out or f"(exit {p.returncode}, no output)"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
