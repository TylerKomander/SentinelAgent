import ipaddress
import os
import re
import shlex
import shutil
import socket
import subprocess

from .. import memory
from ..config import ROOT, remediation_allowlist, scope_allowlist
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
                    "fix, or null if none is safe. It will only be executed if it "
                    "matches an approved shape, so use one of: "
                    "'ufw deny from <ip>[ to any[ port <port>]]', "
                    "'iptables -A INPUT -s <ip> -j DROP', "
                    "'nft add rule inet filter input ip saddr <ip> drop', "
                    "'fail2ban-client set sshd banip <ip>'. No pipes, no chaining, "
                    "no sudo prefix. Anything else is reported but never run.",
                },
                "action_evidence": {
                    "type": ["string", "null"],
                    "description": "REQUIRED whenever proposed_action is not null. Name the "
                    "IP the command targets and quote the specific tool output that "
                    "identifies it as the actor to block (e.g. 'auth.log shows 15 failed "
                    "root logins from 198.51.100.34'). Do NOT target an IP merely because "
                    "the alert named it — target the one the evidence incriminates. If you "
                    "cannot point at observed evidence for the target, set proposed_action "
                    "to null instead.",
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
    """Run a recon tool and record every IP the output actually revealed. Returns
    (output_text, is_error). The observed set is what `proposed_action` is checked
    against later — an IP the agent never saw in evidence is not a justified target."""
    out, err = _execute(name, inp, record)
    if not err:
        for ip in IP_RE.findall(out or ""):
            if ip not in record.observed_ips:
                record.observed_ips.append(ip)
    return out, err


def _execute(name, inp, record):
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


_PLACEHOLDERS = {
    "<ip>": r"\d{1,3}(?:\.\d{1,3}){3}",
    "<cidr>": r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}",
    "<port>": r"\d{1,5}",
    "<text>": r"[\w.:/@-]+",
}


def _compile(pattern):
    parts = [_PLACEHOLDERS.get(tok, re.escape(tok)) for tok in pattern.split()]
    return re.compile(r"\s+".join(parts))


def _matches_allowlist(command):
    for pattern in remediation_allowlist():
        if _compile(pattern).fullmatch(command):
            return pattern
    return None


def apply_fix(command, record):
    """Execute a remediation command. DENY BY DEFAULT: the command must match a shape in
    config/remediation_allowlist.txt, or it does not run. Returns (ok, output)."""

    def blocked(reason, message):
        store.audit(
            "remediation_blocked",
            {"id": record.alert.id, "command": command, "reason": reason},
        )
        return False, message

    command = " ".join(command.split())
    if not command:
        return blocked("empty", "BLOCKED: empty command.")

    # Backstop only. The allowlist below is the real gate; this catches a careless
    # pattern added to the allowlist file by hand.
    low = command.lower()
    for d in DENY:
        if d in low:
            return blocked(d, f"BLOCKED by deny list (matched '{d}'). Not executed.")

    pattern = _matches_allowlist(command)
    if not pattern:
        return blocked(
            "not allowlisted",
            "BLOCKED: this command does not match any approved remediation shape in "
            "config/remediation_allowlist.txt. Not executed.",
        )

    try:
        argv = shlex.split(command)
    except ValueError as e:
        return blocked("unparseable", f"BLOCKED: could not parse command ({e}).")

    # Firewall commands need root, but the dashboard has no business running as root.
    # When the service is unprivileged, hand the already-shape-checked argv to sudo in
    # non-interactive mode. A sudoers drop-in (deploy/sentinel-sudoers) grants NOPASSWD
    # for only the remediation binaries; anything else fails closed on a password prompt
    # sudo -n will not answer. When the app is already root (e.g. in the container) sudo
    # is unnecessary and may be absent, so skip it.
    if os.name == "posix" and os.geteuid() != 0:
        argv = ["sudo", "-n", *argv]

    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        ok = p.returncode == 0
        out = ((p.stdout or "") + (p.stderr or "")).strip()[:6000]
        return ok, out or f"(exit {p.returncode}, no output)"
    except FileNotFoundError:
        return False, f"(command '{argv[0]}' is not installed on this host)"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
