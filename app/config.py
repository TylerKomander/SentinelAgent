import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"


def _load_env():
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


_load_env()

MODEL = os.environ.get("SENTINEL_MODEL", "claude-opus-4-8")


def has_api_key():
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


def has_oauth_token():
    return bool(os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip())


def has_local_server():
    return bool(os.environ.get("SENTINEL_LOCAL_BASE_URL", "").strip())


def provider_name():
    """sdk = Anthropic SDK (API key); claude_agent = Claude Agent SDK (subscription);
    local = any OpenAI-compatible server (Ollama, LM Studio, llama.cpp, vLLM).
    Explicit SENTINEL_PROVIDER wins; otherwise pick by which credential is present."""
    p = os.environ.get("SENTINEL_PROVIDER", "").strip().lower()
    if p:
        return p
    if has_api_key():
        return "sdk"
    if has_oauth_token():
        return "claude_agent"
    if has_local_server():
        return "local"
    return "sdk"


def local_base_url():
    """OpenAI-compatible base URL. Ollama serves one at :11434/v1."""
    return (
        os.environ.get("SENTINEL_LOCAL_BASE_URL", "").strip()
        or "http://127.0.0.1:11434/v1"
    )


def local_api_key():
    """Local servers ignore this but many still require the header to be present."""
    return os.environ.get("SENTINEL_LOCAL_API_KEY", "").strip() or "local"


def local_model():
    return os.environ.get("SENTINEL_LOCAL_MODEL", "").strip() or MODEL


def active_model():
    return local_model() if provider_name() == "local" else MODEL


def scope_allowlist():
    f = CONFIG_DIR / "scope_allowlist.txt"
    if not f.exists():
        return []
    out = []
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def remediation_allowlist():
    """Command shapes the agent may execute. Empty file or missing = execute nothing."""
    f = CONFIG_DIR / "remediation_allowlist.txt"
    if not f.exists():
        return []
    out = []
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def suricata_eve_path():
    """Path to Suricata's eve.json. If set, the app tails it and feeds real alerts
    into the dashboard. Blank = demo feed only."""
    return os.environ.get("SURICATA_EVE_PATH", "").strip()


def vault_dir():
    p = os.environ.get("OBSIDIAN_VAULT_PATH", "").strip()
    return Path(p) if p else ROOT / "data" / "vault"


def agent_brief():
    f = CONFIG_DIR / "agent_brief.md"
    return f.read_text(encoding="utf-8") if f.exists() else ""


def dedup_window_seconds():
    """Repeat alerts (same source/signature/src/dst) inside this sliding window
    collapse into one record with a count. A port scan is one event to an analyst,
    not four hundred. 0 disables coalescing."""
    try:
        return float(os.environ.get("SENTINEL_DEDUP_WINDOW", "300"))
    except ValueError:
        return 300.0


def bind_host():
    """Loopback unless told otherwise. On a headless lab box you need 0.0.0.0 to reach
    the dashboard from another machine — that is an explicit choice, not a default,
    because the dashboard has no authentication in front of it."""
    return os.environ.get("SENTINEL_HOST", "").strip() or "127.0.0.1"


def bind_port():
    try:
        return int(os.environ.get("SENTINEL_PORT", "8000"))
    except ValueError:
        return 8000
