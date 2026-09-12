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


def auto_remediate_armed():
    """Master switch for unattended remediation. OFF unless explicitly set. A rule
    opting in is not enough — you also have to arm the machine, and this is the one
    line to flip when you want it to stop."""
    return os.environ.get("SENTINEL_AUTO_REMEDIATE", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


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
