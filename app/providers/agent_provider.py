import json

from .. import memory
from ..ai import tools as T
from ..ai.prompts import REPORT_SYSTEM, composed_system, triage_prompt
from ..config import MODEL, has_api_key, has_oauth_token
from ..models import Verdict

NAME = "claude_agent"
MAX_ITERS = 12
_SERVER = "sentinel"
_ALLOWED = [f"mcp__{_SERVER}__{s['name']}" for s in T.TRIAGE_TOOLS]
_REPORT_KEYS = [k for _, k in memory.SECTIONS]


def available():
    try:
        import claude_agent_sdk  # noqa: F401
    except ImportError:
        return False, "claude-agent-sdk not installed (pip install claude-agent-sdk)."
    if not (has_oauth_token() or has_api_key()):
        return False, (
            "No CLAUDE_CODE_OAUTH_TOKEN set. Run `claude setup-token` (uses your "
            "Claude subscription) and add the token to .env."
        )
    return True, ""


def investigate(record):
    import anyio
    return anyio.run(_investigate, record)


def _build_tools(record, state):
    from claude_agent_sdk import tool

    sdk_tools = []
    for spec in T.TRIAGE_TOOLS:
        name = spec["name"]
        schema = spec["input_schema"]
        if name == "submit_verdict":
            @tool(name, spec["description"], schema)
            async def _submit(args):
                fields = {k: v for k, v in args.items() if k in Verdict.model_fields}
                record.verdict = Verdict(**fields)
                state["verdict"] = True
                state["steps"].append({"tool": "submit_verdict", "input": args})
                return {"content": [{"type": "text", "text": "Verdict recorded."}]}
            sdk_tools.append(_submit)
        else:
            @tool(name, spec["description"], schema)
            async def _run(args, _n=name):
                out, is_err = T.execute(_n, args, record)
                state["steps"].append({
                    "tool": _n, "input": args, "output": out[:2000], "is_error": is_err,
                })
                return {
                    "content": [{"type": "text", "text": out}],
                    "is_error": is_err,
                }
            sdk_tools.append(_run)
    return sdk_tools


async def _investigate(record):
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        PermissionResultAllow,
        PermissionResultDeny,
        TextBlock,
        create_sdk_mcp_server,
        query,
    )

    prompt = triage_prompt(record)
    state = {"verdict": False, "steps": [{"prompt": prompt}]}
    server = create_sdk_mcp_server(_SERVER, "1.0.0", _build_tools(record, state))

    async def _gate(tool_name, _inp, _ctx):
        if tool_name in _ALLOWED:
            return PermissionResultAllow()
        return PermissionResultDeny(
            message="blocked: only scope-enforced sentinel tools are permitted"
        )

    opts = ClaudeAgentOptions(
        mcp_servers={_SERVER: server},
        allowed_tools=_ALLOWED,
        disallowed_tools=["Bash", "Read", "Edit", "Write", "WebFetch", "WebSearch"],
        system_prompt=composed_system(),
        permission_mode="dontAsk",
        can_use_tool=_gate,
        model=MODEL,
        max_turns=MAX_ITERS,
    )

    transcript = []
    async for msg in query(prompt=prompt, options=opts):
        if isinstance(msg, AssistantMessage):
            for b in msg.content:
                if isinstance(b, TextBlock):
                    transcript.append(b.text)
                    state["steps"].append({"reasoning": b.text})

    if not state["verdict"]:
        record.error = record.error or "Triage finished without submitting a verdict."
        return None, state["steps"]
    text = "\n".join(transcript)
    return (lambda: _narrate(text)), state["steps"]


def _narrate(transcript):
    import anyio
    try:
        return anyio.run(_narrate_async, transcript)
    except Exception:
        return None


async def _narrate_async(transcript):
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeAgentOptions,
        TextBlock,
        query,
    )

    keys = ", ".join(_REPORT_KEYS)
    prompt = (
        f"Investigation transcript:\n{transcript}\n\n"
        f"Write an incident report as a single JSON object with exactly these keys: "
        f"{keys}. Each value is markdown prose. Output ONLY the JSON, no fences."
    )
    opts = ClaudeAgentOptions(
        system_prompt=REPORT_SYSTEM,
        model=MODEL,
        permission_mode="dontAsk",
        allowed_tools=[],
        tools=[],
        max_turns=1,
    )
    out = []
    async for msg in query(prompt=prompt, options=opts):
        if isinstance(msg, AssistantMessage):
            for b in msg.content:
                if isinstance(b, TextBlock):
                    out.append(b.text)
    return _extract_json("\n".join(out))


def _extract_json(text):
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start:end + 1])
    except ValueError:
        return None
    return {k: data[k] for k in _REPORT_KEYS if k in data} or None
