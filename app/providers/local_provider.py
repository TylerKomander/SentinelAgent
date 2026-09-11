import json
import urllib.error
import urllib.request

from .. import memory
from ..ai import tools as T
from ..ai.prompts import REPORT_SYSTEM, composed_system, triage_prompt
from ..config import active_model, local_api_key, local_base_url
from ..models import Verdict

NAME = "local"
MAX_ITERS = 8
_TIMEOUT = 600
_PROBE_TIMEOUT = 5
_REPORT_KEYS = [k for _, k in memory.SECTIONS]
_VERDICT_FIELDS = set(Verdict.model_fields)

_NUDGE = (
    "You replied with prose and no tool call. Investigate with a recon tool, or call "
    "submit_verdict with your final verdict. Respond with a tool call."
)


def _request(path, payload=None, timeout=_TIMEOUT):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        local_base_url().rstrip("/") + path,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {local_api_key()}",
        },
        method="POST" if data is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def available():
    url = local_base_url()
    try:
        _request("/models", timeout=_PROBE_TIMEOUT)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, (
                f"Local model server at {url} rejected the credential (HTTP {e.code}). "
                "Set SENTINEL_LOCAL_API_KEY to whatever it expects."
            )
        return False, f"Local model server at {url} returned HTTP {e.code}."
    except Exception as e:
        return False, (
            f"No local model server reachable at {url} ({type(e).__name__}). Start one "
            "(`ollama serve`) or point SENTINEL_LOCAL_BASE_URL at it."
        )
    return True, ""


def _tool_specs():
    """Our Anthropic-shaped tool specs, in the OpenAI function-calling shape."""
    return [
        {
            "type": "function",
            "function": {
                "name": spec["name"],
                "description": spec["description"],
                "parameters": spec["input_schema"],
            },
        }
        for spec in T.TRIAGE_TOOLS
    ]


def _call_args(call):
    raw = (call.get("function") or {}).get("arguments")
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw or "{}")
    except ValueError:
        return {}


def _extract_json(text):
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except ValueError:
        return None


def _set_verdict(record, args):
    """Returns an error string for the model to read, or None when the verdict stands.
    A small local model will omit required fields; that has to come back as a tool error
    it can retry rather than an exception that kills the triage."""
    fields = {k: v for k, v in args.items() if k in _VERDICT_FIELDS}
    try:
        record.verdict = Verdict(**fields)
    except Exception as e:
        missing = ", ".join(sorted(_VERDICT_FIELDS - set(fields)))
        return (
            f"Verdict rejected ({type(e).__name__}). Call submit_verdict again with every "
            f"required field. Missing or invalid: {missing or 'see schema'}."
        )
    return None


def investigate(record):
    """Run the triage loop against an OpenAI-compatible local server (Ollama, LM Studio,
    llama.cpp, vLLM). Same tools, same scope enforcement as the hosted providers."""
    prompt = triage_prompt(record)
    messages = [
        {"role": "system", "content": composed_system()},
        {"role": "user", "content": prompt},
    ]
    steps = [{"prompt": prompt}]
    nudged = False

    for _ in range(MAX_ITERS):
        try:
            resp = _request(
                "/chat/completions",
                {
                    "model": active_model(),
                    "messages": messages,
                    "tools": _tool_specs(),
                    "temperature": 0,
                },
            )
        except Exception as e:
            record.error = f"Local model call failed: {type(e).__name__}: {e}"
            return None, steps

        message = (resp.get("choices") or [{}])[0].get("message") or {}
        text = (message.get("content") or "").strip()
        calls = message.get("tool_calls") or []
        if text:
            steps.append({"reasoning": text})

        if calls:
            messages.append(
                {"role": "assistant", "content": message.get("content") or "", "tool_calls": calls}
            )
        else:
            messages.append({"role": "assistant", "content": text})
            recovered = _extract_json(text)
            if recovered and _set_verdict(record, recovered) is None:
                steps.append(
                    {"tool": "submit_verdict", "input": recovered, "output": "recovered from message text"}
                )
                return (lambda: _narrate(messages)), steps
            if nudged:
                record.error = "Local model finished without submitting a verdict."
                return None, steps
            nudged = True
            messages.append({"role": "user", "content": _NUDGE})
            continue

        for call in calls:
            name = (call.get("function") or {}).get("name", "")
            args = _call_args(call)
            if name == "submit_verdict":
                error = _set_verdict(record, args)
                out, is_error = (error or "Verdict recorded."), bool(error)
            else:
                out, is_error = T.execute(name, args, record)
            steps.append(
                {"tool": name, "input": args, "output": out[:2000], "is_error": is_error}
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.get("id") or name,
                    "name": name,
                    "content": out,
                }
            )

        if record.verdict:
            return (lambda: _narrate(messages)), steps

    record.error = record.error or "Local model hit the turn limit without a verdict."
    return None, steps


def _narrate(messages):
    keys = ", ".join(_REPORT_KEYS)
    msgs = [{"role": "system", "content": REPORT_SYSTEM}]
    msgs += [m for m in messages if m.get("role") != "system"]
    msgs.append(
        {
            "role": "user",
            "content": (
                f"Write the incident report as a single JSON object with exactly these keys: "
                f"{keys}. Each value is markdown prose. Output only the JSON."
            ),
        }
    )
    try:
        resp = _request(
            "/chat/completions",
            {"model": active_model(), "messages": msgs, "temperature": 0},
        )
    except Exception:
        return None
    text = ((resp.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    data = _extract_json(text)
    if not data:
        return None
    return {k: data[k] for k in _REPORT_KEYS if k in data} or None
