import anthropic

from .. import memory
from ..ai import tools as T
from ..ai.prompts import REPORT_SYSTEM, composed_system, triage_prompt
from ..config import MODEL, has_api_key
from ..models import Verdict

NAME = "sdk"
MAX_ITERS = 8

WRITE_REPORT_TOOL = {
    "name": "write_incident_report",
    "description": "Write the incident report narrative. Fill every section.",
    "input_schema": {
        "type": "object",
        "properties": {k: {"type": "string"} for _, k in memory.SECTIONS},
        "required": [k for _, k in memory.SECTIONS],
    },
}

_REPORT_INSTR = (
    "Now write the incident report using write_incident_report. Be thorough and "
    "honest about any trip-ups, dead ends, or uncertainty."
)


def available():
    if not has_api_key():
        return False, (
            "No ANTHROPIC_API_KEY set. Add your key to .env (or switch to the "
            "subscription provider with SENTINEL_PROVIDER=claude_agent)."
        )
    return True, ""


def investigate(record):
    """Run the triage loop. Sets record.verdict + recon_log. Returns (narrator, steps):
    narrator is a report callable (or None if no verdict); steps is the full trace."""
    client = anthropic.Anthropic()
    prompt = triage_prompt(record)
    messages = [{"role": "user", "content": prompt}]
    steps = [{"prompt": prompt}]

    try:
        for _ in range(MAX_ITERS):
            resp = client.messages.create(
                model=MODEL,
                max_tokens=8000,
                system=composed_system(),
                tools=T.TRIAGE_TOOLS,
                messages=messages,
            )
            turn = []
            for block in resp.content:
                if block.type == "text":
                    turn.append({"reasoning": block.text})
                elif block.type == "tool_use":
                    turn.append({"tool_call": block.name, "input": block.input})
            steps.append({"assistant": turn})
            if resp.stop_reason != "tool_use":
                break
            messages.append({"role": "assistant", "content": resp.content})
            results, tool_trace = [], []
            for block in resp.content:
                if block.type != "tool_use":
                    continue
                if block.name == "submit_verdict":
                    record.verdict = Verdict(**block.input)
                    results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": "Verdict recorded.",
                    })
                    tool_trace.append({"tool": "submit_verdict", "input": block.input})
                else:
                    out, is_err = T.execute(block.name, block.input, record)
                    results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": out,
                        "is_error": is_err,
                    })
                    tool_trace.append({
                        "tool": block.name, "input": block.input,
                        "output": out[:2000], "is_error": is_err,
                    })
            steps.append({"tool_results": tool_trace})
            messages.append({"role": "user", "content": results})
            if record.verdict:
                return (lambda: _narrate(record, client, messages)), steps
    except anthropic.AuthenticationError:
        record.error = "Invalid ANTHROPIC_API_KEY — authentication failed."
        return None, steps
    record.error = record.error or "Triage finished without submitting a verdict."
    return None, steps


def _narrate(record, client, messages):
    msgs = _with_report_prompt(messages)
    resp = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=REPORT_SYSTEM,
        tools=[WRITE_REPORT_TOOL],
        tool_choice={"type": "tool", "name": "write_incident_report"},
        messages=msgs,
    )
    for block in resp.content:
        if getattr(block, "type", None) == "tool_use" and block.name == (
            "write_incident_report"
        ):
            return dict(block.input)
    return None


def _with_report_prompt(messages):
    msgs = [dict(m) for m in messages]
    if msgs and msgs[-1].get("role") == "user":
        c = msgs[-1].get("content")
        if isinstance(c, list):
            msgs[-1]["content"] = list(c) + [{"type": "text", "text": _REPORT_INSTR}]
        else:
            msgs[-1]["content"] = f"{c}\n\n{_REPORT_INSTR}"
    else:
        msgs.append({"role": "user", "content": _REPORT_INSTR})
    return msgs
