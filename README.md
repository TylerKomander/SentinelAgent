# SentinelAgent

A security alert fires and an AI analyst picks it up: it runs read-only recon, reads what it wrote
about past incidents, and posts a verdict with a root cause, a plain-language fix and a concrete
command — and **that command only runs when you click Apply fix.** Drop in an Anthropic API key, your
Claude subscription, or a local model on your own hardware, and point it at a network you own.

Not a chatbot with a shell on the end of it. The recon and remediation tools are ordinary Python
functions in `app/ai/tools.py`, and each one checks its target against `config/scope_allowlist.txt`
before it does anything, so the model cannot reach a host you did not list. The scope is enforced in
code; the model is only asked to think.

## Run it

```bash
pip install -r requirements.txt
python run.py
# open http://127.0.0.1:8000
```

No credential is needed to boot. The dashboard, the demo sensor and the Suricata feed all work
without one — click **Inject demo alert** and an alert appears. Only AI triage is switched off, and
the page says so instead of failing.

## Turn on the AI

Copy `.env.example` to `.env` and set one of these. The app detects which you provided.

| Backend | Set in `.env` | Cost | Needs |
|---|---|---|---|
| API key (`sdk`) | `ANTHROPIC_API_KEY=sk-ant-...` | pay-per-token | `pip install anthropic` |
| Subscription (`claude_agent`) | `CLAUDE_CODE_OAUTH_TOKEN=...`, from `claude setup-token` | your Claude Pro/Max plan | Claude Code CLI + `pip install claude-agent-sdk` |
| Local model (`local`) | `SENTINEL_LOCAL_BASE_URL=http://127.0.0.1:11434/v1` | free, your hardware | a running Ollama, LM Studio, llama.cpp or vLLM |

All three run the same scope-enforced tools and the same memory. `SENTINEL_PROVIDER` forces one;
`SENTINEL_MODEL` picks the hosted model and `SENTINEL_LOCAL_MODEL` the local one.

The local backend talks the OpenAI-compatible `/v1/chat/completions` API, so it is not tied to one
runner, and it adds no Python dependency. **Pick a model that can call tools** — the scope wall works
by the model invoking our functions, so a model that cannot do that has nothing to investigate with.
When tool calling misfires, the provider falls back to reading a JSON verdict out of the reply and
tells the model to try again; a small model will still produce a worse verdict than a large one.

## What's in it

- **Dashboard** — every alert as a card, with its severity, source, status and verdict. It polls
  every two seconds, so a triage running in the background fills in as it goes.
- **Triage** — the agent investigates with nmap, DNS, whois and log reads, then submits one verdict:
  severity, category, disposition, root cause, suggested fix and a proposed command.
- **Memory vault** — every triage writes a deduplicated incident report as Obsidian-style markdown,
  and the app recalls related prior incidents *before* each alert rather than hoping the model asks
  for them. Point `OBSIDIAN_VAULT_PATH` at a real vault for the linked-notes view.
- **Doctrine** — caution first: anything uncertain is flagged and documented, and `benign` has to be
  earned by a pattern memory has confirmed before. It lives in `config/agent_brief.md`, which is
  appended to the system prompt, so you can retune the analyst without touching code.
- **Sensors** — `app/sensors/demo.py` emits synthetic alerts and `app/sensors/suricata.py` tails a
  real `eve.json` (set `SURICATA_EVE_PATH`). Both produce the same `Alert`, so switching to real
  detections is a config change.
- **Apply fix** — the verdict's command, run behind the same scope check plus a destructive-command
  deny list, and only on your click.

## What it can touch, and what stops it

| Guard | Where it is enforced |
|---|---|
| Scope allowlist | `in_scope()` in `app/ai/tools.py`, on every scan and on every IP inside a remediation command |
| Destructive-command deny list | `apply_fix()` in `app/ai/tools.py`, matched before the command runs |
| Read-only triage | the triage tool set contains no tool that changes anything |
| Human in the loop | remediation has its own endpoint and only runs from the Apply fix button |
| Audit log | every block, verdict and applied fix is appended to `data/audit.jsonl` |

Blocks are refusals the model sees and has to work around, not silent drops.

**The deny list is a backstop, not a sandbox.** It matches known-destructive strings in a shell
command; it is not a proof that nothing harmful gets through. Run this in the container or a VM, on a
network you own, and keep the allowlist as small as the job needs.

## Where it stands

Proven: the full loop has run live on WSL against Claude Sonnet 4.6 — recon, verdict, incident report
— with out-of-scope targets refused, `rm -rf` refused by the deny list, and repeat alerts deduplicating
onto one note instead of spawning a second.

Not yet: a VM run against real Suricata traffic, the `auto_remediate` flag in `config/rules.yaml`
wired into the pipeline, and a per-day token budget.

**The local backend has never been run against a real local model.** It is verified against a
scripted OpenAI-compatible server — tool translation, the scope wall, malformed-verdict recovery
and a dead server all covered — which proves the wiring and nothing about how well a 7B model
triages a security alert. Expect worse verdicts than the hosted models give, and check its work.

**Every IP, hostname, domain and MAC in this repo is a placeholder** — RFC 5737 documentation
addresses, RFC 1918 private ranges and `.example` names. Nothing here points at a real host, and no
real third party is labelled an attacker. Realistic data for running simulated attacks gets its own
commit; until then, `config/scope_allowlist.txt` is the file to edit before anything scans.

## Docker

```bash
ANTHROPIC_API_KEY=sk-ant-... docker compose up --build
```

The image is Kali-based, so nmap, tshark, whois and dig are present — on a plain Windows host the
agent notices they are missing and says so instead of inventing findings. On a Linux host, uncomment
`network_mode: host` in `docker-compose.yml` so recon can reach the LAN. `.dockerignore` keeps `.env`
and `data/` out of the image, so your key is not baked into a layer.

## Licence

MIT — see `LICENSE`. It drives nmap, tshark, whois and dig, which are their own projects under their
own licences, and it is not affiliated with or endorsed by Anthropic.
