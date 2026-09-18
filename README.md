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
- **Alert coalescing** — one port scan is thousands of IDS events and one thing worth looking at,
  so repeats of the same signature between the same endpoints collapse into a single card with a
  count. The window is `SENTINEL_DEDUP_WINDOW` (300 seconds by default, `0` to disable). The count
  is given to the analyst as evidence, and a card that keeps counting after you applied a fix is
  telling you the traffic did not stop.
- **Apply fix** — the verdict's command, run only if it matches an approved command shape in
  `config/remediation_allowlist.txt`, and only on your click.
- **Human in the loop, always** — the agent proposes the fix and never runs it on its own. A command
  executes only when you click Apply fix, and applied commands are ledgered so the same ban never
  fires twice.

## What it can touch, and what stops it

| Guard | Where it is enforced |
|---|---|
| Observation scope allowlist | `in_scope()` in `app/ai/tools.py`, on every scan — governs what the agent may LOOK AT |
| Remediation shape allowlist | `apply_fix()` in `app/ai/tools.py` — deny by default; a command runs only if it matches a shape in `config/remediation_allowlist.txt` |
| No shell | remediation runs via `shlex.split` + argv, never `shell=True`, so `;` `&&` `|` `$()` are not syntax |
| Destructive-command deny list | `apply_fix()`, a backstop in case a careless shape is added to the allowlist |
| Read-only triage | the triage tool set contains no tool that changes anything |
| Evidence-gated targets | `engine._verify_action_target()` — a command may only name an IP that appeared in real tool output, never one the alert merely claimed |
| Idempotent actions | `data/applied.jsonl` — a command that already ran is skipped, and the ledger survives restart |
| Least privilege | the app runs unprivileged; remediation shells out through `sudo -n` with a sudoers drop-in (`deploy/sentinel-sudoers`) that grants NOPASSWD for only `ufw`, `iptables`, `nft`, `fail2ban-client` — never blanket root |
| Human in the loop | remediation runs only on an explicit Apply fix click — the agent never applies a fix on its own |
| Audit log | every block, verdict and applied fix is appended to `data/audit.jsonl` |

Blocks are refusals the model sees and has to work around, not silent drops.

**Two different questions, two different lists.** `config/scope_allowlist.txt` decides what the agent
may *look at*; `config/remediation_allowlist.txt` decides what it may *run*. They are deliberately
separate: a firewall block rule names the attacker, who is never a host you own, so gating remediation
on the observation scope would refuse every legitimate fix. Every shape shipped in the remediation
allowlist can only ADD a block — none can remove one, flush a table, or stop a service.

**This is a gate, not a sandbox.** Deny-by-default is a much stronger position than a blacklist, but
the shapes you add are yours to get right. The evidence check narrows *which* address a command may
name — it cannot tell you the model read that evidence correctly. Run it in the container or a VM, on a network you own, and keep both lists as small as the
job needs.

## Where it stands

Proven on a real lab, not a mock. A Kali attacker and an Ubuntu victim sit on an isolated host-only
network with Suricata watching the victim's lab interface. An `nmap` from the attacker raises a
genuine IDS alert; the dashboard picks it up; the analyst — Claude Sonnet 4.6 — investigates with
real `nmap` and `whois` against in-scope hosts only, names the attacker rather than the host the
alert happened to list first, and proposes a `ufw` block. Clicking Apply fix enforced that rule on
the victim's firewall, and it was reversed by hand afterwards. Out-of-scope targets were refused
throughout, and every refusal is in `data/audit.jsonl`.

The memory is the part worth reading. A second attack on the same victim from a *different* source
address was recognised as the same campaign: the agent recalled the earlier incident note, cited it
by filename, and proposed that the first block had pushed the attacker onto a new address. Nothing
in the prompt said the two were related — deterministic recall put the earlier note in front of the
model before it started, and it drew the line itself.

The lab itself is written up in [`docs/lab.md`](docs/lab.md) — the two-machine topology, the two
Suricata settings that decide whether anything fires at all, the unprivileged sudo path, and the
`ufw` default that will lock you out of your own box if you let it.

Not yet: a per-day token budget and a persistent alert queue. **The alert queue is in memory, so
restarting the app clears the board.** That is deliberate for now rather than surprising — the
Suricata read offset is persisted, so a restart does not replay old events back onto a fresh queue.

**What a small local model is actually like**, measured on `qwen2.5:7b` against Ollama on an
8 GB RTX 2080 SUPER. A triage takes about 40 seconds. The scope wall held every time it tried an
out-of-scope host, and the refusals are in the audit log. The verdicts are plausible and thin —
`high / actionable / c2-beacon`, root cause naming both hosts and the interval — and it usually
returns no `proposed_action` at all, so **Apply fix often has nothing to run.** It wanders: on one
run it spent every turn on a missing tool, a log that does not exist and a note that was never
written, and finished with no verdict. Runs differ from each other on identical input.

Treat it as a triage assistant that never sleeps, not as an analyst. Check its work.

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
