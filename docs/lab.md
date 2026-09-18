# The lab

This is the setup behind the "Where it stands" section of the README — two virtual machines on an
isolated network, one attacking and one defending, with SentinelAgent watching from the victim. It
is what turns the dashboard from a thing that demos into a thing that has been used: a real `nmap`
raises a real Suricata alert, the analyst investigates with real tools, and the fix it proposes is
enforced on a real firewall.

Everything here is reproducible in an evening on a laptop. **The settings that cost the most time
are called out with the symptom they produce**, because each of them fails quietly — the pipeline
looks healthy and simply never fires.

## The shape

| Host | Role | Interfaces |
|---|---|---|
| Ubuntu Server | victim — runs SentinelAgent and Suricata | NAT (reaches the Anthropic API) + host-only (lab traffic) |
| Kali | attacker — runs `nmap` and nothing else | host-only |

Addresses below use `10.0.0.0/24` for the host-only network, matching the range already shipped in
`config/scope_allowlist.txt`, so a fresh clone needs no edit to follow this document: the victim is
`10.0.0.10` and the attacker `10.0.0.20`. Interface names are the VMware defaults (`ens33` for NAT,
`ens37` for host-only); yours may differ, and `ip -br addr` will tell you.

## Why the victim needs two interfaces

The agent has to reach the Anthropic API to think, and the traffic it is reasoning about has to stay
on a wire that nothing else touches. One interface cannot do both cleanly — API calls would appear
in the same capture as the attack, and an isolated network has no route to the internet. So the NAT
interface carries the agent's own API traffic and your SSH session, the host-only interface carries
the lab, and **Suricata is bound to the host-only interface only.**

## Suricata: the two settings that decide whether anything fires

- **`HOME_NET` must be the victim alone, as a `/32`.** Set it to `[10.0.0.10/32]`, not the `/24`.
  With the whole subnet listed as home, the attacker is *inside* the network Suricata is protecting,
  and every `$EXTERNAL_NET -> $HOME_NET` scan rule — which is most of them — stops matching. The
  symptom is a scan that completes normally and produces no alert at all, which reads as a broken
  install rather than a configuration choice.
- **`af-packet` must name the interface that exists.** The stock config watches `eth0`, which is not
  what a modern Ubuntu calls anything. Point it at `ens37`. The symptom is identical to the one
  above: a clean start, a healthy `systemctl status`, and an `eve.json` that never grows.

Confirm both at once by pinging the victim from Kali and watching the log grow:

```bash
# on the victim
wc -l /var/log/suricata/eve.json
```

A count that increases after traffic means Suricata is on the right wire. A count that never moves
means one of the two settings above is wrong, and no amount of attacking will change that.

Then point the app at the log with `SURICATA_EVE_PATH=/var/log/suricata/eve.json`. The reader tracks
a byte offset and persists it, so restarting the app does not replay events you have already seen.

## Running the app on the victim

- **Use the `sdk` provider.** `SENTINEL_PROVIDER=sdk` with an `ANTHROPIC_API_KEY` needs nothing but
  Python. The subscription backend would also need Node and the Claude CLI installed on the victim,
  which is a lot of machinery to put on a box whose job is to be attacked.
- **Bind to all interfaces to reach the dashboard from your host browser.** `SENTINEL_HOST=0.0.0.0`.
  **The dashboard has no login**, so do this only on an isolated lab network and understand that
  anything which can route to the box can drive it.
- **Put the victim in `config/scope_allowlist.txt`.** This is what the agent may *look at*. The
  attacker does not belong in this file — a block rule names the attacker, and remediation is gated
  by command shape rather than by observation scope. The README explains why those are two lists.

## Remediation without running as root

A firewall block needs root; a web dashboard that an attacker is actively probing must not have it.
The app therefore runs unprivileged and shells out through `sudo -n`, with a sudoers drop-in that
grants passwordless root for only `ufw`, `iptables`, `nft` and `fail2ban-client`:

```bash
sudo cp deploy/sentinel-sudoers /etc/sudoers.d/sentinel
sudo sed -i "s/__USER__/$(logname)/" /etc/sudoers.d/sentinel
sudo chmod 440 /etc/sudoers.d/sentinel
sudo visudo -cf /etc/sudoers.d/sentinel   # must print "parsed OK"
```

Two details worth knowing. The shape allowlist is checked against the **bare** command, before
`sudo` is prepended, so adding `sudo` never smuggles a command past the gate. And `sudo -n` fails
closed: anything outside those four binaries hits a password prompt that non-interactive sudo will
not answer, so it errors instead of running. Deleting the file revokes every remediation privilege
at once.

## `ufw enable` will lock you out

Enabling `ufw` with stock defaults flips the box to deny-incoming, which **drops your SSH session on
the NAT interface and the dashboard on port 8000 in the same instant.** For lab runs, make the
default permissive so that only the agent's own deny rule has any effect:

```bash
sudo ufw default allow incoming
sudo ufw --force enable
```

**A realistic default-deny posture — allowing 22 and 8000 explicitly, then denying the rest — has
not been tested here.** That is a gap, not a recommendation: it is the more honest configuration and
it is the obvious next thing to try, but this lab has only ever run permissive.

## Running the loop end to end

1. Start the app on the victim and open the dashboard from your host browser.
2. From Kali, run `nmap -sV -Pn 10.0.0.10`.
3. Watch the alert appear. One scan is thousands of IDS events and arrives as a single card, because
   repeats of the same signature between the same endpoints coalesce inside `SENTINEL_DEDUP_WINDOW`.
4. Trigger triage. The analyst searches memory first, then runs its own recon against in-scope hosts,
   and submits a verdict naming a root cause and a proposed command.
5. Read the proposed command before you click. **Apply fix is the only thing that executes it**, and
   the command may only name an address that showed up in real tool output.
6. Verify with `sudo ufw status numbered`, then remove the rule by number to reset the lab.

Attacking a second time from a different source address is the run worth doing: the agent recalls
the note it wrote the first time and treats the two as one campaign rather than two unrelated events.

## What this lab does not prove

- **There is no benign traffic on the host-only wire.** Nothing lives there but the attack, so this
  lab demonstrates the response loop and says nothing about false-positive rates. Any detection
  tuning — thresholds, baselines, novelty scoring — needs a capture from a network with ordinary
  background noise on it, and that is a different piece of work.
- **The alert queue is held in memory.** Restarting the app clears the board. The Suricata offset is
  persisted, so old events are not replayed either; re-run the attack to repopulate.
- **The `claude_agent` backend has never been run here.** The `sdk` and `local` backends have.
