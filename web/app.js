const SEV = {
  info: "#5bd6b0", low: "#3aa0c0", medium: "#d9a900",
  high: "#e6731f", critical: "#e23b3b",
};

async function j(url, opt) {
  const r = await fetch(url, opt);
  return r.json();
}

function esc(s) {
  return (s || "").replace(/[&<>]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
}

async function loadStatus() {
  const s = await j("/api/status");
  document.getElementById("model").textContent = "model: " + s.model;
  document.getElementById("scope").textContent =
    "scope: " + (s.scope.join(", ") || "none set");
  const b = document.getElementById("keybanner");
  if (!s.has_key) {
    b.classList.remove("hidden");
    b.textContent =
      "No ANTHROPIC_API_KEY set — add it to .env and restart to enable AI triage. " +
      "The dashboard and sensors work without it.";
  } else {
    b.classList.add("hidden");
  }
}

function card(r) {
  const a = r.alert, v = r.verdict;
  const c = SEV[a.severity] || "#888";
  let h = `<div class="card" style="border-left-color:${c}">
    <div class="row">
      <span class="sev" style="background:${c}">${a.severity}</span>
      <span class="src">${esc(a.src_ip || "?")} &rarr; ${esc(a.dst_ip || "?")}</span>
      <span class="status ${r.status}">${r.status}</span>
    </div>
    <div class="summary">${esc(a.summary)}</div>`;

  if (r.status === "new")
    h += `<button onclick="triage('${a.id}')">Run AI triage</button>`;
  if (r.status === "triaging")
    h += `<div class="working">AI is running recon&hellip;</div>`;
  if (r.error)
    h += `<div class="err">${esc(r.error)}</div>`;

  if (v) {
    h += `<div class="verdict">
      <div><b>Root cause:</b> ${esc(v.root_cause)}</div>
      <div><b>Suggested fix:</b> ${esc(v.suggested_fix)}</div>`;
    if (v.proposed_action)
      h += `<div class="cmd"><code>${esc(v.proposed_action)}</code></div>`;
    if (r.recon_log && r.recon_log.length)
      h += `<details><summary>recon steps (${r.recon_log.length})</summary>
        <pre>${esc(r.recon_log.join("\n"))}</pre></details>`;
    if (v.proposed_action && r.status === "triaged")
      h += `<button class="apply" onclick="apply('${a.id}')">Apply fix</button>`;
    if (r.remediation)
      h += `<div class="${r.remediation.ok ? "ok" : "err"}">remediation ${
        r.remediation.ok ? "applied" : "failed"
      }:<pre>${esc(r.remediation.output)}</pre></div>`;
    h += `</div>`;
  }
  h += `</div>`;
  return h;
}

async function triage(id) {
  await fetch(`/api/alerts/${id}/triage`, { method: "POST" });
  load();
}

async function apply(id) {
  if (!confirm("Apply this fix to the live system?")) return;
  await fetch(`/api/alerts/${id}/apply`, { method: "POST" });
  load();
}

async function load() {
  const rs = await j("/api/alerts");
  document.getElementById("count").textContent = rs.length + " alerts";
  document.getElementById("alerts").innerHTML =
    rs.map(card).join("") ||
    '<p class="empty">No alerts yet. Inject a demo alert to see the pipeline.</p>';
}

document.getElementById("demo").onclick = async () => {
  await fetch("/api/demo", { method: "POST" });
  load();
};

loadStatus();
load();
setInterval(load, 2000);
