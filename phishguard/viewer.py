"""Render the analysed mailbox as a self-contained HTML page.

A visual test harness first and a UI prototype second. It reads only what the
detectors already wrote - verdicts and findings - so whatever appears on the
page is exactly what the backend decided, with no presentation-layer judgement
of its own. If a message looks wrong here, the bug is upstream.

Single file, no assets, no server: `phishguard view` writes it and any browser
opens it.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db.store import Store

TIER_ORDER = {"danger": 0, "caution": 1, "safe": 2}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def collect(store: Store, account_id: int, limit: int = 200) -> dict[str, Any]:
    rows = store.conn.execute(
        """SELECT m.id, m.gmail_id, m.subject, m.from_addr, m.from_display,
                  m.received_at, m.body_text, m.labels_json,
                  v.id AS verdict_id, v.tier, v.score, v.model_version
           FROM messages m
           LEFT JOIN verdicts v ON v.message_id = m.id
           WHERE m.account_id = ? AND m.labels_json NOT LIKE '%SENT%'
           ORDER BY m.received_at DESC
           LIMIT ?""",
        (account_id, limit),
    ).fetchall()

    messages: list[dict[str, Any]] = []
    for row in rows:
        findings: list[dict[str, Any]] = []
        if row["verdict_id"]:
            for f in store.conn.execute(
                "SELECT * FROM findings WHERE verdict_id = ? ORDER BY ABS(weight) DESC",
                (row["verdict_id"],),
            ):
                try:
                    evidence = json.loads(f["evidence_json"] or "{}")
                except (TypeError, ValueError):
                    evidence = {}
                findings.append({
                    "layer": f["layer"], "code": f["code"],
                    "severity": f["severity"], "weight": f["weight"],
                    "text": f["human_text"], "evidence": evidence,
                    "mitigating": (f["weight"] or 0) <= 0,
                })
        messages.append({
            "id": row["gmail_id"],
            "subject": row["subject"] or "(no subject)",
            "from_addr": row["from_addr"] or "",
            "from_display": row["from_display"] or "",
            "date": (row["received_at"] or "")[:10],
            "preview": " ".join((row["body_text"] or "").split())[:180],
            "tier": row["tier"] or "unscored",
            "score": row["score"] if row["score"] is not None else 0.0,
            "model": row["model_version"] or "",
            "findings": findings,
        })

    profiles = [dict(r) for r in store.conn.execute(
        """SELECT canonical_email, samples,
                  json_extract(style_json, '$.samples') AS style_samples
           FROM contact_profiles WHERE account_id = ?
           ORDER BY samples DESC LIMIT 12""", (account_id,))]

    counts: dict[str, int] = {}
    for m in messages:
        counts[m["tier"]] = counts.get(m["tier"], 0) + 1

    return {
        "account": store.account_email(account_id) or "unknown",
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "messages": sorted(
            messages,
            key=lambda m: (TIER_ORDER.get(m["tier"], 9), -m["score"]),
        ),
        "counts": counts,
        "profiles": profiles,
        "stats": store.stats(account_id),
    }


CSS = """
:root {
  color-scheme: light dark;
  --bg: #f6f7f9; --panel: #ffffff; --ink: #14161a; --muted: #646b78;
  --line: #e3e6ec; --accent: #2f6feb;
  --safe: #157f4a; --safe-bg: #e8f6ee;
  --caution: #9a6300; --caution-bg: #fdf3e0;
  --danger: #b3261e; --danger-bg: #fdecea;
  --none: #5b6270; --none-bg: #eef0f4;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #101216; --panel: #171a20; --ink: #e8eaee; --muted: #9aa2b1;
    --line: #262a33; --accent: #6d9bff;
    --safe: #5ed39a; --safe-bg: #14301f;
    --caution: #f0b354; --caution-bg: #33260f;
    --danger: #ff8a80; --danger-bg: #3a1a18;
    --none: #9aa2b1; --none-bg: #21252d;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif;
}
header {
  padding: 20px 24px 16px; border-bottom: 1px solid var(--line);
  background: var(--panel); position: sticky; top: 0; z-index: 5;
}
h1 { margin: 0 0 2px; font-size: 17px; letter-spacing: -0.01em; }
.sub { color: var(--muted); font-size: 12.5px; }
.tallies { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
.tally {
  border: 1px solid var(--line); border-radius: 8px; padding: 7px 12px;
  background: var(--bg); cursor: pointer; font-size: 12.5px; user-select: none;
}
.tally[aria-pressed="true"] { border-color: var(--accent); box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 22%, transparent); }
.tally b { font-size: 15px; }
.wrap { display: grid; grid-template-columns: minmax(320px, 420px) 1fr; gap: 0; min-height: calc(100vh - 118px); }
@media (max-width: 900px) { .wrap { grid-template-columns: 1fr; } #detail { border-left: 0; border-top: 1px solid var(--line); } }
#list { border-right: 1px solid var(--line); overflow-y: auto; max-height: calc(100vh - 118px); }
.row {
  padding: 12px 16px; border-bottom: 1px solid var(--line); cursor: pointer;
  display: grid; grid-template-columns: 74px 1fr; gap: 10px; align-items: start;
}
.row:hover { background: var(--panel); }
.row[aria-selected="true"] { background: var(--panel); box-shadow: inset 3px 0 0 var(--accent); }
.row .who { font-weight: 600; font-size: 13px; }
.row .subj { font-size: 13px; }
.row .prev { color: var(--muted); font-size: 12px; margin-top: 2px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.badge {
  display: inline-block; text-align: center; width: 100%;
  border-radius: 6px; padding: 3px 0; font-size: 10.5px; font-weight: 700;
  letter-spacing: 0.06em; text-transform: uppercase;
}
.t-safe    { color: var(--safe);    background: var(--safe-bg); }
.t-caution { color: var(--caution); background: var(--caution-bg); }
.t-danger  { color: var(--danger);  background: var(--danger-bg); }
.t-unscored{ color: var(--none);    background: var(--none-bg); }
.score { display: block; font-size: 10px; color: var(--muted); margin-top: 3px; text-align: center; }
#detail { padding: 22px 26px; overflow-y: auto; max-height: calc(100vh - 118px); }
.headline { font-size: 15px; font-weight: 600; margin: 14px 0 18px; }
.meta { color: var(--muted); font-size: 12.5px; margin-bottom: 3px; }
.meta b { color: var(--ink); font-weight: 500; }
.finding {
  border: 1px solid var(--line); border-left-width: 3px; border-radius: 8px;
  padding: 11px 14px; margin-bottom: 9px; background: var(--panel);
}
.f-critical, .f-high { border-left-color: var(--danger); }
.f-medium { border-left-color: var(--caution); }
.f-low, .f-info { border-left-color: var(--none); }
.finding.good { border-left-color: var(--safe); }
.ftop { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; margin-bottom: 4px; }
.tag {
  font-size: 10px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;
  padding: 2px 6px; border-radius: 4px; background: var(--none-bg); color: var(--muted);
}
.code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; color: var(--muted); }
.ftext { font-size: 13.5px; }
details { margin-top: 7px; }
summary { cursor: pointer; font-size: 11.5px; color: var(--muted); }
pre {
  margin: 7px 0 0; padding: 9px 11px; background: var(--bg); border: 1px solid var(--line);
  border-radius: 6px; font-size: 11px; overflow-x: auto;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}
h3 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.07em;
     color: var(--muted); margin: 22px 0 9px; font-weight: 600; }
.empty { color: var(--muted); padding: 60px 20px; text-align: center; }
.body-preview { white-space: pre-wrap; font-size: 13px; color: var(--muted);
  border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; background: var(--panel); }
"""

JS = """
const DATA = __DATA__;
let filter = null, selected = null;

const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

function visible() {
  return filter ? DATA.messages.filter(m => m.tier === filter) : DATA.messages;
}

function renderList() {
  const rows = visible();
  const el = document.getElementById('list');
  if (!rows.length) { el.innerHTML = '<div class="empty">Nothing here.</div>'; return; }
  el.innerHTML = rows.map((m, i) => `
    <div class="row" role="option" data-i="${i}" aria-selected="${selected === m.id}">
      <div>
        <span class="badge t-${m.tier}">${m.tier === 'unscored' ? '—' : m.tier}</span>
        <span class="score">${m.tier === 'unscored' ? '' : m.score.toFixed(2)}</span>
      </div>
      <div>
        <div class="who">${esc(m.from_display || m.from_addr)}</div>
        <div class="subj">${esc(m.subject)}</div>
        <div class="prev">${esc(m.preview || '')}</div>
      </div>
    </div>`).join('');
  el.querySelectorAll('.row').forEach(r =>
    r.onclick = () => { selected = rows[+r.dataset.i].id; renderList(); renderDetail(); });
}

function renderDetail() {
  const m = DATA.messages.find(x => x.id === selected);
  const el = document.getElementById('detail');
  if (!m) {
    el.innerHTML = '<div class="empty">Select a message to see why it was judged that way.</div>';
    return;
  }
  const risks = m.findings.filter(f => !f.mitigating);
  const good = m.findings.filter(f => f.mitigating);
  const headline = risks.length ? risks[0].text
    : (good.length ? good[0].text : 'No verdict recorded for this message.');

  const card = f => `
    <div class="finding f-${f.severity} ${f.mitigating ? 'good' : ''}">
      <div class="ftop">
        <span class="tag">L${f.layer}</span>
        <span class="tag">${f.mitigating ? 'in favour' : esc(f.severity)}</span>
        <span class="code">${esc(f.code)}</span>
      </div>
      <div class="ftext">${esc(f.text)}</div>
      ${Object.keys(f.evidence || {}).length ? `<details><summary>evidence</summary>
        <pre>${esc(JSON.stringify(f.evidence, null, 2))}</pre></details>` : ''}
    </div>`;

  el.innerHTML = `
    <span class="badge t-${m.tier}" style="width:auto;padding:4px 12px">${
      m.tier === 'unscored' ? 'not analysed' : m.tier}</span>
    ${m.tier !== 'unscored' ? `<span class="code" style="margin-left:10px">score ${
      m.score.toFixed(2)} · ${esc(m.model)}</span>` : ''}
    <div class="headline">${esc(headline)}</div>
    <div class="meta">from <b>${esc(m.from_display)}</b> &lt;${esc(m.from_addr)}&gt;</div>
    <div class="meta">subject <b>${esc(m.subject)}</b></div>
    <div class="meta">received <b>${esc(m.date)}</b></div>
    ${risks.length ? `<h3>why it was flagged</h3>${risks.map(card).join('')}` : ''}
    ${good.length ? `<h3>what argued the other way</h3>${good.map(card).join('')}` : ''}
    ${m.preview ? `<h3>message</h3><div class="body-preview">${esc(m.preview)}</div>` : ''}`;
}

function renderTallies() {
  const order = ['danger', 'caution', 'safe', 'unscored'];
  const el = document.getElementById('tallies');
  el.innerHTML = [['all', DATA.messages.length]].concat(
      order.filter(t => DATA.counts[t]).map(t => [t, DATA.counts[t]]))
    .map(([t, n]) => `<button class="tally" data-t="${t}" aria-pressed="${
      (filter || 'all') === t}"><b>${n}</b> ${t}</button>`).join('');
  el.querySelectorAll('.tally').forEach(b => b.onclick = () => {
    filter = b.dataset.t === 'all' ? null : b.dataset.t;
    selected = null; renderTallies(); renderList(); renderDetail();
  });
}

renderTallies(); renderList(); renderDetail();
"""


def render(data: dict[str, Any]) -> str:
    payload = json.dumps(data).replace("</", "<\\/")
    stats = data["stats"]
    profiles = "".join(
        f"<div class='meta'><b>{html.escape(p['canonical_email'])}</b> — "
        f"{p['samples']} messages, {p['style_samples'] or 0} style samples</div>"
        for p in data["profiles"]
    ) or "<div class='meta'>No fingerprints built yet — run <code>phishguard profile</code>.</div>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishGuard — {html.escape(data['account'])}</title>
<style>{CSS}</style></head>
<body>
<header>
  <h1>PhishGuard</h1>
  <div class="sub">{html.escape(data['account'])} · {stats['messages']:,} messages ·
    {stats['contacts']:,} contacts · generated {data['generated']}</div>
  <div class="tallies" id="tallies"></div>
</header>
<div class="wrap">
  <div id="list" role="listbox"></div>
  <div id="detail"></div>
</div>
<div style="padding:18px 26px;border-top:1px solid var(--line)">
  <h3>sender fingerprints</h3>{profiles}
</div>
<script>{JS.replace('__DATA__', payload)}</script>
</body></html>"""


def write(store: Store, account_id: int, out_path: Path, limit: int = 200) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render(collect(store, account_id, limit)), encoding="utf-8")
    return out_path
