"""Run Layer 4 over a handful of real messages and show what came back.

Exists to answer four questions that no offline test can:
  - does the request shape the SDK actually wants match what we send
  - does redaction hold on real bodies, not fixtures
  - is the model's judgement calibrated, or does it cry wolf
  - what does a call really cost

Deliberately capped and explicit about spend, because every run here is real
money against a real key.

    ANTHROPIC_API_KEY=... python tools/try_layer4.py --limit 5
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard import config as C
from phishguard.db.store import Store
from phishguard.detect import intent
from phishguard.detect.context import build_context
from phishguard.detect.engine import Engine, analyse
from phishguard.detect.redact import leaks

# Opus 5 list price, $/million tokens.
IN_PER_M, OUT_PER_M = 5.0, 25.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=5)
    ap.add_argument("--effort", default="low",
                    choices=["low", "medium", "high", "xhigh", "max"])
    args = ap.parse_args()

    if not intent.available():
        print("anthropic SDK not installed", file=sys.stderr)
        return 2

    store = Store(C.load().db_path)
    account = store.conn.execute("SELECT id FROM accounts LIMIT 1").fetchone()["id"]
    ctx = build_context(store, account)
    engine = Engine(store, account, ctx)

    rows = store.conn.execute(
        """SELECT m.* FROM messages m JOIN verdicts v ON v.message_id = m.id
           WHERE m.account_id = ? AND v.score BETWEEN ? AND ?
           ORDER BY v.score DESC LIMIT ?""",
        (account, intent.LLM_BAND_LOW, intent.LLM_BAND_HIGH, args.limit),
    ).fetchall()

    if not rows:
        print("no messages in the ambiguous band")
        return 0

    client = intent.IntentClient(store=store, effort=args.effort)
    tok_in = tok_out = 0
    print(f"{len(rows)} messages, effort={args.effort}, model={intent.MODEL}\n")

    for row in rows:
        view = engine.view_for(row)
        before = analyse(view, ctx)

        # Check redaction against the real body before it goes anywhere.
        prompt = intent.build_user_prompt(view, ctx)
        escaped = leaks(view.body_text or "", prompt)

        result = client.classify(view, ctx)
        tok_in += result.input_tokens
        tok_out += result.output_tokens

        after = analyse(view, ctx, client)
        d = result.data

        print(f"  from     {(view.from_display or view.from_addr)[:46]}")
        print(f"  subject  {view.subject[:66]}")
        print(f"  rules    {before.tier.value} {before.score:.2f}"
              f"   ->  with layer 4: {after.tier.value} {after.score:.2f}")
        if result.error:
            print(f"  ERROR    {result.error}")
        else:
            print(f"  intent   {d.get('intent')} (confidence {d.get('confidence')})"
                  f"  urgency={d.get('urgency')}"
                  f"  injection={d.get('prompt_injection_attempt')}")
            print(f"  reason   {str(d.get('one_line_reason', ''))[:88]}")
        if escaped:
            print(f"  !! REDACTION LEAK: {escaped[:3]}")
        print()

    cost = (tok_in * IN_PER_M + tok_out * OUT_PER_M) / 1_000_000
    print(f"tokens: {tok_in:,} in / {tok_out:,} out")
    print(f"cost:   ${cost:.4f} for {len(rows)} messages "
          f"(${cost / max(len(rows), 1) * 270:.2f} to do all 270 in the band)")
    store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
