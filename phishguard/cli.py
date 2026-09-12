"""Command line entry point.

    phishguard auth                 one-time Google consent
    phishguard backfill [--max N]   index history (INBOX, SPAM, SENT)
    phishguard sync                 apply changes since the last run
    phishguard watch [--interval S] poll forever
    phishguard stats                what is in the local store
    phishguard contacts [-n N]      the contact graph, by affinity
    phishguard show <gmail_id>      dump one stored message
    phishguard inspect <file.eml>   parse a local .eml, no network, no database

    phishguard profile [--rebuild]  build per-contact sender fingerprints
    phishguard analyze [--llm]      score stored mail: safe / caution / danger
    phishguard report [--tier T]    everything currently flagged
    phishguard verdict <gmail_id>   why one message was judged the way it was
    phishguard evaluate             precision/recall against synthetic attacks
    phishguard view                 render the mailbox as an HTML page
    phishguard security             what protection is actually in force
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

from . import config as C
from .db.store import Store
from .parse.message import parse_rfc822


def _reconfigure_stdio() -> None:
    """Force UTF-8 output.

    Windows consoles default to cp1252, and a single emoji in a subject line -
    which real mail is full of - raises UnicodeEncodeError and kills the whole
    command. Replacing unencodable characters is always better than losing the
    report.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _log_setup(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # These libraries log a wall of noise at INFO.
    for noisy in ("googleapiclient", "google_auth_httplib2", "urllib3", "google.auth"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


GOOGLE_DEPS_HELP = """The Google client libraries are not installed. From the project directory:

    pip install -r requirements.txt

Everything that works offline - inspect, and the detection layers themselves -
needs none of this; only the commands that talk to Gmail do."""


def _require_google() -> None:
    """Turn a missing optional dependency into an instruction.

    This is the first command a new user runs, and an ImportError traceback is
    a poor way to learn that a pip install was skipped.
    """
    try:
        import google.auth  # noqa: F401
        import googleapiclient  # noqa: F401
    except ImportError:
        raise SystemExit(GOOGLE_DEPS_HELP)


def _connect(cfg: C.Config, interactive: bool = True):
    """Build (store, syncer, account_id). Imported lazily so the offline
    commands work without the Google client libraries installed."""
    _require_google()
    from .gmail.auth import load_credentials
    from .gmail.client import GmailClient
    from .gmail.sync import Syncer

    creds = load_credentials(cfg, interactive=interactive)
    client = GmailClient(creds)
    email = client.profile().get("emailAddress", "unknown")
    store = Store(cfg.db_path)
    account_id = store.get_or_create_account(email)
    return store, Syncer(store, client, account_id), account_id, email


def _progress(phase: str, done: int, total: int) -> None:
    total_s = str(total) if total else "?"
    sys.stderr.write(f"\r  {phase}: {done}/{total_s}   ")
    sys.stderr.flush()


_COLOUR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_TIER_STYLE = {
    "safe":    ("\033[32m", "ok"),
    "caution": ("\033[33m", "CAUTION"),
    "danger":  ("\033[31m", "DANGER"),
}


def _tier_label(tier: str) -> str:
    colour, label = _TIER_STYLE.get(tier, ("", tier))
    return f"{colour}{label}\033[0m" if _COLOUR else label


def _print_findings(findings: list[dict]) -> None:
    """Risk first, then what argued the other way.

    Negative stored weights mark mitigating findings - the evidence that
    *reduced* the score. Showing them matters: a user who only ever sees
    accusations has no way to calibrate trust in the tool.
    """
    risks = [f for f in findings if (f["weight"] or 0) > 0]
    eases = [f for f in findings if (f["weight"] or 0) <= 0]
    for f in risks:
        print(f"  [L{f['layer']}] {f['severity'].upper():<8} {f['code']}")
        print(f"         {f['human_text']}")
    for f in eases:
        print(f"  [L{f['layer']}] in favour  {f['code']}")
        print(f"         {f['human_text']}")


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


# ------------------------------------------------------------------ commands

def cmd_auth(args, cfg: C.Config) -> int:
    _require_google()
    from .gmail.auth import AuthError, load_credentials
    from .gmail.client import GmailClient

    try:
        creds = load_credentials(cfg)
    except AuthError as exc:
        print(exc, file=sys.stderr)
        return 2
    profile = GmailClient(creds).profile()
    store = Store(cfg.db_path)
    store.get_or_create_account(profile["emailAddress"])
    store.close()
    print(f"authorised: {profile['emailAddress']}")
    print(f"  {profile.get('messagesTotal', '?')} messages, "
          f"{profile.get('threadsTotal', '?')} threads in the mailbox")
    print(f"  token:    {cfg.token_path}")
    print(f"  database: {cfg.db_path}")
    return 0


def cmd_backfill(args, cfg: C.Config) -> int:
    store, syncer, account_id, email = _connect(cfg)
    labels = args.labels.split(",") if args.labels else C.BACKFILL_LABELS
    print(f"backfilling {email}: {', '.join(labels)}")
    try:
        report = syncer.backfill(labels, progress=_progress, max_messages=args.max)
    finally:
        sys.stderr.write("\n")
    print(report)
    for err in report.errors[:10]:
        print(f"  ! {err}", file=sys.stderr)
    if len(report.errors) > 10:
        print(f"  ! ... and {len(report.errors) - 10} more", file=sys.stderr)
    store.close()
    return 0


def cmd_sync(args, cfg: C.Config) -> int:
    store, syncer, account_id, email = _connect(cfg, interactive=False)
    if not store.sync_state(account_id).get("backfill_done"):
        print("backfill has not completed; run: phishguard backfill", file=sys.stderr)
        store.close()
        return 2
    try:
        report = syncer.incremental(progress=_progress)
    finally:
        sys.stderr.write("\n")
    print(report)
    store.close()
    return 0


def cmd_watch(args, cfg: C.Config) -> int:
    """Poll on an interval.

    Gmail supports push via Cloud Pub/Sub, but that needs a public endpoint -
    which a local-first desktop app deliberately does not have. Polling every
    30-60s costs one quota unit per call and is entirely adequate.
    """
    store, syncer, account_id, email = _connect(cfg, interactive=False)
    print(f"watching {email} every {args.interval}s (ctrl-c to stop)")
    try:
        while True:
            try:
                report = syncer.incremental()
                if report.fetched or report.deleted or report.relabelled:
                    print(f"  {report}")
            except Exception as exc:
                logging.getLogger("phishguard").warning("sync failed: %s", exc)
                store.update_sync_state(account_id, last_error=str(exc))
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped")
    store.close()
    return 0


def cmd_stats(args, cfg: C.Config) -> int:
    if not cfg.db_path.exists():
        print("no database yet; run: phishguard auth && phishguard backfill", file=sys.stderr)
        return 2
    store = Store(cfg.db_path)
    rows = store.conn.execute("SELECT id, email FROM accounts").fetchall()
    if not rows:
        print("no accounts", file=sys.stderr)
        return 2
    for row in rows:
        s = store.stats(row["id"])
        state = store.sync_state(row["id"])
        print(f"{row['email']}")
        print(f"  messages      {s['messages']:,}  ({s['parse_errors']} parse errors, "
              f"{s['with_raw']:,} with raw kept)")
        print(f"  contacts      {s['contacts']:,}")
        print(f"  range         {(s['oldest'] or '-')[:10]} .. {(s['newest'] or '-')[:10]}")
        print(f"  database      {_human_bytes(s['db_bytes'])}")
        print(f"  backfill      {'done' if state.get('backfill_done') else 'incomplete'}"
              f"   watermark {state.get('history_id') or '-'}")
        if state.get("last_error"):
            print(f"  last error    {state['last_error']}")
        breakdown = store.auth_breakdown(row["id"])
        if breakdown:
            print("  DMARC         " + "  ".join(f"{b['dmarc']}={b['n']:,}" for b in breakdown))
    store.close()
    return 0


def cmd_contacts(args, cfg: C.Config) -> int:
    store = Store(cfg.db_path)
    row = store.conn.execute("SELECT id FROM accounts LIMIT 1").fetchone()
    if not row:
        print("no accounts", file=sys.stderr)
        return 2
    print(f"{'in':>6} {'out':>6}  {'contact':<44} names")
    for c in store.top_contacts(row["id"], limit=args.number):
        names = ", ".join(json.loads(c["display_names_json"])[:2])
        print(f"{c['inbound_count']:>6} {c['outbound_count']:>6}  "
              f"{c['canonical_email'][:44]:<44} {names[:40]}")
    store.close()
    return 0


def cmd_show(args, cfg: C.Config) -> int:
    store = Store(cfg.db_path)
    row = store.conn.execute(
        "SELECT * FROM messages WHERE gmail_id = ? OR id = ?",
        (args.message_id, args.message_id if args.message_id.isdigit() else -1),
    ).fetchone()
    if not row:
        print("not found", file=sys.stderr)
        return 2

    print(f"gmail_id     {row['gmail_id']}")
    print(f"received     {row['received_at']}")
    print(f"from         {row['from_display']!r} <{row['from_addr']}>")
    if row["reply_to_addr"] and row["reply_to_addr"] != row["from_addr"]:
        print(f"reply-to     {row['reply_to_addr']}          <-- differs from From")
    if row["return_path_addr"] and row["return_path_addr"] != row["from_addr"]:
        print(f"return-path  {row['return_path_addr']}       <-- differs from From")
    print(f"subject      {row['subject']}")
    print(f"labels       {', '.join(json.loads(row['labels_json'] or '[]'))}")
    print(f"x-mailer     {row['x_mailer'] or row['user_agent'] or '-'}")
    print(f"mime         {row['mime_signature']}")
    print(f"hdr-order    {row['header_order_hash']}")
    print(f"tz offset    {row['date_tz_offset']}")

    auth = store.conn.execute(
        "SELECT * FROM auth_results WHERE message_id = ?", (row["id"],)
    ).fetchone()
    if auth:
        print(f"auth         spf={auth['spf']} ({auth['spf_domain']})  "
              f"dkim={auth['dkim']} (d={auth['dkim_domain']})  "
              f"dmarc={auth['dmarc']}  arc={'yes' if auth['arc_present'] else 'no'}")

    hops = store.conn.execute(
        "SELECT * FROM received_hops WHERE message_id = ? ORDER BY hop_index", (row["id"],)
    ).fetchall()
    if hops:
        print("hops         (0 = closest to us, highest = claimed origin)")
        for h in hops:
            print(f"  [{h['hop_index']}] from {h['from_host'] or '?'} "
                  f"[{h['from_ip'] or '?'}] by {h['by_host'] or '?'} {h['with_proto'] or ''}")

    atts = store.conn.execute(
        "SELECT * FROM attachments WHERE message_id = ?", (row["id"],)
    ).fetchall()
    for a in atts:
        print(f"attachment   {a['filename'] or '(unnamed)'}  {a['content_type']}  "
              f"{a['size_bytes']}B  sha256={a['sha256'][:16]}")

    verdict = store.conn.execute(
        "SELECT * FROM verdicts WHERE message_id = ?", (row["id"],)
    ).fetchone()
    if verdict:
        print(f"verdict      {_tier_label(verdict['tier'])}  score {verdict['score']:.2f}")
        findings = store.conn.execute(
            "SELECT * FROM findings WHERE verdict_id = ? ORDER BY ABS(weight) DESC",
            (verdict["id"],),
        ).fetchall()
        _print_findings([dict(f) for f in findings])

    if args.body:
        print("-" * 60)
        print((row["body_text"] or row["body_html"] or "")[:4000])
    store.close()
    return 0


def cmd_inspect(args, cfg: C.Config) -> int:
    """Parse a local .eml with no network and no database.

    The fastest way to check the parser against a real phishing sample: in
    Gmail, Show original -> Download original, then point this at the file.
    """
    parsed = parse_rfc822(Path(args.path).read_bytes())

    if args.detect:
        from .detect.engine import analyse_local

        verdict = analyse_local(parsed)
        print(f"{_tier_label(verdict.tier.value)}  score {verdict.score:.2f}")
        print(f"  {verdict.headline}\n")
        _print_findings([{**f.as_row(), "weight": -f.weight if f.mitigating else f.weight}
                         for f in verdict.findings])
        print("\nNote: run without a mailbox, so only Layer 0 (protocol) applies.")
        print("Identity checks need the contact graph - they are absent here, not clean.")
        return 0

    out = {
        "from": {"display": parsed.from_display, "addr": parsed.from_addr},
        "reply_to": parsed.reply_to_addr,
        "return_path": parsed.return_path_addr,
        "subject": parsed.subject,
        "date": parsed.date_iso,
        "tz_offset_min": parsed.date_tz_offset,
        "message_id": parsed.rfc822_message_id,
        "x_mailer": parsed.x_mailer or parsed.user_agent,
        "mime_signature": parsed.mime_signature,
        "header_order_hash": parsed.header_order_hash,
        "auth": parsed.auth.__dict__ | {"raw": None},
        "hops": [h.__dict__ for h in parsed.hops],
        "attachments": [a.__dict__ for a in parsed.attachments],
        "body_text_chars": len(parsed.body_text),
        "body_html_chars": len(parsed.body_html),
        "parse_error": parsed.parse_error,
    }
    print(json.dumps(out, indent=2, default=str))
    return 0


# ---------------------------------------------------------------- detection

def _engine(cfg: C.Config):
    from .detect.engine import Engine

    store = Store(cfg.db_path)
    row = store.conn.execute("SELECT id FROM accounts LIMIT 1").fetchone()
    if not row:
        store.close()
        raise SystemExit("no accounts; run: phishguard auth && phishguard backfill")
    return store, Engine(store, row["id"]), row["id"]


def cmd_analyze(args, cfg: C.Config) -> int:
    store, engine, account_id = _engine(cfg)

    if args.llm:
        from .detect import intent

        if not intent.available():
            print("the `anthropic` package is not installed; run: pip install anthropic",
                  file=sys.stderr)
            store.close()
            return 2
        engine.intent_client = intent.IntentClient(store=store, effort=args.effort)
        print(f"layer 4 enabled: {intent.MODEL} at effort={args.effort}, "
              f"scores {intent.LLM_BAND_LOW}-{intent.LLM_BAND_HIGH} only")
        print("  message text leaves this machine for those messages (identifiers redacted)")

    if args.online:
        from .detect import intel
        from .detect.context import build_context

        print("looking up sender domain registration dates (RDAP)...")
        stats = intel.enrich_sender_domains(store, account_id, limit=args.intel_limit,
                                            progress=lambda i, n: _progress("rdap", i, n))
        sys.stderr.write("\n")
        print(f"  {stats['looked_up']} looked up, {stats['cached']} cached, "
              f"{stats['failed']} failed")
        engine.ctx = build_context(store, account_id)  # pick up the new intel

    print(f"contact graph: {len(engine.ctx.contacts)} contacts, "
          f"{len(engine.ctx.by_display_name)} reference names, "
          f"{len(engine.ctx.reference_domains)} reference domains")
    try:
        report = engine.analyse_pending(limit=args.limit, redo=args.redo,
                                        progress=lambda i, n: _progress("analyze", i, n))
    finally:
        sys.stderr.write("\n")
    print(report)
    for err in report.errors[:5]:
        print(f"  ! {err}", file=sys.stderr)
    store.close()
    return 0


def cmd_profile(args, cfg: C.Config) -> int:
    from .detect import profiles

    store, engine, account_id = _engine(cfg)
    print("building sender fingerprints from stored history...")
    try:
        report = profiles.build_all(store, account_id, rebuild=args.rebuild,
                                    progress=lambda i, n: _progress("profile", i, n))
    finally:
        sys.stderr.write("\n")
    print(report)
    if report.built:
        rows = store.conn.execute(
            """SELECT canonical_email, samples,
                      json_extract(style_json, '$.samples') AS style_samples
               FROM contact_profiles WHERE account_id = ?
               ORDER BY samples DESC LIMIT ?""",
            (account_id, args.number),
        ).fetchall()
        print(f"\n{'messages':>9} {'style':>6}  contact")
        for r in rows:
            print(f"{r['samples']:>9} {r['style_samples'] or 0:>6}  {r['canonical_email']}")
    store.close()
    return 0


def cmd_evaluate(args, cfg: C.Config) -> int:
    from .evaluate import harness

    store, engine, account_id = _engine(cfg)
    print("generating synthetic attacks against your own contact graph...")
    report = harness.full_report(store, account_id, engine.ctx,
                                 per_transform=args.per_transform,
                                 benign_limit=args.benign, seed=args.seed)
    if args.json:
        print(harness.to_json(report))
    else:
        print(harness.render(report))
    store.close()
    return 0


def cmd_view(args, cfg: C.Config) -> int:
    from . import viewer

    store, engine, account_id = _engine(cfg)
    out = Path(args.out) if args.out else cfg.home / "phishguard.html"
    viewer.write(store, account_id, out, limit=args.limit)
    store.close()
    print(f"wrote {out}")
    return 0


def cmd_security(args, cfg: C.Config) -> int:
    from . import security

    st = security.status()
    print(f"platform            {st['platform']}")
    print(f"keychain available  {'yes' if st['keychain_available'] else 'no'}")
    print(f"sqlcipher available {'yes' if st['sqlcipher_available'] else 'no'}")
    print(f"token storage       {st['token_backend']}")
    print(f"database encrypted  {'yes' if st['database_encrypted'] else 'NO'}")

    if args.migrate_token:
        moved = security.TokenStore(cfg.token_path).migrate_to_keychain()
        print(f"\ntoken migration     {'moved to keychain' if moved else 'nothing to move'}")

    if st["warnings"]:
        print()
        for w in st["warnings"]:
            print(f"  !  {w}")
    return 0


def cmd_report(args, cfg: C.Config) -> int:
    store, engine, _ = _engine(cfg)
    summary = engine.summary()
    tiers = summary["tiers"]
    if not tiers:
        print("nothing analysed yet; run: phishguard analyze", file=sys.stderr)
        store.close()
        return 2

    total = sum(tiers.values())
    print("verdicts: " + "   ".join(
        f"{_tier_label(t)} {tiers.get(t, 0):,} ({tiers.get(t, 0) / total:.1%})"
        for t in ("safe", "caution", "danger")))
    if summary["top_codes"]:
        print("\nmost common risk findings")
        for c in summary["top_codes"][:10]:
            print(f"  {c['n']:>6}  {c['severity']:<8} {c['code']}")

    rows = engine.flagged(tier=args.tier, limit=args.number)
    if rows:
        print(f"\nflagged messages ({len(rows)})")
        for r in rows:
            who = f"{r['from_display']} <{r['from_addr']}>" if r["from_display"] else r["from_addr"]
            print(f"  {_tier_label(r['tier']):<20} {r['score']:.2f}  {(r['received_at'] or '')[:10]}  "
                  f"{r['gmail_id']}")
            print(f"    {who[:76]}")
            print(f"    {(r['subject'] or '(no subject)')[:76]}")
    store.close()
    return 0


def cmd_verdict(args, cfg: C.Config) -> int:
    store, engine, _ = _engine(cfg)
    result = engine.verdict_for(args.message_id)
    if not result:
        print("no verdict for that message; run: phishguard analyze", file=sys.stderr)
        store.close()
        return 2

    who = (f"{result['from_display']} <{result['from_addr']}>"
           if result["from_display"] else result["from_addr"])
    print(f"{_tier_label(result['tier'])}   score {result['score']:.2f}   "
          f"model {result['model_version']}")
    print(f"from     {who}")
    print(f"subject  {result['subject']}")
    print(f"date     {result['received_at']}\n")
    _print_findings(result["findings"])
    store.close()
    return 0


# --------------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishguard", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("auth", help="one-time Google consent").set_defaults(fn=cmd_auth)

    b = sub.add_parser("backfill", help="index mailbox history")
    b.add_argument("--labels", help="comma separated, default INBOX,SPAM,SENT")
    b.add_argument("--max", type=int, help="stop after N new messages")
    b.set_defaults(fn=cmd_backfill)

    sub.add_parser("sync", help="apply changes since last run").set_defaults(fn=cmd_sync)

    w = sub.add_parser("watch", help="poll on an interval")
    w.add_argument("--interval", type=int, default=45)
    w.set_defaults(fn=cmd_watch)

    sub.add_parser("stats", help="what is in the local store").set_defaults(fn=cmd_stats)

    c = sub.add_parser("contacts", help="contact graph by affinity")
    c.add_argument("-n", "--number", type=int, default=30)
    c.set_defaults(fn=cmd_contacts)

    s = sub.add_parser("show", help="dump one stored message")
    s.add_argument("message_id")
    s.add_argument("--body", action="store_true")
    s.set_defaults(fn=cmd_show)

    i = sub.add_parser("inspect", help="parse a local .eml offline")
    i.add_argument("path")
    i.add_argument("--detect", action="store_true", help="also run Layer 0 detection")
    i.set_defaults(fn=cmd_inspect)

    a = sub.add_parser("analyze", help="score stored mail")
    a.add_argument("--limit", type=int, help="stop after N messages")
    a.add_argument("--redo", action="store_true", help="re-score everything")
    a.add_argument("--online", action="store_true",
                   help="look up sender domain ages via RDAP first")
    a.add_argument("--intel-limit", type=int, default=200,
                   help="max RDAP lookups per run (default 200)")
    a.add_argument("--llm", action="store_true",
                   help="enable Layer 4 intent analysis (sends ambiguous messages "
                        "to the Claude API, identifiers redacted)")
    a.add_argument("--effort", default="medium",
                   choices=["low", "medium", "high", "xhigh", "max"])
    a.set_defaults(fn=cmd_analyze)

    pr = sub.add_parser("profile", help="build per-contact sender fingerprints")
    pr.add_argument("--rebuild", action="store_true", help="rebuild even if current")
    pr.add_argument("-n", "--number", type=int, default=15)
    pr.set_defaults(fn=cmd_profile)

    ev = sub.add_parser("evaluate", help="precision/recall against synthetic attacks")
    ev.add_argument("--per-transform", type=int, default=20)
    ev.add_argument("--benign", type=int, default=300)
    ev.add_argument("--seed", type=int, default=20250909)
    ev.add_argument("--json", action="store_true")
    ev.set_defaults(fn=cmd_evaluate)

    vw = sub.add_parser("view", help="render the analysed mailbox as HTML")
    vw.add_argument("--out", help="output path (default: app-support dir)")
    vw.add_argument("--limit", type=int, default=200)
    vw.set_defaults(fn=cmd_view)

    sec = sub.add_parser("security", help="what protection is in force")
    sec.add_argument("--migrate-token", action="store_true",
                     help="move an on-disk OAuth token into the Keychain")
    sec.set_defaults(fn=cmd_security)

    r = sub.add_parser("report", help="everything currently flagged")
    r.add_argument("--tier", choices=["safe", "caution", "danger"])
    r.add_argument("-n", "--number", type=int, default=25)
    r.set_defaults(fn=cmd_report)

    vd = sub.add_parser("verdict", help="why one message was judged that way")
    vd.add_argument("message_id", help="gmail id")
    vd.set_defaults(fn=cmd_verdict)
    return p


def main(argv: list[str] | None = None) -> int:
    _reconfigure_stdio()
    args = build_parser().parse_args(argv)
    _log_setup(args.verbose)
    cfg = C.load()
    try:
        return args.fn(args, cfg)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
