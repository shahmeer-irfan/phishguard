"""Orchestration: run the layers, fuse, persist.

Analysis reads stored columns rather than re-parsing raw bytes, so a full pass
over a 15k-message mailbox is seconds rather than minutes. The raw bytes stay
on disk for the layers that will need them (Phase 2 onwards).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..db.store import Store
from ..parse.message import ParsedMessage
from .base import Finding
from .context import AnalysisContext, build_context
from .scoring import MODEL_VERSION, Verdict, fuse
from .view import MessageView
from . import intent as INTENT
from . import layer0, layer1, layer2, layer3

ProgressFn = Callable[[int, int], None]

# Billable Layer-4 calls in this process. Module-level because `analyse` is a
# free function by design - it stays pure apart from this one counter, which
# exists so the CLI can report what a run actually cost.
_LLM_CALLS = {"n": 0}


@dataclass
class AnalysisReport:
    analysed: int = 0
    skipped: int = 0
    llm_calls: int = 0
    tiers: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    seconds: float = 0.0

    def __str__(self) -> str:
        tiers = "  ".join(f"{k}={v}" for k, v in sorted(self.tiers.items()))
        tail = f", {len(self.errors)} errors" if self.errors else ""
        llm = f", {self.llm_calls} llm calls" if self.llm_calls else ""
        return (f"{self.analysed} analysed ({tiers}), {self.skipped} skipped{llm}{tail} "
                f"in {self.seconds:.1f}s")


def analyse(view: MessageView, ctx: AnalysisContext,
            intent_client: "INTENT.IntentClient | None" = None) -> Verdict:
    """Run every layer over one message.

    The rule layers are pure and local. Layer 4 is neither, so it runs in a
    second pass and only when the first pass landed in the ambiguous band -
    that gate is what keeps the cost, the latency and the amount of mail
    leaving the device all proportionate.
    """
    findings: list[Finding] = []
    findings += layer0.run(view, ctx)
    findings += layer1.run(view, ctx)
    findings += layer2.run(view, ctx)
    findings += layer3.run(view, ctx)
    verdict = fuse(findings)

    if intent_client is None or not INTENT.in_band(verdict.score):
        return verdict

    result = intent_client.classify(view, ctx)
    if not result.cached:
        _LLM_CALLS["n"] += 1
    extra = INTENT.to_findings(result)
    if not extra:
        return verdict
    return fuse(findings + extra)


def analyse_local(parsed: ParsedMessage, ctx: AnalysisContext | None = None) -> Verdict:
    """Offline path for a single .eml.

    Without a contact graph only Layer 0 has anything to compare against, so
    identity findings will be absent - not negative. The CLI says so explicitly
    rather than presenting a hollow 'safe'.
    """
    return analyse(MessageView.from_parsed(parsed), ctx or AnalysisContext(account_id=0))


class Engine:
    def __init__(self, store: Store, account_id: int, ctx: AnalysisContext | None = None,
                 intent_client: "INTENT.IntentClient | None" = None):
        self.store = store
        self.account_id = account_id
        self.ctx = ctx or build_context(store, account_id)
        self.intent_client = intent_client

    # ------------------------------------------------------------- one-shot

    def view_for(self, row: Any) -> MessageView:
        auth = self.store.conn.execute(
            "SELECT * FROM auth_results WHERE message_id = ?", (row["id"],)
        ).fetchone()
        hops = self.store.conn.execute(
            "SELECT * FROM received_hops WHERE message_id = ? ORDER BY hop_index",
            (row["id"],),
        ).fetchall()
        atts = self.store.conn.execute(
            "SELECT * FROM attachments WHERE message_id = ?", (row["id"],)
        ).fetchall()
        message_id = row["id"]
        return MessageView.from_db(
            row, auth, hops, atts,
            raw_loader=lambda: self.store.raw_message(message_id),
        )

    def analyse_row(self, row: Any) -> Verdict:
        return analyse(self.view_for(row), self.ctx, self.intent_client)

    def persist(self, message_id: int, verdict: Verdict) -> int:
        """Replace any previous verdict for this message. Findings cascade."""
        self.store.conn.execute("DELETE FROM verdicts WHERE message_id = ?", (message_id,))
        cur = self.store.conn.execute(
            """INSERT INTO verdicts (message_id, tier, score, model_version, created_at)
               VALUES (?,?,?,?,?)""",
            (message_id, verdict.tier.value, verdict.score, verdict.model_version,
             datetime.now(timezone.utc).isoformat()),
        )
        verdict_id = int(cur.lastrowid)
        if verdict.findings:
            self.store.conn.executemany(
                """INSERT INTO findings (
                       verdict_id, layer, code, severity, weight, evidence_json, human_text)
                   VALUES (?,?,?,?,?,?,?)""",
                [(verdict_id, f.layer, f.code, f.severity.value,
                  -f.weight if f.mitigating else f.weight,
                  json.dumps(f.evidence, default=str), f.human_text)
                 for f in verdict.findings],
            )
        return verdict_id

    # ---------------------------------------------------------------- bulk

    def _should_skip(self, row: Any) -> bool:
        """Never judge the user's own outbound mail.

        SENT messages exist in the store to build the trust graph, not to be
        scored. Analysing them would flood every report with the user
        'impersonating' themselves.
        """
        try:
            labels = json.loads(row["labels_json"] or "[]")
        except (TypeError, ValueError):
            labels = []
        if "SENT" in labels or "DRAFT" in labels:
            return True
        return self.ctx.is_own_address(row["from_addr"] or "")

    def analyse_pending(
        self, limit: int | None = None, redo: bool = False,
        progress: ProgressFn | None = None,
    ) -> AnalysisReport:
        started = time.monotonic()
        report = AnalysisReport()

        where = "m.account_id = ?"
        if not redo:
            # Re-score anything judged by an older ruleset: a verdict is only
            # meaningful relative to the model that produced it.
            where += (" AND (v.id IS NULL OR v.model_version != '" + MODEL_VERSION + "')")
        sql = (f"SELECT m.* FROM messages m LEFT JOIN verdicts v ON v.message_id = m.id "
               f"WHERE {where} ORDER BY m.received_at DESC")
        params: list[Any] = [self.account_id]
        if limit:
            sql += " LIMIT ?"
            params.append(limit)

        rows = self.store.conn.execute(sql, params).fetchall()
        total = len(rows)
        _LLM_CALLS["n"] = 0

        self.store.conn.execute("BEGIN")
        try:
            for i, row in enumerate(rows, 1):
                if self._should_skip(row):
                    report.skipped += 1
                    continue
                try:
                    view = self.view_for(row)
                    verdict = analyse(view, self.ctx, self.intent_client)
                    self.persist(row["id"], verdict)
                    self.store.replace_links(row["id"], layer3.extract_links(view))
                except Exception as exc:
                    report.errors.append(f"{row['gmail_id']}: {type(exc).__name__}: {exc}")
                    continue
                report.analysed += 1
                report.tiers[verdict.tier.value] = report.tiers.get(verdict.tier.value, 0) + 1
                if progress and i % 200 == 0:
                    progress(i, total)
            self.store.conn.execute("COMMIT")
        except BaseException:
            self.store.conn.execute("ROLLBACK")
            raise

        if progress:
            progress(total, total)
        report.llm_calls = _LLM_CALLS["n"]
        report.seconds = time.monotonic() - started
        return report

    # -------------------------------------------------------------- queries

    def verdict_for(self, gmail_id: str) -> dict[str, Any] | None:
        row = self.store.conn.execute(
            """SELECT v.*, m.subject, m.from_addr, m.from_display, m.received_at, m.gmail_id
               FROM verdicts v JOIN messages m ON m.id = v.message_id
               WHERE m.account_id = ? AND m.gmail_id = ?""",
            (self.account_id, gmail_id),
        ).fetchone()
        if not row:
            return None
        findings = self.store.conn.execute(
            "SELECT * FROM findings WHERE verdict_id = ? ORDER BY ABS(weight) DESC",
            (row["id"],),
        ).fetchall()
        return {**dict(row), "findings": [dict(f) for f in findings]}

    def flagged(self, tier: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        sql = ("""SELECT v.tier, v.score, m.gmail_id, m.subject, m.from_display,
                         m.from_addr, m.received_at
                  FROM verdicts v JOIN messages m ON m.id = v.message_id
                  WHERE m.account_id = ?""")
        params: list[Any] = [self.account_id]
        if tier:
            sql += " AND v.tier = ?"
            params.append(tier)
        else:
            sql += " AND v.tier != 'safe'"
        sql += " ORDER BY v.score DESC, m.received_at DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.store.conn.execute(sql, params)]

    def summary(self) -> dict[str, Any]:
        tiers = {r["tier"]: r["n"] for r in self.store.conn.execute(
            """SELECT v.tier, COUNT(*) n FROM verdicts v
               JOIN messages m ON m.id = v.message_id
               WHERE m.account_id = ? GROUP BY v.tier""", (self.account_id,))}
        codes = [dict(r) for r in self.store.conn.execute(
            """SELECT f.code, f.severity, COUNT(*) n FROM findings f
               JOIN verdicts v ON v.id = f.verdict_id
               JOIN messages m ON m.id = v.message_id
               WHERE m.account_id = ? AND f.weight > 0
               GROUP BY f.code ORDER BY n DESC LIMIT 20""", (self.account_id,))]
        return {"tiers": tiers, "top_codes": codes}
