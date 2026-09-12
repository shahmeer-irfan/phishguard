"""Backfill and incremental sync.

Threading model: worker threads fetch and parse (network-bound, and parsing is
cheap), the calling thread does every database write. SQLite connections are not
safely shared across threads and a single writer is fast enough - the bottleneck
is Gmail's quota, not disk.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from ..config import MAX_CONCURRENT_FETCHES, STORE_RAW, STORE_RAW_MAX_BYTES
from ..db.store import Store
from ..parse import headers as H
from ..parse.message import parse_rfc822
from .client import GmailClient, HistoryTooOld

log = logging.getLogger("phishguard.sync")

ProgressFn = Callable[[str, int, int], None]


@dataclass
class SyncReport:
    fetched: int = 0
    skipped: int = 0
    deleted: int = 0
    relabelled: int = 0
    errors: list[str] = field(default_factory=list)
    seconds: float = 0.0

    def __str__(self) -> str:
        parts = [f"{self.fetched} new", f"{self.skipped} already stored"]
        if self.deleted:
            parts.append(f"{self.deleted} deleted")
        if self.relabelled:
            parts.append(f"{self.relabelled} relabelled")
        if self.errors:
            parts.append(f"{len(self.errors)} errors")
        return f"{', '.join(parts)} in {self.seconds:.1f}s"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Syncer:
    def __init__(self, store: Store, client: GmailClient, account_id: int):
        self.store = store
        self.client = client
        self.account_id = account_id

    # --------------------------------------------------------------- fetch

    def _fetch_and_parse(self, gmail_id: str) -> tuple[dict, Any, bytes | None] | None:
        msg = self.client.get_raw(gmail_id)
        if msg is None:
            return None
        raw = msg.pop("raw", b"")
        parsed = parse_rfc822(raw)
        msg["received_at"] = H.epoch_ms_to_iso(msg.get("internalDate")) or parsed.date_iso
        keep = raw if (STORE_RAW and len(raw) <= STORE_RAW_MAX_BYTES) else None
        return msg, parsed, keep

    def _ingest_ids(self, ids: list[str], report: SyncReport, progress: ProgressFn | None,
                    phase: str, done_so_far: int, total: int) -> int:
        """Fetch `ids` in parallel, write them serially. Returns count written."""
        if not ids:
            return 0

        written = 0
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_FETCHES) as pool:
            futures = {pool.submit(self._fetch_and_parse, gid): gid for gid in ids}
            self.store.conn.execute("BEGIN")
            try:
                for future in futures:
                    gid = futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        report.errors.append(f"{gid}: {type(exc).__name__}: {exc}")
                        continue
                    if result is None:
                        continue
                    meta, parsed, raw = result
                    try:
                        self.store.upsert_message(self.account_id, meta, parsed, raw)
                    except Exception as exc:
                        report.errors.append(f"{gid}: store: {type(exc).__name__}: {exc}")
                        continue
                    written += 1
                    report.fetched += 1
                    if progress and written % 25 == 0:
                        progress(phase, done_so_far + written, total)
                self.store.conn.execute("COMMIT")
            except BaseException:
                self.store.conn.execute("ROLLBACK")
                raise
        if progress:
            progress(phase, done_so_far + written, total)
        return written

    # ------------------------------------------------------------ backfill

    def backfill(self, labels: list[str], progress: ProgressFn | None = None,
                 max_messages: int | None = None) -> SyncReport:
        """Index history for the given labels.

        The history watermark is captured *before* listing starts. Anything that
        arrives during a long backfill is then picked up by the next incremental
        run; taking the watermark afterwards would silently drop that window.
        """
        started = time.monotonic()
        report = SyncReport()

        watermark = self.client.profile().get("historyId")
        state = self.store.sync_state(self.account_id)
        cursor = state.get("backfill_cursor")

        for label in labels:
            page_token = cursor if (cursor and label == labels[0]) else None
            cursor = None
            for ids, next_token in self.client.list_message_ids(
                label_ids=[label], page_token=page_token
            ):
                if not ids:
                    self.store.update_sync_state(self.account_id, backfill_cursor=next_token)
                    continue

                known = self.store.existing_gmail_ids(self.account_id, ids)
                todo = [i for i in ids if i not in known]
                report.skipped += len(ids) - len(todo)

                if max_messages is not None:
                    remaining = max_messages - report.fetched
                    if remaining <= 0:
                        report.seconds = time.monotonic() - started
                        return report
                    todo = todo[:remaining]

                self._ingest_ids(todo, report, progress, f"backfill:{label}",
                                 report.fetched, report.fetched + len(todo))
                self.store.update_sync_state(self.account_id, backfill_cursor=next_token)

        self.store.update_sync_state(
            self.account_id, backfill_done=1, backfill_cursor=None,
            last_sync_at=_now(), last_error=None,
        )
        self.store.advance_history_id(self.account_id, watermark)
        report.seconds = time.monotonic() - started
        return report

    # --------------------------------------------------------- incremental

    def incremental(self, progress: ProgressFn | None = None) -> SyncReport:
        """Apply changes since the stored watermark."""
        started = time.monotonic()
        report = SyncReport()
        state = self.store.sync_state(self.account_id)
        start_id = state.get("history_id")

        if not start_id:
            report.errors.append("no history watermark; run backfill first")
            report.seconds = time.monotonic() - started
            return report

        added: list[str] = []
        label_changes: dict[str, list[str]] = {}
        deleted: list[str] = []
        newest = start_id

        try:
            for page in self.client.history(start_id):
                newest = page.get("historyId", newest)
                for record in page.get("history", []):
                    for item in record.get("messagesAdded", []):
                        added.append(item["message"]["id"])
                    for item in record.get("messagesDeleted", []):
                        deleted.append(item["message"]["id"])
                    # Gmail reports the message's full label set on a change,
                    # so the last record seen for an id wins - no set algebra.
                    for key in ("labelsAdded", "labelsRemoved"):
                        for item in record.get(key, []):
                            msg = item["message"]
                            label_changes[msg["id"]] = msg.get("labelIds", [])
        except HistoryTooOld as exc:
            log.warning("%s - falling back to a recent-window resync", exc)
            self.store.update_sync_state(self.account_id, last_error=str(exc))
            return self._resync_recent(progress, report, started)

        added = [i for i in dict.fromkeys(added) if i not in set(deleted)]
        known = self.store.existing_gmail_ids(self.account_id, added)
        todo = [i for i in added if i not in known]
        report.skipped += len(added) - len(todo)

        self._ingest_ids(todo, report, progress, "incremental", 0, len(todo))

        self.store.conn.execute("BEGIN")
        try:
            for gid in deleted:
                self.store.delete_message(self.account_id, gid)
                report.deleted += 1
            for gid, labels in label_changes.items():
                if gid in known or gid in todo or self.store.has_message(self.account_id, gid):
                    self.store.set_labels(self.account_id, gid, labels)
                    report.relabelled += 1
            self.store.conn.execute("COMMIT")
        except BaseException:
            self.store.conn.execute("ROLLBACK")
            raise

        self.store.advance_history_id(self.account_id, newest)
        self.store.update_sync_state(self.account_id, last_sync_at=_now(), last_error=None)
        report.seconds = time.monotonic() - started
        return report

    def _resync_recent(self, progress: ProgressFn | None, report: SyncReport,
                       started: float, days: int = 30) -> SyncReport:
        """Recovery path when the history watermark has expired.

        Re-lists a recent window rather than the whole mailbox: everything older
        is already stored and immutable for our purposes.
        """
        watermark = self.client.profile().get("historyId")
        query = f"newer_than:{days}d"
        for ids, _ in self.client.list_message_ids(query=query):
            known = self.store.existing_gmail_ids(self.account_id, ids)
            todo = [i for i in ids if i not in known]
            report.skipped += len(ids) - len(todo)
            self._ingest_ids(todo, report, progress, "resync", 0, len(todo))

        self.store.advance_history_id(self.account_id, watermark)
        self.store.update_sync_state(self.account_id, last_sync_at=_now())
        report.seconds = time.monotonic() - started
        return report
