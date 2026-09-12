"""Gmail API wrapper: retries, quota pacing, and raw message fetch.

Gmail allows 250 quota units per user per second. messages.get costs 5 units,
so ~50 fetches/second is the hard ceiling. We run well under it and let
exponential backoff absorb the rest - a backfill that finishes slightly slower
is strictly better than one that trips rate limiting halfway through.
"""

from __future__ import annotations

import base64
import random
import threading
import time
from typing import Any, Callable, Iterator

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from ..config import BACKFILL_PAGE_SIZE

RETRYABLE_STATUS = {403, 429, 500, 502, 503, 504}
MAX_RETRIES = 6


class HistoryTooOld(RuntimeError):
    """Gmail expired the startHistoryId. The only recovery is a full resync."""


def _is_retryable(err: HttpError) -> bool:
    status = getattr(err.resp, "status", None)
    if status not in RETRYABLE_STATUS:
        return False
    if status == 403:
        # 403 is overloaded: rate limiting is retryable, a permission problem
        # is not. Retrying a scope error forever would hide a real bug.
        reason = str(err)
        return "rateLimitExceeded" in reason or "userRateLimitExceeded" in reason
    return True


def _with_retry(fn: Callable[[], Any], what: str) -> Any:
    delay = 1.0
    for attempt in range(MAX_RETRIES):
        try:
            return fn()
        except HttpError as err:
            if not _is_retryable(err) or attempt == MAX_RETRIES - 1:
                raise
            # Full jitter: synchronised retries from parallel workers are what
            # turn a brief throttle into a sustained one.
            time.sleep(random.uniform(0, delay))
            delay = min(delay * 2, 32.0)
    raise RuntimeError(f"unreachable: {what}")


class GmailClient:
    def __init__(self, credentials):
        self._creds = credentials
        self._local = threading.local()

    @property
    def service(self):
        """googleapiclient service objects are not thread-safe, so each worker
        thread gets its own. They share the credentials object, which is."""
        svc = getattr(self._local, "svc", None)
        if svc is None:
            svc = build("gmail", "v1", credentials=self._creds, cache_discovery=False)
            self._local.svc = svc
        return svc

    # ------------------------------------------------------------- profile

    def profile(self) -> dict[str, Any]:
        return _with_retry(
            lambda: self.service.users().getProfile(userId="me").execute(), "getProfile"
        )

    # -------------------------------------------------------------- listing

    def list_message_ids(
        self,
        label_ids: list[str] | None = None,
        query: str | None = None,
        page_token: str | None = None,
    ) -> Iterator[tuple[list[str], str | None]]:
        """Yield (ids, next_page_token) per page so a backfill can checkpoint
        its cursor after every page and resume after a crash."""
        token = page_token
        while True:
            params: dict[str, Any] = {"userId": "me", "maxResults": BACKFILL_PAGE_SIZE}
            if label_ids:
                params["labelIds"] = label_ids
            if query:
                params["q"] = query
            if token:
                params["pageToken"] = token

            resp = _with_retry(
                lambda p=params: self.service.users().messages().list(**p).execute(),
                "messages.list",
            )
            ids = [m["id"] for m in resp.get("messages", [])]
            token = resp.get("nextPageToken")
            yield ids, token
            if not token:
                return

    # ---------------------------------------------------------------- fetch

    def get_raw(self, message_id: str) -> dict[str, Any] | None:
        """Fetch one message as raw RFC822 plus Gmail's own metadata.

        format='raw' is the whole point: it returns the bytes as they arrived,
        including every header. format='full' gives a parsed structure that has
        already thrown away header order and exact encoding - the two things
        Layer 2 fingerprinting depends on.
        """
        try:
            msg = _with_retry(
                lambda: self.service.users().messages()
                .get(userId="me", id=message_id, format="raw").execute(),
                "messages.get",
            )
        except HttpError as err:
            if getattr(err.resp, "status", None) == 404:
                return None  # deleted between listing and fetching
            raise

        raw_b64 = msg.get("raw")
        raw = base64.urlsafe_b64decode(raw_b64.encode("ascii")) if raw_b64 else b""
        return {
            "id": msg["id"],
            "threadId": msg.get("threadId"),
            "historyId": msg.get("historyId"),
            "labelIds": msg.get("labelIds", []),
            "snippet": msg.get("snippet"),
            "sizeEstimate": msg.get("sizeEstimate"),
            "internalDate": msg.get("internalDate"),
            "raw": raw,
        }

    # -------------------------------------------------------------- history

    def history(self, start_history_id: str, page_token: str | None = None) -> Iterator[dict]:
        """Yield history.list pages from a watermark.

        Raises HistoryTooOld if Gmail has aged out the id - the mailbox moved
        further than the retained history window (roughly a week of changes,
        but Google does not guarantee it), so a full resync is the only option.
        """
        token = page_token
        while True:
            params: dict[str, Any] = {
                "userId": "me",
                "startHistoryId": start_history_id,
                "historyTypes": ["messageAdded", "messageDeleted",
                                 "labelAdded", "labelRemoved"],
                "maxResults": 500,
            }
            if token:
                params["pageToken"] = token
            try:
                resp = _with_retry(
                    lambda p=params: self.service.users().history().list(**p).execute(),
                    "history.list",
                )
            except HttpError as err:
                if getattr(err.resp, "status", None) == 404:
                    raise HistoryTooOld(
                        f"startHistoryId {start_history_id} expired; full resync required"
                    ) from err
                raise
            yield resp
            token = resp.get("nextPageToken")
            if not token:
                return
