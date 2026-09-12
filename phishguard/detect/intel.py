"""Domain registration lookups over RDAP.

Off by default. Everything else in Phase 1 is local and deterministic; this is
the one place the app talks to a third party, so it is opt-in (`analyze
--online`) and it leaks only the domain names already present in the user's
mail - never an address, a subject, or a body.

RDAP rather than WHOIS: it is JSON over HTTPS, it needs no extra dependency,
and rdap.org redirects to the right registry automatically.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from ..db.store import Store
from . import domains as D

log = logging.getLogger("phishguard.intel")

RDAP_BASE = "https://rdap.org/domain/"
USER_AGENT = "PhishGuard/0.1 (local anti-phishing tool)"
TIMEOUT = 6.0
MIN_INTERVAL = 0.5   # be a good citizen; rdap.org is a free redirector
RECHECK_AFTER_DAYS = 30


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event_date(events: list[dict], action: str) -> str | None:
    for event in events or []:
        if str(event.get("eventAction", "")).lower() == action:
            return event.get("eventDate")
    return None


def fetch_rdap(domain: str) -> dict[str, str | None]:
    """One RDAP lookup. Returns a row dict; failures land in `error`."""
    req = urllib.request.Request(RDAP_BASE + domain, headers={
        "User-Agent": USER_AGENT, "Accept": "application/rdap+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        # 404 is a real answer: the domain is not registered in any registry
        # RDAP knows about, which for a sender domain is itself odd.
        return {"error": f"http {exc.code}", "source": "rdap"}
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "source": "rdap"}

    events = payload.get("events", [])
    registrar = None
    for entity in payload.get("entities", []):
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray") or []
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] == "fn":
                        registrar = item[3]
                        break
    nameservers = [ns.get("ldhName") for ns in payload.get("nameservers", []) if ns.get("ldhName")]
    return {
        "created_at": _event_date(events, "registration"),
        "expires_at": _event_date(events, "expiration"),
        "registrar": registrar,
        "nameservers": ",".join(nameservers[:6]) if nameservers else None,
        "source": "rdap",
        "error": None,
    }


def needs_refresh(row: dict | None) -> bool:
    if row is None:
        return True
    if row.get("error"):
        # Retry failures, but not on every run.
        try:
            checked = datetime.fromisoformat(str(row["checked_at"]))
        except (TypeError, ValueError):
            return True
        return (datetime.now(timezone.utc) - checked).days >= 7
    if not row.get("created_at"):
        return False  # registry genuinely has no creation date; stop asking
    try:
        checked = datetime.fromisoformat(str(row["checked_at"]))
    except (TypeError, ValueError):
        return True
    return (datetime.now(timezone.utc) - checked).days >= RECHECK_AFTER_DAYS


def enrich_sender_domains(store: Store, account_id: int, limit: int = 200,
                          progress=None) -> dict[str, int]:
    """Look up the organisational domains of recent unknown senders.

    Ordered by how recently the domain was seen, because a lookup budget is
    best spent on mail the user is about to read.
    """
    rows = store.conn.execute(
        """SELECT m.from_domain, MAX(m.received_at) AS last_seen, COUNT(*) AS n
           FROM messages m
           WHERE m.account_id = ? AND m.from_domain != ''
           GROUP BY m.from_domain ORDER BY last_seen DESC""",
        (account_id,),
    ).fetchall()

    seen: set[str] = set()
    targets: list[str] = []
    for row in rows:
        org = D.org_domain(row["from_domain"])
        if not org or org in seen or D.is_freemail(org):
            continue
        seen.add(org)
        cached = store.conn.execute(
            "SELECT * FROM domain_intel WHERE domain = ?", (org,)
        ).fetchone()
        if needs_refresh(dict(cached) if cached else None):
            targets.append(org)
        if len(targets) >= limit:
            break

    stats = {"looked_up": 0, "cached": len(seen) - len(targets), "failed": 0}
    for i, domain in enumerate(targets, 1):
        result = fetch_rdap(domain)
        if result.get("error"):
            stats["failed"] += 1
        else:
            stats["looked_up"] += 1
        store.conn.execute(
            """INSERT INTO domain_intel (domain, created_at, expires_at, registrar,
                                         nameservers, source, checked_at, error)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(domain) DO UPDATE SET
                   created_at = excluded.created_at, expires_at = excluded.expires_at,
                   registrar = excluded.registrar, nameservers = excluded.nameservers,
                   source = excluded.source, checked_at = excluded.checked_at,
                   error = excluded.error""",
            (domain, result.get("created_at"), result.get("expires_at"),
             result.get("registrar"), result.get("nameservers"),
             result.get("source"), _now(), result.get("error")),
        )
        if progress:
            progress(i, len(targets))
        time.sleep(MIN_INTERVAL)
    return stats
