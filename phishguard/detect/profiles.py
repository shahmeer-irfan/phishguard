"""Building and persisting contact profiles.

Runs as its own pass (`phishguard profile`) rather than during ingest: a
profile is an aggregate over a contact's whole history, so it is cheaper and
far less error-prone to rebuild it in bulk than to maintain it incrementally
on every arriving message.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from ..db.store import Store
from ..parse.headers import canonical_address
from . import domains as D
from . import fingerprint as FP

ProgressFn = Callable[[int, int], None]

# A profile is only built from messages the sender could plausibly have really
# sent. Anything already judged dangerous is excluded, or a successful
# impersonation would be folded into the baseline it is supposed to violate.
MIN_MESSAGES_FOR_PROFILE = 5
MAX_MESSAGES_PER_PROFILE = 400


@dataclass
class ProfileReport:
    built: int = 0
    skipped_thin: int = 0
    with_style: int = 0
    excluded_messages: int = 0
    seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        tail = f", {len(self.errors)} errors" if self.errors else ""
        return (f"{self.built} profiles built ({self.with_style} with a writing "
                f"baseline), {self.skipped_thin} contacts too thin, "
                f"{self.excluded_messages} messages excluded{tail} "
                f"in {self.seconds:.1f}s")


def _sample_from_row(row: Any, link_orgs: list[str], has_attachments: bool) -> FP.SampleMessage:
    hour = None
    if row["received_at"]:
        try:
            hour = datetime.fromisoformat(row["received_at"]).hour
        except (TypeError, ValueError):
            hour = None

    origin_org = None
    try:
        recipients = len(json.loads(row["to_addrs"] or "[]"))
    except (TypeError, ValueError):
        recipients = 1

    return FP.SampleMessage(
        body_text=row["body_text"] or "",
        x_mailer=row["x_mailer"] or row["user_agent"],
        message_id=row["rfc822_message_id"],
        mime_signature=row["mime_signature"],
        header_order_hash=row["header_order_hash"],
        tz_offset=row["date_tz_offset"],
        origin_org=origin_org,
        dkim_domain=row["dkim_domain"],
        hour=hour,
        n_recipients=max(recipients, 1),
        has_links=bool(link_orgs),
        has_attachments=has_attachments,
        link_orgs=link_orgs,
    )


def build_all(store: Store, account_id: int, progress: ProgressFn | None = None,
              rebuild: bool = False) -> ProfileReport:
    started = time.monotonic()
    report = ProfileReport()

    contacts = store.conn.execute(
        """SELECT canonical_email, inbound_count FROM contacts
           WHERE account_id = ? AND inbound_count >= ?
           ORDER BY inbound_count DESC""",
        (account_id, MIN_MESSAGES_FOR_PROFILE),
    ).fetchall()

    total = len(contacts)
    for i, contact in enumerate(contacts, 1):
        canon = contact["canonical_email"]
        if not rebuild and store.profile_is_current(account_id, canon, FP.PROFILE_VERSION):
            continue
        try:
            profile, excluded = _build_one(store, account_id, canon)
        except Exception as exc:
            report.errors.append(f"{canon}: {type(exc).__name__}: {exc}")
            continue

        report.excluded_messages += excluded
        if profile is None or not profile.usable_technical:
            report.skipped_thin += 1
            continue
        store.save_profile(account_id, profile)
        report.built += 1
        if profile.usable_style:
            report.with_style += 1
        if progress and i % 25 == 0:
            progress(i, total)

    if progress:
        progress(total, total)
    report.seconds = time.monotonic() - started
    return report


def _build_one(store: Store, account_id: int, canon: str
               ) -> tuple[FP.ContactProfile | None, int]:
    """Gather a contact's inbound history and aggregate it.

    Messages already judged `danger` are excluded. This matters more than it
    looks: without it, the first successful impersonation of a contact becomes
    part of that contact's baseline, and the second one matches.
    """
    # Filtered in SQL on the indexed from_addr, not in Python over a recent
    # window. The previous version pulled the newest 4000 messages and sifted
    # them per contact, which was both O(contacts x messages) and silently
    # wrong: a correspondent whose mail all predated that window got no profile
    # at all, so Layer 2 quietly switched itself off for exactly the long-
    # standing relationships it is most needed for.
    #
    # from_addr is stored normalised but not canonicalised (+tags, Gmail dots),
    # so the candidate set is widened by local-part prefix and the exact
    # canonical check is still applied in Python.
    local = canon.split("@", 1)[0]
    domain = canon.split("@", 1)[1] if "@" in canon else ""
    rows = store.conn.execute(
        """SELECT m.*, a.dkim_domain,
                  (SELECT COUNT(*) FROM attachments t
                    WHERE t.message_id = m.id AND t.is_inline = 0) AS n_attachments,
                  v.tier AS tier,
                  (SELECT from_host FROM received_hops h
                    WHERE h.message_id = m.id
                    ORDER BY h.hop_index DESC LIMIT 1) AS origin_host
           FROM messages m
           LEFT JOIN auth_results a ON a.message_id = m.id
           LEFT JOIN verdicts v ON v.message_id = m.id
           WHERE m.account_id = ?
             AND m.from_addr LIKE ?
             AND m.labels_json NOT LIKE '%SENT%'
           ORDER BY m.received_at DESC
           LIMIT ?""",
        (account_id, f"{local[:1]}%@{domain}", MAX_MESSAGES_PER_PROFILE * 2),
    ).fetchall()

    mine = [r for r in rows if canonical_address(r["from_addr"]) == canon]
    excluded = sum(1 for r in mine if r["tier"] == "danger")
    usable = [r for r in mine if r["tier"] != "danger"][:MAX_MESSAGES_PER_PROFILE]
    if len(usable) < MIN_MESSAGES_FOR_PROFILE:
        return None, excluded

    ids = [r["id"] for r in usable]
    links_by_message = _links_for(store, ids)

    samples: list[FP.SampleMessage] = []
    for row in usable:
        sample = _sample_from_row(row, links_by_message.get(row["id"], []),
                                  bool(row["n_attachments"]))
        if row["origin_host"]:
            sample.origin_org = D.org_domain(row["origin_host"])
        samples.append(sample)

    return FP.build_profile(canon, samples), excluded


def _links_for(store: Store, message_ids: list[int]) -> dict[int, list[str]]:
    """Link organisations for many messages in one pass.

    Replaces a query per message; on a contact with 400 stored messages that
    was 400 round trips to build one profile.
    """
    out: dict[int, list[str]] = {}
    for i in range(0, len(message_ids), 400):  # SQLITE_MAX_VARIABLE_NUMBER
        chunk = message_ids[i:i + 400]
        marks = ",".join("?" * len(chunk))
        rows = store.conn.execute(
            f"""SELECT DISTINCT message_id, org FROM message_links
                WHERE message_id IN ({marks}) AND org != ''""",
            chunk,
        ).fetchall()
        for row in rows:
            out.setdefault(row["message_id"], []).append(row["org"])
    return out


# ------------------------------------------------------------ persistence

def save(store: Store, account_id: int, profile: FP.ContactProfile) -> None:
    store.save_profile(account_id, profile)


def load_all(store: Store, account_id: int) -> dict[str, FP.ContactProfile]:
    """Every current-version profile for this account, keyed by canonical email."""
    out: dict[str, FP.ContactProfile] = {}
    try:
        rows = store.conn.execute(
            "SELECT * FROM contact_profiles WHERE account_id = ? AND profile_version = ?",
            (account_id, FP.PROFILE_VERSION),
        ).fetchall()
    except Exception:
        return out

    for row in rows:
        try:
            out[row["canonical_email"]] = FP.ContactProfile(
                canonical_email=row["canonical_email"],
                technical=FP.TechnicalProfile.from_dict(json.loads(row["technical_json"])),
                style=FP.StyleProfile.from_dict(json.loads(row["style_json"])),
                relationship=FP.RelationshipProfile.from_dict(
                    json.loads(row["relationship_json"])),
                version=row["profile_version"],
            )
        except (TypeError, ValueError):
            continue
    return out
