"""SQLite persistence layer.

One writer (the sync worker), many readers (the API). WAL mode makes that safe
without a connection pool.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..parse.message import ParsedMessage

# Bump whenever schema.sql changes shape. Every statement there is CREATE ...
# IF NOT EXISTS so new tables appear on the next open, but the recorded version
# is what tells a future migration which shape it is starting from - and it had
# been left at "1" through four schema changes, which made it worthless.
SCHEMA_VERSION = "5"
_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path: Path | str, encrypt: bool | None = None):
        """Open the store, encrypted when SQLCipher and a Keychain are both
        available. `encrypt=True` refuses to open in the clear instead of
        silently downgrading - a caller that asked for encryption should not be
        handed a plaintext database."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.encrypted = False

        if encrypt is not False:
            from ..security import connect_encrypted, encryption_available, get_or_create_db_key

            if encryption_available():
                key = get_or_create_db_key()
                if key:
                    self.conn = connect_encrypted(str(self.path), key)
                    self.encrypted = True
                elif encrypt:
                    raise RuntimeError("encryption requested but no key store is available")
            elif encrypt:
                raise RuntimeError("encryption requested but SQLCipher is not installed")

        if not self.encrypted:
            self.conn = sqlite3.connect(str(self.path), isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = NORMAL")
        self._migrate()

    def _migrate(self) -> None:
        self.conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (SCHEMA_VERSION,),
        )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------ accounts

    def get_or_create_account(self, email: str) -> int:
        email = email.strip().lower()
        cur = self.conn.execute("SELECT id FROM accounts WHERE email = ?", (email,))
        row = cur.fetchone()
        if row:
            return int(row["id"])
        cur = self.conn.execute(
            "INSERT INTO accounts(email, provider, added_at) VALUES(?, 'gmail', ?)",
            (email, _now()),
        )
        account_id = int(cur.lastrowid)
        self.conn.execute("INSERT INTO sync_state(account_id) VALUES(?)", (account_id,))
        return account_id

    def account_email(self, account_id: int) -> str | None:
        row = self.conn.execute(
            "SELECT email FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        return row["email"] if row else None

    # ---------------------------------------------------------- sync state

    def sync_state(self, account_id: int) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM sync_state WHERE account_id = ?", (account_id,)
        ).fetchone()
        return dict(row) if row else {}

    def update_sync_state(self, account_id: int, **fields: Any) -> None:
        if not fields:
            return
        allowed = {"history_id", "backfill_done", "backfill_cursor", "last_sync_at", "last_error"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"unknown sync_state fields: {sorted(bad)}")
        sets = ", ".join(f"{k} = ?" for k in fields)
        self.conn.execute(
            f"UPDATE sync_state SET {sets} WHERE account_id = ?",
            (*fields.values(), account_id),
        )

    def advance_history_id(self, account_id: int, history_id: str | None) -> None:
        """Move the watermark forward only. Gmail history ids are monotonic per
        mailbox, and a page of results can carry an older id than one already
        stored; letting it go backwards would re-play history forever."""
        if not history_id:
            return
        current = self.sync_state(account_id).get("history_id")
        try:
            if current is not None and int(history_id) <= int(current):
                return
        except (TypeError, ValueError):
            pass
        self.update_sync_state(account_id, history_id=str(history_id))

    # ------------------------------------------------------------ messages

    def has_message(self, account_id: int, gmail_id: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM messages WHERE account_id = ? AND gmail_id = ?",
            (account_id, gmail_id),
        ).fetchone()
        return row is not None

    def existing_gmail_ids(self, account_id: int, gmail_ids: Iterable[str]) -> set[str]:
        ids = list(gmail_ids)
        if not ids:
            return set()
        found: set[str] = set()
        for i in range(0, len(ids), 400):  # stay under SQLITE_MAX_VARIABLE_NUMBER
            chunk = ids[i:i + 400]
            marks = ",".join("?" * len(chunk))
            rows = self.conn.execute(
                f"SELECT gmail_id FROM messages WHERE account_id = ? AND gmail_id IN ({marks})",
                (account_id, *chunk),
            ).fetchall()
            found.update(r["gmail_id"] for r in rows)
        return found

    def upsert_message(
        self,
        account_id: int,
        gmail_meta: dict[str, Any],
        parsed: ParsedMessage,
        raw: bytes | None = None,
    ) -> int:
        """Insert a message and its child rows. Idempotent on (account, gmail_id).

        A re-seen message keeps its stored body but refreshes labels and
        history_id: labels are the only field Gmail mutates after delivery.
        """
        gmail_id = gmail_meta["id"]
        labels = gmail_meta.get("labelIds") or []
        received_at = gmail_meta.get("received_at") or parsed.date_iso

        existing = self.conn.execute(
            "SELECT id FROM messages WHERE account_id = ? AND gmail_id = ?",
            (account_id, gmail_id),
        ).fetchone()
        if existing:
            self.conn.execute(
                "UPDATE messages SET labels_json = ?, history_id = ? WHERE id = ?",
                (json.dumps(labels), gmail_meta.get("historyId"), existing["id"]),
            )
            return int(existing["id"])

        raw_gz = gzip.compress(raw, compresslevel=6) if raw else None

        cur = self.conn.execute(
            """
            INSERT INTO messages (
                account_id, gmail_id, thread_id, rfc822_message_id, history_id,
                received_at, date_header, date_tz_offset,
                from_addr, from_display, from_domain, reply_to_addr, return_path_addr,
                to_addrs, cc_addrs, subject, in_reply_to, references_hdr,
                headers_json, header_order_hash, mime_signature, x_mailer, user_agent,
                body_text, body_html, snippet, labels_json, size_estimate,
                raw_gz, parse_error, ingested_at
            ) VALUES (?,?,?,?,?, ?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?)
            """,
            (
                account_id, gmail_id, gmail_meta.get("threadId"),
                parsed.rfc822_message_id, gmail_meta.get("historyId"),
                received_at, parsed.date_header, parsed.date_tz_offset,
                parsed.from_addr, parsed.from_display, parsed.from_domain,
                parsed.reply_to_addr, parsed.return_path_addr,
                json.dumps(parsed.to_addrs), json.dumps(parsed.cc_addrs),
                parsed.subject, parsed.in_reply_to, json.dumps(parsed.references),
                json.dumps(parsed.header_pairs), parsed.header_order_hash,
                parsed.mime_signature, parsed.x_mailer, parsed.user_agent,
                parsed.body_text, parsed.body_html, gmail_meta.get("snippet"),
                json.dumps(labels), gmail_meta.get("sizeEstimate"),
                raw_gz, parsed.parse_error, _now(),
            ),
        )
        message_id = int(cur.lastrowid)

        a = parsed.auth
        self.conn.execute(
            """INSERT INTO auth_results (
                   message_id, authserv_id, spf, spf_domain, dkim, dkim_domain,
                   dkim_selector, dmarc, dmarc_domain, compauth, arc_present, raw)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (message_id, a.authserv_id, a.spf, a.spf_domain, a.dkim, a.dkim_domain,
             a.dkim_selector, a.dmarc, a.dmarc_domain, a.compauth,
             1 if a.arc_present else 0, a.raw),
        )

        if parsed.hops:
            self.conn.executemany(
                """INSERT INTO received_hops (
                       message_id, hop_index, raw, from_host, from_ip, by_host,
                       with_proto, hop_time)
                   VALUES (?,?,?,?,?,?,?,?)""",
                [(message_id, h.hop_index, h.raw, h.from_host, h.from_ip,
                  h.by_host, h.with_proto, h.hop_time) for h in parsed.hops],
            )

        if parsed.attachments:
            self.conn.executemany(
                """INSERT INTO attachments (
                       message_id, part_path, filename, content_type, content_id,
                       is_inline, size_bytes, sha256)
                   VALUES (?,?,?,?,?,?,?,?)""",
                [(message_id, at.part_path, at.filename, at.content_type, at.content_id,
                  1 if at.is_inline else 0, at.size_bytes, at.sha256)
                 for at in parsed.attachments],
            )

        self._touch_contacts(account_id, parsed, labels, received_at)
        return message_id

    def raw_message(self, message_id: int) -> bytes | None:
        row = self.conn.execute(
            "SELECT raw_gz FROM messages WHERE id = ?", (message_id,)
        ).fetchone()
        if not row or row["raw_gz"] is None:
            return None
        return gzip.decompress(row["raw_gz"])

    def delete_message(self, account_id: int, gmail_id: str) -> None:
        """Used when history reports a permanent deletion. Child rows cascade."""
        self.conn.execute(
            "DELETE FROM messages WHERE account_id = ? AND gmail_id = ?",
            (account_id, gmail_id),
        )

    def set_labels(self, account_id: int, gmail_id: str, labels: list[str]) -> None:
        self.conn.execute(
            "UPDATE messages SET labels_json = ? WHERE account_id = ? AND gmail_id = ?",
            (json.dumps(labels), account_id, gmail_id),
        )

    # ------------------------------------------------------------ profiles

    def save_profile(self, account_id: int, profile) -> None:
        """Write a contact fingerprint, replacing any earlier version."""
        self.conn.execute(
            """INSERT INTO contact_profiles (
                   account_id, canonical_email, profile_version, technical_json,
                   style_json, relationship_json, samples, built_at)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(account_id, canonical_email) DO UPDATE SET
                   profile_version = excluded.profile_version,
                   technical_json = excluded.technical_json,
                   style_json = excluded.style_json,
                   relationship_json = excluded.relationship_json,
                   samples = excluded.samples,
                   built_at = excluded.built_at""",
            (account_id, profile.canonical_email, profile.version,
             json.dumps(profile.technical.to_dict()),
             json.dumps(profile.style.to_dict()),
             json.dumps(profile.relationship.to_dict()),
             profile.technical.samples, _now()),
        )

    def profile_is_current(self, account_id: int, canon: str, version: str) -> bool:
        row = self.conn.execute(
            """SELECT 1 FROM contact_profiles
               WHERE account_id = ? AND canonical_email = ? AND profile_version = ?""",
            (account_id, canon, version),
        ).fetchone()
        return row is not None

    def profile_count(self, account_id: int) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) c FROM contact_profiles WHERE account_id = ?",
            (account_id,)).fetchone()
        return int(row["c"]) if row else 0

    # --------------------------------------------------------------- links

    def replace_links(self, message_id: int, links) -> None:
        """Store the links a message contains, replacing any previous pass.

        Re-analysis is idempotent this way, and the accumulated table becomes
        the corpus behind a question no single message can answer: has any mail
        this user ever received linked to this domain before?
        """
        self.conn.execute("DELETE FROM message_links WHERE message_id = ?", (message_id,))
        rows = [
            (message_id, (l.href or "")[:2000], l.host, l.org,
             (l.anchor_text or "")[:300], l.source)
            for l in links if getattr(l, "href", None)
        ]
        if rows:
            self.conn.executemany(
                """INSERT INTO message_links (message_id, href, host, org, anchor_text, source)
                   VALUES (?,?,?,?,?,?)""",
                rows,
            )

    def link_domain_seen_count(self, account_id: int, org: str) -> int:
        """How many stored messages have ever linked to this organisation."""
        row = self.conn.execute(
            """SELECT COUNT(DISTINCT l.message_id) c FROM message_links l
               JOIN messages m ON m.id = l.message_id
               WHERE m.account_id = ? AND l.org = ?""",
            (account_id, org),
        ).fetchone()
        return int(row["c"]) if row else 0

    # ------------------------------------------------------------ contacts

    def _touch_contacts(
        self, account_id: int, parsed: ParsedMessage, labels: list[str], seen_at: str | None
    ) -> None:
        """Maintain the contact graph as mail lands.

        Outbound mail is weighted separately from inbound: the user having
        *written to* an address is a far stronger trust signal than having
        received from it, since anyone can send you mail.
        """
        from ..parse.headers import canonical_address, split_address

        outbound = "SENT" in labels
        if outbound:
            people = [(p["addr"], p["display"]) for p in (parsed.to_addrs + parsed.cc_addrs)]
        else:
            people = [(parsed.from_addr, parsed.from_display)]

        for addr, display in people:
            if not addr or "@" not in addr:
                continue
            canon = canonical_address(addr)
            domain = split_address(canon)[1]
            self.conn.execute(
                """INSERT INTO contacts (
                       account_id, canonical_email, domain, display_names_json,
                       first_seen, last_seen, inbound_count, outbound_count)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(account_id, canonical_email) DO UPDATE SET
                       last_seen = MAX(COALESCE(contacts.last_seen, ''), COALESCE(excluded.last_seen, '')),
                       first_seen = MIN(COALESCE(NULLIF(contacts.first_seen, ''), excluded.first_seen),
                                        COALESCE(excluded.first_seen, contacts.first_seen)),
                       inbound_count = contacts.inbound_count + excluded.inbound_count,
                       outbound_count = contacts.outbound_count + excluded.outbound_count""",
                (account_id, canon, domain, json.dumps([display] if display else []),
                 seen_at, seen_at, 0 if outbound else 1, 1 if outbound else 0),
            )
            if display:
                self._add_display_name(account_id, canon, display)

    def _add_display_name(self, account_id: int, canon: str, display: str) -> None:
        """Display names are append-only per contact.

        The *set* is what matters later: a sender whose display name has been
        stable for two years suddenly arriving as 'CEO - Urgent' is a signal,
        and you cannot see that if you only keep the latest value.
        """
        row = self.conn.execute(
            "SELECT display_names_json FROM contacts WHERE account_id = ? AND canonical_email = ?",
            (account_id, canon),
        ).fetchone()
        if not row:
            return
        try:
            names = json.loads(row["display_names_json"]) or []
        except (TypeError, ValueError):
            names = []
        if display in names:
            return
        names.append(display)
        self.conn.execute(
            "UPDATE contacts SET display_names_json = ? WHERE account_id = ? AND canonical_email = ?",
            (json.dumps(names[-20:]), account_id, canon),
        )

    def contact(self, account_id: int, addr: str) -> dict[str, Any] | None:
        from ..parse.headers import canonical_address

        row = self.conn.execute(
            "SELECT * FROM contacts WHERE account_id = ? AND canonical_email = ?",
            (account_id, canonical_address(addr)),
        ).fetchone()
        return dict(row) if row else None

    def top_contacts(self, account_id: int, limit: int = 30) -> list[dict[str, Any]]:
        """Ranked by two-way traffic. Outbound counts triple - mail the user
        actually wrote is the closest thing to a declared trust relationship."""
        rows = self.conn.execute(
            """SELECT *, (inbound_count + outbound_count * 3) AS affinity
               FROM contacts WHERE account_id = ?
               ORDER BY affinity DESC LIMIT ?""",
            (account_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # --------------------------------------------------------------- stats

    def stats(self, account_id: int) -> dict[str, Any]:
        one = lambda sql, *a: self.conn.execute(sql, a).fetchone()[0]  # noqa: E731
        return {
            "messages": one("SELECT COUNT(*) FROM messages WHERE account_id = ?", account_id),
            "contacts": one("SELECT COUNT(*) FROM contacts WHERE account_id = ?", account_id),
            "parse_errors": one(
                "SELECT COUNT(*) FROM messages WHERE account_id = ? AND parse_error IS NOT NULL",
                account_id),
            "with_raw": one(
                "SELECT COUNT(*) FROM messages WHERE account_id = ? AND raw_gz IS NOT NULL",
                account_id),
            "db_bytes": self.path.stat().st_size if self.path.exists() else 0,
            "oldest": one("SELECT MIN(received_at) FROM messages WHERE account_id = ?", account_id),
            "newest": one("SELECT MAX(received_at) FROM messages WHERE account_id = ?", account_id),
        }

    def auth_breakdown(self, account_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT COALESCE(a.dmarc, '(none)') AS dmarc, COUNT(*) AS n
               FROM messages m JOIN auth_results a ON a.message_id = m.id
               WHERE m.account_id = ? GROUP BY 1 ORDER BY n DESC""",
            (account_id,),
        ).fetchall()
        return [dict(r) for r in rows]
