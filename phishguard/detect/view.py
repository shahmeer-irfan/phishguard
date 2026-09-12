"""MessageView - the flat shape detectors consume.

Two constructors feed it: stored rows (the normal path, no re-parsing) and a
freshly parsed .eml (the offline `inspect --detect` path). Detectors never
touch SQLite or the email module, so the same code covers both.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from ..parse.message import ParsedMessage
from .attachments import AttachmentInfo


@dataclass
class HopView:
    index: int
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None


@dataclass
class MessageView:
    message_id: int | None = None
    gmail_id: str = ""
    received_at: str | None = None
    subject: str = ""

    from_addr: str = ""
    from_display: str = ""
    from_domain: str = ""
    reply_to_addr: str = ""
    return_path_addr: str = ""
    to_addrs: list[dict] = field(default_factory=list)

    spf: str | None = None
    spf_domain: str | None = None
    dkim: str | None = None
    dkim_domain: str | None = None
    dmarc: str | None = None
    dmarc_domain: str | None = None
    arc_present: bool = False
    auth_raw: str | None = None
    auth_present: bool = False

    hops: list[HopView] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)

    body_text: str = ""
    body_html: str = ""
    attachments: list[AttachmentInfo] = field(default_factory=list)

    # Layer-2 raw material. Captured at ingest because Gmail's parsed format
    # throws all of it away.
    rfc822_message_id: str | None = None
    in_reply_to: str | None = None
    mime_signature: str = ""
    header_order_hash: str = ""
    x_mailer: str | None = None
    user_agent: str | None = None
    date_tz_offset: int | None = None

    # Returns the original RFC822 bytes, or None. Deliberately a callable:
    # Layer 3 only needs them to pull image payloads out for QR decoding, and
    # decompressing every stored message during a bulk pass would cost far more
    # than the analysis itself.
    raw_loader: Callable[[], bytes | None] | None = None

    # Parsed HTML, memoised. Layer 2, Layer 3 and the engine's link-corpus
    # write each need it, and parsing a large marketing email three times is
    # pure waste on a 15k-message pass.
    _html_cache: Any = field(default=None, repr=False, compare=False)

    def html(self):
        from .content import HtmlAnalysis, analyse_html

        if self._html_cache is None:
            self._html_cache = (analyse_html(self.body_html) if self.body_html
                                else HtmlAnalysis())
        return self._html_cache

    @property
    def origin_hop(self) -> HopView | None:
        """The claimed origin: the last hop in the chain, and the most forgeable."""
        return self.hops[-1] if self.hops else None

    @property
    def body(self) -> str:
        """Plain text for keyword work. Falls back to nothing rather than to
        raw HTML - matching markup against prose patterns produces noise."""
        return self.body_text

    def image_payloads(self, max_bytes: int = 4 * 1024 * 1024) -> list[bytes]:
        """Decoded bytes of every image part, for QR scanning.

        Re-parses the stored raw message, since Phase 0 keeps attachment
        metadata but not attachment content.
        """
        if self.raw_loader is None:
            return []
        raw = self.raw_loader()
        if not raw:
            return []
        from email import policy
        from email.parser import BytesParser

        out: list[bytes] = []
        try:
            msg = BytesParser(policy=policy.compat32).parsebytes(raw)
            for part in msg.walk():
                if part.is_multipart():
                    continue
                if not (part.get_content_type() or "").lower().startswith("image/"):
                    continue
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    continue
                if payload and len(payload) <= max_bytes:
                    out.append(payload)
        except Exception:
            return out
        return out

    @staticmethod
    def from_db(row: Any, auth: Any | None, hops: list[Any],
                attachments: list[Any] | None = None,
                raw_loader: Callable[[], bytes | None] | None = None) -> "MessageView":
        def js(value: Any, fallback: Any) -> Any:
            try:
                return json.loads(value) if value else fallback
            except (TypeError, ValueError):
                return fallback

        view = MessageView(
            message_id=row["id"],
            gmail_id=row["gmail_id"],
            received_at=row["received_at"],
            subject=row["subject"] or "",
            from_addr=row["from_addr"] or "",
            from_display=row["from_display"] or "",
            from_domain=row["from_domain"] or "",
            reply_to_addr=row["reply_to_addr"] or "",
            return_path_addr=row["return_path_addr"] or "",
            to_addrs=js(row["to_addrs"], []),
            labels=js(row["labels_json"], []),
            hops=[HopView(h["hop_index"], h["from_host"], h["from_ip"], h["by_host"])
                  for h in hops],
            body_text=row["body_text"] or "",
            body_html=row["body_html"] or "",
            rfc822_message_id=row["rfc822_message_id"],
            in_reply_to=row["in_reply_to"],
            mime_signature=row["mime_signature"] or "",
            header_order_hash=row["header_order_hash"] or "",
            x_mailer=row["x_mailer"], user_agent=row["user_agent"],
            date_tz_offset=row["date_tz_offset"],
            attachments=[AttachmentInfo(
                filename=a["filename"] or "", content_type=a["content_type"] or "",
                size_bytes=a["size_bytes"] or 0, is_inline=bool(a["is_inline"]),
                sha256=a["sha256"] or "",
            ) for a in (attachments or [])],
            raw_loader=raw_loader,
        )
        if auth:
            view.spf, view.spf_domain = auth["spf"], auth["spf_domain"]
            view.dkim, view.dkim_domain = auth["dkim"], auth["dkim_domain"]
            view.dmarc, view.dmarc_domain = auth["dmarc"], auth["dmarc_domain"]
            view.arc_present = bool(auth["arc_present"])
            view.auth_raw = auth["raw"]
            view.auth_present = bool(auth["raw"])
        return view

    @staticmethod
    def from_parsed(parsed: ParsedMessage, gmail_id: str = "(local)") -> "MessageView":
        a = parsed.auth
        return MessageView(
            gmail_id=gmail_id,
            received_at=parsed.date_iso,
            subject=parsed.subject,
            from_addr=parsed.from_addr,
            from_display=parsed.from_display,
            from_domain=parsed.from_domain,
            reply_to_addr=parsed.reply_to_addr,
            return_path_addr=parsed.return_path_addr,
            to_addrs=parsed.to_addrs,
            spf=a.spf, spf_domain=a.spf_domain,
            dkim=a.dkim, dkim_domain=a.dkim_domain,
            dmarc=a.dmarc, dmarc_domain=a.dmarc_domain,
            arc_present=a.arc_present, auth_raw=a.raw, auth_present=bool(a.raw),
            hops=[HopView(h.hop_index, h.from_host, h.from_ip, h.by_host)
                  for h in parsed.hops],
            body_text=parsed.body_text,
            body_html=parsed.body_html,
            rfc822_message_id=parsed.rfc822_message_id,
            in_reply_to=parsed.in_reply_to,
            mime_signature=parsed.mime_signature,
            header_order_hash=parsed.header_order_hash,
            x_mailer=parsed.x_mailer, user_agent=parsed.user_agent,
            date_tz_offset=parsed.date_tz_offset,
            attachments=[AttachmentInfo(
                filename=at.filename or "", content_type=at.content_type,
                size_bytes=at.size_bytes, is_inline=at.is_inline, sha256=at.sha256,
            ) for at in parsed.attachments],
        )
