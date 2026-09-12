"""RFC822 -> ParsedMessage.

Parsed with the compat32 policy on purpose. The modern `policy.default` helpfully
decodes and re-folds headers, which destroys exactly the artefacts Layer 2 wants:
raw header casing, header order, and whether the client used Q- or B-encoding.
We keep the raw values and decode explicitly where a human-readable form is needed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import BytesParser

from . import headers as H

# Text parts larger than this are almost certainly not prose we want to model.
MAX_BODY_CHARS = 2_000_000


@dataclass
class Attachment:
    part_path: str
    filename: str | None
    content_type: str
    content_id: str | None
    is_inline: bool
    size_bytes: int
    sha256: str


@dataclass
class ParsedMessage:
    # identity
    rfc822_message_id: str | None = None
    date_header: str | None = None
    date_iso: str | None = None
    date_tz_offset: int | None = None

    from_addr: str = ""
    from_display: str = ""
    from_domain: str = ""
    reply_to_addr: str = ""
    return_path_addr: str = ""
    to_addrs: list[dict] = field(default_factory=list)
    cc_addrs: list[dict] = field(default_factory=list)
    subject: str = ""

    in_reply_to: str | None = None
    references: list[str] = field(default_factory=list)

    # fingerprint raw material
    header_pairs: list[tuple[str, str]] = field(default_factory=list)
    header_order_hash: str = ""
    mime_signature: str = ""
    x_mailer: str | None = None
    user_agent: str | None = None

    # content
    body_text: str = ""
    body_html: str = ""
    attachments: list[Attachment] = field(default_factory=list)

    # protocol
    auth: H.AuthResults = field(default_factory=H.AuthResults)
    hops: list[H.ReceivedHop] = field(default_factory=list)

    parse_error: str | None = None

    def header_values(self, name: str) -> list[str]:
        low = name.lower()
        return [v for n, v in self.header_pairs if n.lower() == low]

    def header(self, name: str) -> str | None:
        vals = self.header_values(name)
        return vals[0] if vals else None


def _decode_part(part: Message) -> str:
    """Decode a leaf text part, never raising on a bad charset."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return ""
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError, ValueError):
        return payload.decode("utf-8", errors="replace")


def _is_attachment(part: Message) -> bool:
    disp = (part.get_content_disposition() or "").lower()
    if disp == "attachment":
        return True
    if part.get_filename():
        return True
    # A leaf that is neither text nor a container is payload, however it is
    # labelled - phishing kits routinely omit Content-Disposition.
    return disp != "inline" and part.get_content_maintype() not in ("text", "multipart")


def _walk(part: Message, path: str, out: ParsedMessage, texts: list[str], htmls: list[str]) -> str:
    """Recursive walk. Returns this part's MIME signature fragment."""
    ctype = (part.get_content_type() or "application/octet-stream").lower()

    if part.is_multipart():
        children = part.get_payload()
        if not isinstance(children, list):
            return ctype
        frags = [
            _walk(child, f"{path}.{i + 1}" if path else str(i + 1), out, texts, htmls)
            for i, child in enumerate(children)
        ]
        return f"{ctype}({','.join(frags)})"

    if _is_attachment(part):
        try:
            raw = part.get_payload(decode=True) or b""
        except Exception:
            raw = b""
        disp = (part.get_content_disposition() or "").lower()
        cid = part.get("Content-ID")
        out.attachments.append(Attachment(
            part_path=path or "1",
            filename=H.decode_mime_header(part.get_filename()) or None,
            content_type=ctype,
            content_id=cid.strip("<>") if cid else None,
            is_inline=disp == "inline" or bool(cid),
            size_bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(),
        ))
        return ctype

    # Every text part is collected, including ones a mail client would hide.
    # Alternative parts that disagree with each other are themselves a signal.
    text = _decode_part(part)[:MAX_BODY_CHARS]
    if ctype == "text/html":
        htmls.append(text)
    elif ctype.startswith("text/"):
        texts.append(text)
    return ctype


def parse_rfc822(raw: bytes) -> ParsedMessage:
    """Parse raw message bytes. Never raises; failures land in `parse_error`."""
    out = ParsedMessage()
    try:
        msg = BytesParser(policy=policy.compat32).parsebytes(raw)
    except Exception as exc:  # a mailbox is not a trusted input
        out.parse_error = f"parse: {type(exc).__name__}: {exc}"
        return out

    try:
        out.header_pairs = [(str(k), str(v)) for k, v in msg.items()]
    except Exception as exc:
        out.parse_error = f"headers: {type(exc).__name__}: {exc}"
        out.header_pairs = []

    out.header_order_hash = H.header_order_hash([n for n, _ in out.header_pairs])

    frm = H.parse_single_address(out.header("From"))
    out.from_addr, out.from_display, out.from_domain = frm["addr"], frm["display"], frm["domain"]
    out.reply_to_addr = H.parse_single_address(out.header("Reply-To"))["addr"]
    out.return_path_addr = H.parse_single_address(out.header("Return-Path"))["addr"]
    out.to_addrs = H.parse_address_list(out.header("To"))
    out.cc_addrs = H.parse_address_list(out.header("Cc"))
    out.subject = H.decode_mime_header(out.header("Subject"))

    out.date_header = out.header("Date")
    out.date_iso, out.date_tz_offset = H.parse_date_header(out.date_header)

    out.rfc822_message_id = H.parse_message_id(out.header("Message-ID"))
    out.in_reply_to = H.parse_message_id(out.header("In-Reply-To"))
    out.references = H.parse_references(out.header("References"))

    out.x_mailer = out.header("X-Mailer")
    out.user_agent = out.header("User-Agent")

    out.auth = H.parse_authentication_results(
        out.header_values("Authentication-Results"),
        arc_present=bool(out.header_values("ARC-Seal") or out.header_values("ARC-Authentication-Results")),
    )
    out.hops = H.parse_received(out.header_values("Received"))

    texts: list[str] = []
    htmls: list[str] = []
    try:
        out.mime_signature = _walk(msg, "", out, texts, htmls)
    except Exception as exc:
        out.parse_error = (out.parse_error or "") + f" body: {type(exc).__name__}: {exc}"
    out.body_text = "\n".join(t for t in texts if t.strip())[:MAX_BODY_CHARS]
    out.body_html = "\n".join(h for h in htmls if h.strip())[:MAX_BODY_CHARS]

    return out
