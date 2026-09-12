"""Header-level parsing.

Everything here is deliberately tolerant: phishing mail is frequently
malformed on purpose, and a parser that raises on bad input becomes a
detection blind spot. Functions return partial results rather than throwing.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

# ---------------------------------------------------------------- addresses

_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}


def split_address(addr: str) -> tuple[str, str]:
    """('user', 'domain.com') from an addr-spec. Empty strings when absent."""
    if not addr or "@" not in addr:
        return (addr or "").strip().lower(), ""
    local, _, domain = addr.rpartition("@")
    return local.strip().lower(), domain.strip().lower().rstrip(".")


def normalise_address(addr: str) -> str:
    """Lowercase, whitespace-stripped addr-spec. Preserves local-part exactly.

    Accepts either a bare addr-spec or a full name-addr ('Abdul <a@b.com>'), so
    callers can hand over a raw header value without pre-parsing it.
    """
    if not addr:
        return ""
    addr = addr.strip()
    if "<" in addr or addr.count("@") > 1:
        extracted = parseaddr(" ".join(addr.split()))[1]
        if extracted:
            addr = extracted
    addr = addr.strip().strip("<>").strip()
    local, domain = split_address(addr)
    return f"{local}@{domain}" if domain else local


def canonical_address(addr: str) -> str:
    """Identity key for the contact table.

    Folds the aliases that resolve to the same human mailbox: +tags everywhere,
    and dots on Gmail (Gmail treats a.b@ and ab@ as one account, so an attacker
    cannot use dot-variation to look like a new-but-familiar sender).
    Non-Gmail dots are left alone; elsewhere they are significant.
    """
    norm = normalise_address(addr)
    local, domain = split_address(norm)
    if not domain:
        return norm
    local = local.split("+", 1)[0]
    if domain in _GMAIL_DOMAINS:
        local = local.replace(".", "")
        domain = "gmail.com"
    return f"{local}@{domain}"


def decode_mime_header(raw: str | None) -> str:
    """Decode RFC 2047 encoded-words, tolerating broken encodings.

    The *raw* form is kept elsewhere on purpose: whether a client uses Q- or
    B-encoding, and whether it encodes at all, is itself a fingerprint feature.
    """
    if not raw:
        return ""
    flat = " ".join(raw.split())
    try:
        return str(make_header(decode_header(flat)))
    except (UnicodeDecodeError, LookupError, ValueError):
        try:
            return "".join(
                part.decode(enc or "utf-8", errors="replace") if isinstance(part, bytes) else part
                for part, enc in decode_header(flat)
            )
        except Exception:
            return flat


def parse_address_list(raw: str | None) -> list[dict[str, str]]:
    """[{display, addr, domain}, ...] from a To:/Cc:-style header."""
    if not raw:
        return []
    flat = " ".join(raw.split())
    out: list[dict[str, str]] = []
    try:
        pairs = getaddresses([flat])
    except Exception:
        return []
    for display, addr in pairs:
        addr = normalise_address(addr)
        display = decode_mime_header(display).strip().strip('"').strip()
        if not addr and not display:
            continue
        out.append({"display": display, "addr": addr, "domain": split_address(addr)[1]})
    return out


def parse_single_address(raw: str | None) -> dict[str, str]:
    parsed = parse_address_list(raw)
    return parsed[0] if parsed else {"display": "", "addr": "", "domain": ""}


# ------------------------------------------------------------------- dates

def parse_date_header(raw: str | None) -> tuple[str | None, int | None]:
    """(ISO8601 UTC, tz offset in minutes).

    The offset is kept separately because it is a sender-fingerprint feature:
    a contact who has always sent from +05:00 suddenly sending from -07:00 is
    worth noticing, and that fact is destroyed by normalising to UTC.
    """
    if not raw:
        return None, None
    try:
        dt = parsedate_to_datetime(" ".join(raw.split()))
    except (TypeError, ValueError, IndexError):
        return None, None
    if dt is None:
        return None, None
    offset_min = None
    if dt.tzinfo is not None:
        off = dt.utcoffset()
        if off is not None:
            offset_min = int(off.total_seconds() // 60)
        dt = dt.astimezone(timezone.utc)
    else:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat(), offset_min


def epoch_ms_to_iso(ms: str | int | None) -> str | None:
    if ms in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


# ------------------------------------------------------- message-id / refs

_MSGID_RE = re.compile(r"<([^<>]+)>")


def parse_message_id(raw: str | None) -> str | None:
    if not raw:
        return None
    m = _MSGID_RE.search(raw)
    return (m.group(1) if m else " ".join(raw.split())) or None


def parse_references(raw: str | None) -> list[str]:
    if not raw:
        return []
    found = _MSGID_RE.findall(raw)
    return found or [t for t in raw.split() if t]


# ------------------------------------------------------- header order hash

_ORDER_SKIP_PREFIXES = (
    "received", "arc-", "x-google", "x-gm-", "x-received", "dkim-signature",
    "authentication-results", "x-originating-ip", "return-path", "delivered-to",
    "x-spam", "x-virus", "x-ms-exchange", "x-forefront", "x-microsoft-antispam",
)


def header_order_hash(header_names: list[str]) -> str:
    """Fingerprint of the header-name sequence.

    Mail clients emit headers in a stable order, so this acts almost like a
    client serial number. Hop-added headers (Received, ARC-*, spam-scanner
    output) are dropped because they describe who relayed the mail, not who
    composed it - and they change per delivery.
    """
    seq = [n.lower() for n in header_names if not n.lower().startswith(_ORDER_SKIP_PREFIXES)]
    return hashlib.sha256("|".join(seq).encode("utf-8")).hexdigest()[:32]


# ------------------------------------------------- Authentication-Results

@dataclass
class AuthResults:
    authserv_id: str | None = None
    spf: str | None = None
    spf_domain: str | None = None
    dkim: str | None = None
    dkim_domain: str | None = None
    dkim_selector: str | None = None
    dmarc: str | None = None
    dmarc_domain: str | None = None
    compauth: str | None = None
    arc_present: bool = False
    raw: str | None = None


def _split_unparenthesised(text: str, sep: str) -> list[str]:
    """Split on `sep` while ignoring separators inside (comments)."""
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _strip_comments(text: str) -> str:
    out: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


_KV_RE = re.compile(r'([A-Za-z0-9_.\-]+)\s*=\s*("[^"]*"|\S+)')


def parse_authentication_results(values: list[str], arc_present: bool = False) -> AuthResults:
    """Parse RFC 8601 Authentication-Results headers.

    Order matters for trust. Headers are prepended on delivery, so values[0] is
    the one stamped by our own provider (mx.google.com) and is the only one we
    can believe - an attacker is free to forge their own Authentication-Results
    upstream. Later entries fill gaps only.
    """
    res = AuthResults(arc_present=arc_present, raw="\n".join(values) if values else None)

    for value in values:
        flat = " ".join(value.split())
        chunks = _split_unparenthesised(flat, ";")
        if not chunks:
            continue
        if res.authserv_id is None:
            res.authserv_id = _strip_comments(chunks[0]).strip() or None

        for chunk in chunks[1:]:
            clean = _strip_comments(chunk).strip()
            if not clean or "=" not in clean:
                continue
            method, _, rest = clean.partition("=")
            method = method.strip().lower()
            rest = rest.strip()
            if not rest:
                continue
            kvs = {k.lower(): v.strip('"') for k, v in _KV_RE.findall(rest)}
            result = rest.split()[0].strip('"').lower()

            if method == "spf" and res.spf is None:
                res.spf = result
                origin = kvs.get("smtp.mailfrom") or kvs.get("smtp.helo")
                if origin:
                    res.spf_domain = split_address(origin)[1] or origin.lower()
            elif method == "dkim" and res.dkim is None:
                res.dkim = result
                ident = kvs.get("header.d") or kvs.get("header.i")
                if ident:
                    res.dkim_domain = split_address(ident)[1] or ident.lstrip("@").lower()
                res.dkim_selector = kvs.get("header.s")
            elif method == "dmarc" and res.dmarc is None:
                res.dmarc = result
                res.dmarc_domain = (kvs.get("header.from") or "").lower() or None
            elif method == "compauth" and res.compauth is None:
                res.compauth = result
    return res


# -------------------------------------------------------------- Received:

_IP_RE = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")
# Colons are allowed because internal Google hops write a bare IPv6 address
# where a hostname would normally go ("by 2002:a05:6214:1a8f with SMTP").
_HOST_PAT = r"([A-Za-z0-9_.:\-]+)"


@dataclass
class ReceivedHop:
    hop_index: int
    raw: str
    from_host: str | None = None
    from_ip: str | None = None
    by_host: str | None = None
    with_proto: str | None = None
    hop_time: str | None = None


def parse_received(values: list[str]) -> list[ReceivedHop]:
    """Parse the Received: chain, newest hop first.

    Header order is delivery order reversed, so index 0 is the hop closest to
    us (most trustworthy) and the highest index is the claimed origin (most
    forgeable). Later layers care about exactly that asymmetry.
    """
    hops: list[ReceivedHop] = []
    for i, raw in enumerate(values):
        flat = " ".join(raw.split())
        hop = ReceivedHop(hop_index=i, raw=flat)

        # The timestamp follows the last top-level ';'.
        segments = _split_unparenthesised(flat, ";")
        if len(segments) > 1:
            hop.hop_time, _ = parse_date_header(_strip_comments(segments[-1]).strip())
            body = ";".join(segments[:-1])
        else:
            body = flat

        m = re.search(r"\bfrom\s+" + _HOST_PAT, body, re.I)
        if m:
            hop.from_host = m.group(1).rstrip(".").lower()
        m = re.search(r"\bby\s+" + _HOST_PAT, body, re.I)
        if m:
            hop.by_host = m.group(1).rstrip(".").lower()
        m = re.search(r"\bwith\s+([A-Za-z0-9/]+)", body, re.I)
        if m:
            hop.with_proto = m.group(1).upper()

        # Prefer the IP inside the "from ... [ip]" clause; an IP after " by "
        # belongs to our own receiving server and says nothing about the sender.
        from_match = re.search(r"\bfrom\b", body, re.I)
        search_space = body[from_match.start():] if from_match else body
        by_pos = search_space.lower().find(" by ")
        if by_pos > 0:
            search_space = search_space[:by_pos]
        ip = _IP_RE.search(search_space) or _IP_RE.search(body)
        if ip:
            hop.from_ip = ip.group(1)

        hops.append(hop)
    return hops
