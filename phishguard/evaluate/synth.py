"""Synthetic impersonation generator.

The measurement problem this solves: real business-email-compromise samples are
scarce, and generic phishing corpora say nothing about whether *this* user's
contacts can be impersonated. A public corpus can tell you the detector catches
phishing in general; it cannot tell you it would catch a fake of your manager.

So attacks are manufactured against the user's own contact graph. Take genuine
messages from real correspondents, apply each attack transform, and the labels
come for free - every generated message is known-malicious by construction and
every source message is known-benign.

The transforms mirror how these attacks are actually built, which means the
generated set is only a floor: it measures whether the detector catches the
techniques we already modelled. It cannot discover one nobody thought of.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ..parse.headers import canonical_address, split_address

# Attack families, each mapping to the layer it is meant to exercise.
TRANSFORMS: dict[str, int] = {
    "display_name_freemail": 1,   # same name, personal mailbox
    "lookalike_domain": 1,        # cousin/typo domain
    "reply_to_divert": 0,         # genuine sender, replies redirected
    "auth_forgery": 0,            # spoofed From, DMARC fails
    "credential_link": 3,         # anchor text lies about destination
    "dangerous_attachment": 3,    # double-extension payload
    "style_swap": 2,              # right address, someone else writing
}

_LOOKALIKE_AFFIX = ["-secure", "-payroll", "-billing", "-support", "-hr",
                    "secure-", "mail-", "my-"]

_PAYMENT_BODIES = [
    "Hi,\n\nOur bank has flagged the old account so please use the updated "
    "details below for the invoice due this week. Let me know once the transfer "
    "is done.\n\nIBAN: GB29NWBK60161331926819\n\nThanks",
    "Hello,\n\nQuick one before I get on a flight - can you push the payment "
    "through today? Use the new account, the old one is frozen. I won't have "
    "signal so don't call, just confirm here.\n\nRegards",
    "Hi,\n\nPlease find the revised remittance details attached. Kindly process "
    "before close of business and keep this between us until the audit is "
    "finished.\n\nBest",
]

_CREDENTIAL_BODIES = [
    "Your mailbox storage is full and incoming mail is being rejected. "
    "Sign in below within 24 hours to restore delivery.",
    "We detected an unusual sign-in to your account. Confirm it was you, or "
    "your access will be suspended.",
]


@dataclass
class SynthMessage:
    """A generated message plus the label and provenance the harness needs."""
    raw: bytes
    label: str                       # "attack" | "benign"
    transform: str
    target_layer: int
    source_gmail_id: str = ""
    impersonated: str = ""
    notes: dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceMessage:
    """A genuine message used as raw material."""
    gmail_id: str
    from_addr: str
    from_display: str
    subject: str
    body_text: str
    to_addr: str
    x_mailer: str | None = None
    message_id: str | None = None


def _auth_header(domain: str, result: str = "pass", policy: str = "NONE") -> str:
    return (f"Authentication-Results: mx.google.com; "
            f"dkim={result} header.i=@{domain} header.s=sel; "
            f"spf={result} smtp.mailfrom=x@{domain}; "
            f"dmarc={result} (p={policy} sp={policy} dis=NONE) header.from={domain}")


def _compose(*, frm: str, display: str, to: str, subject: str, body: str,
             auth: str, extra_headers: str = "", html: str | None = None,
             attachment: tuple[str, str] | None = None,
             x_mailer: str | None = None, message_id: str | None = None) -> bytes:
    head = [f"From: {display} <{frm}>" if display else f"From: {frm}",
            f"To: {to}", f"Subject: {subject}",
            "Date: Tue, 9 Sep 2025 11:02:01 +0500", "MIME-Version: 1.0"]
    if message_id:
        head.append(f"Message-ID: <{message_id}>")
    if x_mailer:
        head.append(f"X-Mailer: {x_mailer}")
    head.append(auth)
    if extra_headers:
        head.append(extra_headers.rstrip("\r\n"))

    if attachment:
        name, payload = attachment
        head.append('Content-Type: multipart/mixed; boundary="SB"')
        body_part = (
            "\r\n--SB\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n"
            f"{body}\r\n"
            f"--SB\r\nContent-Type: application/octet-stream; name=\"{name}\"\r\n"
            f"Content-Disposition: attachment; filename=\"{name}\"\r\n"
            "Content-Transfer-Encoding: base64\r\n\r\n"
            f"{payload}\r\n--SB--\r\n"
        )
    elif html:
        head.append('Content-Type: text/html; charset="utf-8"')
        body_part = f"\r\n{html}"
    else:
        head.append('Content-Type: text/plain; charset="utf-8"')
        body_part = f"\r\n{body}"

    return ("\r\n".join(head) + "\r\n" + body_part).encode("utf-8", errors="replace")


# ------------------------------------------------------------- transforms

def t_display_name_freemail(src: SourceMessage, rng: random.Random) -> SynthMessage | None:
    """Same human name, personal mailbox. The canonical BEC opener."""
    _, domain = split_address(src.from_addr)
    if not src.from_display or domain in ("gmail.com", "googlemail.com"):
        return None
    handle = re.sub(r"[^a-z0-9]+", "", src.from_display.lower())[:18] or "contact"
    fake = f"{handle}{rng.randint(1, 99)}@gmail.com"
    return SynthMessage(
        raw=_compose(frm=fake, display=src.from_display, to=src.to_addr,
                     subject=f"Re: {src.subject}"[:120],
                     body=rng.choice(_PAYMENT_BODIES),
                     auth=_auth_header("gmail.com")),
        label="attack", transform="display_name_freemail", target_layer=1,
        source_gmail_id=src.gmail_id, impersonated=src.from_addr,
    )


def t_lookalike_domain(src: SourceMessage, rng: random.Random) -> SynthMessage | None:
    local, domain = split_address(src.from_addr)
    if not domain or domain in ("gmail.com", "googlemail.com"):
        return None
    label, _, tld = domain.partition(".")
    if len(label) < 4:
        return None
    affix = rng.choice(_LOOKALIKE_AFFIX)
    fake_domain = f"{affix}{label}.{tld}" if affix.endswith("-") else f"{label}{affix}.{tld}"
    fake = f"{local}@{fake_domain}"
    return SynthMessage(
        raw=_compose(frm=fake, display=src.from_display, to=src.to_addr,
                     subject=src.subject or "Invoice",
                     body=rng.choice(_PAYMENT_BODIES),
                     auth=_auth_header(fake_domain)),
        label="attack", transform="lookalike_domain", target_layer=1,
        source_gmail_id=src.gmail_id, impersonated=src.from_addr,
    )


def t_reply_to_divert(src: SourceMessage, rng: random.Random) -> SynthMessage | None:
    """Genuine, authenticated sender - only the reply address is hijacked."""
    _, domain = split_address(src.from_addr)
    if not domain:
        return None
    handle = re.sub(r"[^a-z0-9]+", "", (src.from_display or "contact").lower())[:16]
    return SynthMessage(
        raw=_compose(frm=src.from_addr, display=src.from_display, to=src.to_addr,
                     subject=src.subject or "Payment",
                     body=rng.choice(_PAYMENT_BODIES),
                     auth=_auth_header(domain),
                     extra_headers=f"Reply-To: {handle}.finance{rng.randint(1,99)}@gmail.com"),
        label="attack", transform="reply_to_divert", target_layer=0,
        source_gmail_id=src.gmail_id, impersonated=src.from_addr,
    )


def t_auth_forgery(src: SourceMessage, rng: random.Random) -> SynthMessage | None:
    """Exact address, forged: the domain's own policy says it did not send this."""
    _, domain = split_address(src.from_addr)
    if not domain:
        return None
    return SynthMessage(
        raw=_compose(frm=src.from_addr, display=src.from_display, to=src.to_addr,
                     subject=src.subject or "Urgent",
                     body=rng.choice(_PAYMENT_BODIES),
                     auth=_auth_header(domain, result="fail", policy="REJECT"),
                     extra_headers="Return-Path: <bounce@cheap-vps.ru>"),
        label="attack", transform="auth_forgery", target_layer=0,
        source_gmail_id=src.gmail_id, impersonated=src.from_addr,
    )


def t_credential_link(src: SourceMessage, rng: random.Random) -> SynthMessage | None:
    _, domain = split_address(src.from_addr)
    if not domain:
        return None
    fake_host = rng.choice([
        "account-verify.pages.dev", "secure-login.workers.dev", "45.83.12.9",
        f"{domain}.secure-session.ru",
    ])
    html = (f"<p>{rng.choice(_CREDENTIAL_BODIES)}</p>"
            f'<a href="https://{fake_host}/account/login/verify">'
            f"https://{domain}/account</a>")
    return SynthMessage(
        raw=_compose(frm=src.from_addr, display=src.from_display, to=src.to_addr,
                     subject="Action required: verify your account",
                     body="", auth=_auth_header(domain), html=html),
        label="attack", transform="credential_link", target_layer=3,
        source_gmail_id=src.gmail_id, impersonated=src.from_addr,
    )


def t_dangerous_attachment(src: SourceMessage, rng: random.Random) -> SynthMessage | None:
    _, domain = split_address(src.from_addr)
    if not domain:
        return None
    name = rng.choice(["Invoice_8841.pdf.exe", "Statement.xlsx.scr", "Remittance.pdf.js"])
    return SynthMessage(
        raw=_compose(frm=src.from_addr, display=src.from_display, to=src.to_addr,
                     subject="Invoice attached", body="Please see the attached invoice.",
                     auth=_auth_header(domain), attachment=(name, "TVqQAAMAAAAEAAAA")),
        label="attack", transform="dangerous_attachment", target_layer=3,
        source_gmail_id=src.gmail_id, impersonated=src.from_addr,
    )


def t_style_swap(src: SourceMessage, rng: random.Random) -> SynthMessage | None:
    """Correct address, authenticated, different person at the keyboard.

    Models a compromised account: every signal below Layer 2 is genuine, so
    this transform is the only one that isolates fingerprinting. The substitute
    text is deliberately written in a register - long hedged clauses, formal
    connectives, no contractions - that differs structurally rather than
    topically, since topic is something an attacker controls freely.
    """
    _, domain = split_address(src.from_addr)
    if not domain:
        return None
    body = (
        "Dear Sir/Madam,\n\n"
        "I am writing to you in connection with an outstanding matter which "
        "requires your immediate consideration. It has come to our attention "
        "that the remittance particulars previously furnished are no longer "
        "operative, and accordingly we should be most grateful if you would "
        "arrange for the settlement to be directed to the revised account "
        "specified hereunder at your earliest convenience.\n\n"
        "We would respectfully request that this matter be treated as "
        "confidential pending the conclusion of the ongoing review.\n\n"
        "Yours faithfully"
    )
    return SynthMessage(
        raw=_compose(frm=src.from_addr, display=src.from_display, to=src.to_addr,
                     subject=f"Re: {src.subject}"[:120], body=body,
                     auth=_auth_header(domain),
                     x_mailer="PHPMailer 6.8.0",
                     message_id=f"{rng.randint(10**14, 10**15)}.0@webmail-cluster.example"),
        label="attack", transform="style_swap", target_layer=2,
        source_gmail_id=src.gmail_id, impersonated=src.from_addr,
    )


TRANSFORM_FNS: dict[str, Callable[[SourceMessage, random.Random], SynthMessage | None]] = {
    "display_name_freemail": t_display_name_freemail,
    "lookalike_domain": t_lookalike_domain,
    "reply_to_divert": t_reply_to_divert,
    "auth_forgery": t_auth_forgery,
    "credential_link": t_credential_link,
    "dangerous_attachment": t_dangerous_attachment,
    "style_swap": t_style_swap,
}


def generate(sources: list[SourceMessage], per_transform: int = 20,
             seed: int = 20250909,
             transforms: list[str] | None = None) -> list[SynthMessage]:
    """Build an attack set from genuine messages.

    One attack per (source, transform) at most, and sources are sampled without
    replacement per transform so the set is not twenty variations on one
    contact.
    """
    rng = random.Random(seed)
    chosen = transforms or list(TRANSFORM_FNS)
    out: list[SynthMessage] = []

    # One representative message per contact: repeats of the same correspondent
    # would let a detector look good by learning one relationship.
    by_contact: dict[str, SourceMessage] = {}
    for src in sources:
        key = canonical_address(src.from_addr)
        if key and key not in by_contact:
            by_contact[key] = src
    pool = list(by_contact.values())
    if not pool:
        return out

    for name in chosen:
        fn = TRANSFORM_FNS.get(name)
        if fn is None:
            continue
        candidates = pool[:]
        rng.shuffle(candidates)
        made = 0
        for src in candidates:
            if made >= per_transform:
                break
            try:
                msg = fn(src, rng)
            except Exception:
                continue
            if msg is not None:
                out.append(msg)
                made += 1
    return out
