"""Layer 1 - identity.

Where Layer 0 asks "is this envelope genuine?", Layer 1 asks "is this the
person it claims to be?" - and that is the question the product exists to
answer. Layer 0 is satisfied by `abdul@evil-abdul.com`; Layer 1 is not.

Every detector here compares the incoming message against the user's own
contact graph, so the answers are specific to this mailbox rather than to
phishing in general.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..parse.headers import canonical_address
from .base import Finding, Severity
from .context import AnalysisContext, ContactRef
from . import domains as D
from .view import MessageView


def run(view: MessageView, ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    if not view.from_addr:
        return out

    canon = canonical_address(view.from_addr)
    sender = ctx.contact_for(view.from_addr)
    from_domain = view.from_domain

    out += _display_name_impersonation(view, ctx, canon)
    out += _display_name_carries_address(view, canon)
    out += _domain_deception(view, ctx, from_domain)
    out += _domain_age(view, ctx, from_domain)
    out += _relationship(view, ctx, sender, canon)
    return out


# --------------------------------------------------- display-name identity

def _display_name_impersonation(
    view: MessageView, ctx: AnalysisContext, canon: str
) -> list[Finding]:
    """The flagship check, and the email twin of the voice-fingerprint case.

    Someone is writing under a name the user knows, from an address the user
    has never seen that name use. No history with the *sender* is required -
    only history with the person being imitated - which is what makes this work
    on first contact, precisely when phishing arrives.
    """
    name = (view.from_display or "").strip()
    if not name or "@" in name:
        return []

    targets = [t for t in ctx.impersonation_targets(name) if t.canonical_email != canon]

    # A large sender uses many addresses under one domain - automated@airbnb.com
    # and express@airbnb.com are both Airbnb, and treating either as an
    # impersonation of the other flagged 1,364 messages in a real 2,300-message
    # mailbox. Same organisational domain means same organisation.
    targets = [t for t in targets if not D.same_org(t.domain, view.from_domain)]
    if not targets:
        return []

    target = max(targets, key=lambda t: t.trust)
    known = ", ".join(t.canonical_email for t in targets[:3])
    sender_free = D.is_freemail(view.from_domain)
    target_free = D.is_freemail(target.domain)

    # A corporate identity arriving from a personal mailbox is the strongest
    # form of this: it is how payroll-diversion and invoice fraud start.
    if sender_free and not target_free:
        return [Finding(
            code="DISPLAY_NAME_IMPERSONATION_FREEMAIL", layer=1,
            severity=Severity.CRITICAL, weight=0.88,
            human_text=f'"{name}" normally writes to you from {target.canonical_email}. '
                       f"This message uses the same name but comes from a personal "
                       f"account, {view.from_addr}.",
            evidence={"display_name": name, "sender": view.from_addr,
                      "known_addresses": known, "target_trust": target.trust},
        )]

    severity = Severity.CRITICAL if target.trust >= 0.5 else Severity.HIGH
    weight = 0.85 if target.trust >= 0.5 else 0.68
    return [Finding(
        code="DISPLAY_NAME_IMPERSONATION", layer=1, severity=severity, weight=weight,
        human_text=f'This message is signed "{name}", but that name belongs to '
                   f"{known} in your contacts - not to {view.from_addr}.",
        evidence={"display_name": name, "sender": view.from_addr,
                  "known_addresses": known, "target_trust": target.trust},
    )]


def _display_name_carries_address(view: MessageView, canon: str) -> list[Finding]:
    """`From: "billing@paypal.com" <attacker@random.ru>`.

    Most mail clients show only the display name, so the address the user reads
    is the one the attacker typed, not the one that sent the mail.
    """
    name = view.from_display or ""
    if "@" not in name:
        return []
    embedded = [e for e in D.emails_in_text(name) if canonical_address(e) != canon]
    if not embedded:
        return []
    return [Finding(
        code="DISPLAY_NAME_IS_FOREIGN_ADDRESS", layer=1,
        severity=Severity.HIGH, weight=0.78,
        human_text=f"The sender is displayed as \"{embedded[0]}\", but the message was "
                   f"actually sent by {view.from_addr}.",
        evidence={"displayed_as": embedded[0], "actual": view.from_addr},
    )]


# ------------------------------------------------------------ domain shape

def _domain_deception(
    view: MessageView, ctx: AnalysisContext, from_domain: str
) -> list[Finding]:
    out: list[Finding] = []
    if not from_domain:
        return out

    homoglyph = D.homoglyph_check(from_domain)
    if homoglyph:
        kind, detail = homoglyph
        out.append(Finding(
            code="HOMOGLYPH_DOMAIN", layer=1, severity=Severity.CRITICAL, weight=0.90,
            human_text=f"The sender's domain uses characters from more than one alphabet "
                       f"to look like an ordinary name ({detail}). Legitimate domains do "
                       f"not do this.",
            evidence={"kind": kind, "domain": from_domain, "detail": detail},
        ))

    match = ctx.nearest_reference_domain(from_domain)
    if match:
        known, kind, confidence = match
        out.append(_lookalike_finding(view, from_domain, known, kind, confidence))
    return out


_LOOKALIKE_TEXT = {
    "visual": ("is built to be misread as", Severity.CRITICAL, 0.90),
    "typo": ("is one character away from", Severity.HIGH, 0.80),
    "tld_swap": ("reuses the name of", Severity.HIGH, 0.72),
    "cousin": ("is a variation on", Severity.HIGH, 0.68),
}


def _lookalike_finding(
    view: MessageView, from_domain: str, known: str, kind: str, confidence: float
) -> Finding:
    phrase, severity, base = _LOOKALIKE_TEXT.get(kind, _LOOKALIKE_TEXT["cousin"])
    return Finding(
        code=f"LOOKALIKE_DOMAIN_{kind.upper()}", layer=1, severity=severity,
        weight=round(base * confidence + (1 - confidence) * 0.3, 3),
        human_text=f"The sender's domain {D.org_domain(from_domain)} {phrase} {known}, "
                   f"a domain you actually correspond with.",
        evidence={"from_domain": from_domain, "resembles": known,
                  "kind": kind, "confidence": confidence},
    )


def _domain_age(view: MessageView, ctx: AnalysisContext, from_domain: str) -> list[Finding]:
    """Registration age, when `analyze --online` has filled the intel cache.

    Phishing infrastructure is disposable: domains are registered days before a
    campaign and burned after it. Age is one of the few cheap signals that is
    genuinely hard for an attacker to fake.
    """
    if not from_domain:
        return []
    intel = ctx.domain_intel.get(D.org_domain(from_domain))
    if not intel or not intel.get("created_at"):
        return []
    try:
        created = datetime.fromisoformat(str(intel["created_at"]).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return []
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - created).days
    if age_days > 60:
        return []

    if age_days <= 7:
        severity, weight = Severity.HIGH, 0.72
    elif age_days <= 30:
        severity, weight = Severity.HIGH, 0.62
    else:
        severity, weight = Severity.MEDIUM, 0.40
    return [Finding(
        code="NEWLY_REGISTERED_DOMAIN", layer=1, severity=severity, weight=weight,
        human_text=f"{D.org_domain(from_domain)} was registered {age_days} day"
                   f"{'s' if age_days != 1 else ''} ago. Domains used for fraud are "
                   f"typically brand new.",
        evidence={"domain": D.org_domain(from_domain), "age_days": age_days,
                  "created_at": intel["created_at"]},
    )]


# ------------------------------------------------------------ relationship

def _relationship(
    view: MessageView, ctx: AnalysisContext, sender: ContactRef | None, canon: str
) -> list[Finding]:
    """Prior history with this exact address.

    Deliberately weak on its own. First contact is not suspicious - most
    legitimate mail from a new supplier, recruiter or service is first contact
    too. It earns its place by compounding: first contact *plus* a lookalike
    domain *plus* a failed DMARC check is a different message from any one of
    those alone.
    """
    if sender is None or (sender.inbound + sender.outbound) <= 1:
        return [Finding(
            code="FIRST_CONTACT", layer=1, severity=Severity.INFO, weight=0.15,
            human_text="You have not corresponded with this address before.",
            evidence={"sender": view.from_addr},
        )]

    if sender.outbound > 0:
        return [Finding(
            code="ESTABLISHED_CORRESPONDENT", layer=1, severity=Severity.INFO,
            weight=0.55, mitigating=True, scope=frozenset({1}),
            human_text=f"You have exchanged mail with {sender.canonical_email} before "
                       f"({sender.outbound} sent, {sender.inbound} received).",
            evidence={"sender": sender.canonical_email, "outbound": sender.outbound,
                      "inbound": sender.inbound, "trust": sender.trust},
        )]

    if sender.inbound >= 5:
        return [Finding(
            code="RECURRING_SENDER", layer=1, severity=Severity.INFO,
            weight=0.30, mitigating=True, scope=frozenset({1}),
            human_text=f"This address has written to you {sender.inbound} times before.",
            evidence={"sender": sender.canonical_email, "inbound": sender.inbound},
        )]
    return []
