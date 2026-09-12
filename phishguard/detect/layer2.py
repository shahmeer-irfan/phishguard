"""Layer 2 - sender fingerprinting.

Layer 1 asks "is this address the person it claims to be?" and answers it from
the contact graph. Layer 2 asks a harder question: *this really is their
address - is it really them?*

That is the only layer that catches a genuinely compromised account, where the
envelope authenticates, the address is right, the thread is real, and the only
thing out of place is that someone else is typing.

Two rules shape everything here:

**One mismatch is not evidence.** People buy phones, change clients, travel,
and write differently at 2am. A single differing dimension is background noise;
the signal is several dimensions moving together, and the weights below are
built around that.

**A mid-thread change is the strongest form.** If a contact's technical
fingerprint is stable for two years and then shifts inside a live thread that is
asking about payment, that is account takeover, and it is worth far more than
the same shift on a cold message.
"""

from __future__ import annotations

from .base import Finding, Severity
from .context import AnalysisContext
from . import fingerprint as FP
from .view import MessageView

# A dimension seen in under this share of history is "unusual"; absent entirely
# is "new". Both are reported, but only "new" carries real weight.
RARE_SHARE = 0.10

# Style z-score thresholds, in units of the contact's own variance.
#
# Set from measured separation rather than from the usual statistical
# conventions: on a held-out split, genuine messages from a contact topped out
# at z=0.57 while a substituted writer started at z=1.19. The textbook "3 sigma"
# would have caught nothing at all, because the z here is already deflated by
# the small-sample variance floor and the short-message discount.
#
# These are calibrated against one synthetic writer pair and MUST be re-tuned
# against a real mailbox - that is what `phishguard evaluate` is for.
STYLE_Z_NOTABLE = 1.2
STYLE_Z_STRONG = 2.0
STYLE_Z_MATCH = 0.8

_DIMENSION_LABELS = {
    "x_mailers": "mail app",
    "msgid_shapes": "message formatting",
    "mime_signatures": "message structure",
    "header_orders": "header layout",
    "tz_offsets": "time zone",
    "origin_orgs": "sending server",
    "dkim_domains": "signing domain",
}


def run(view: MessageView, ctx: AnalysisContext) -> list[Finding]:
    profile = ctx.profile_for(view.from_addr) if view.from_addr else None
    if profile is None:
        return []

    out: list[Finding] = []
    out += _technical(view, profile)
    out += _style(view, profile)
    out += _behaviour(view, profile)
    return out


# ------------------------------------------------------------- technical

def observed_dimensions(view: MessageView) -> dict[str, str | None]:
    """The incoming message's technical fingerprint, keyed like the profile."""
    from . import domains as D

    origin = view.origin_hop
    origin_org = D.org_domain(origin.from_host) if origin and origin.from_host else None
    return {
        "x_mailers": view.x_mailer or view.user_agent,
        "msgid_shapes": FP.message_id_shape(view.rfc822_message_id) or None,
        "mime_signatures": view.mime_signature or None,
        "header_orders": view.header_order_hash or None,
        "tz_offsets": str(view.date_tz_offset) if view.date_tz_offset is not None else None,
        "origin_orgs": origin_org,
        "dkim_domains": view.dkim_domain,
    }


def _technical(view: MessageView, profile: FP.ContactProfile) -> list[Finding]:
    if not profile.usable_technical:
        return []

    tech = profile.technical
    observed = observed_dimensions(view)

    novel: list[str] = []      # never seen from this contact
    rare: list[str] = []       # seen, but rarely
    compared = 0

    for dim, value in observed.items():
        if value is None or not getattr(tech, dim):
            continue           # nothing to compare against on this dimension
        compared += 1
        if not tech.is_known(dim, value):
            novel.append(dim)
        elif tech.share(dim, value) < RARE_SHARE:
            rare.append(dim)

    if compared < 3 or not novel:
        return []

    labels = [_DIMENSION_LABELS.get(d, d) for d in novel]
    phrase = ", ".join(labels[:-1]) + f" and {labels[-1]}" if len(labels) > 1 else labels[0]
    mid_thread = bool(view.in_reply_to)

    # One changed dimension is a new phone. Three is a different machine.
    if len(novel) >= 4:
        severity, weight = Severity.CRITICAL, 0.86
    elif len(novel) == 3:
        severity, weight = Severity.HIGH, 0.74
    elif len(novel) == 2:
        severity, weight = Severity.MEDIUM, 0.50
    else:
        severity, weight = Severity.LOW, 0.26

    if mid_thread and len(novel) >= 2:
        # Inside a live conversation the innocent explanations mostly evaporate:
        # the previous message in this same thread came from the old setup.
        severity = Severity.CRITICAL if len(novel) >= 3 else Severity.HIGH
        weight = min(0.92, weight + 0.18)
        text = (f"This reply arrives from a different setup than the rest of the "
                f"conversation ({phrase}). Mid-thread changes like this are what an "
                f"account takeover looks like.")
    else:
        text = (f"This message was not produced the way {profile.canonical_email} "
                f"normally sends mail ({phrase} all differ from their {tech.samples} "
                f"previous messages).")

    return [Finding(
        code="TECHNICAL_FINGERPRINT_MISMATCH", layer=2, severity=severity, weight=weight,
        human_text=text,
        evidence={"novel_dimensions": novel, "rare_dimensions": rare,
                  "compared": compared, "history_samples": tech.samples,
                  "mid_thread": mid_thread,
                  "observed": {k: v for k, v in observed.items() if v}},
    )]


# ----------------------------------------------------------------- style

def _style(view: MessageView, profile: FP.ContactProfile) -> list[Finding]:
    if not profile.usable_style:
        return []
    body = FP.strip_quoted(view.body_text or "")
    if len(FP._WORD_RE.findall(body)) < FP.MIN_WORDS_FOR_STYLE:
        return []      # too short to characterise; silence beats a guess

    similarity = profile.style.similarity(view.body_text or "")
    if similarity is None:
        return []
    z = profile.style.z_score(similarity, n_words=len(FP._WORD_RE.findall(body)))

    out: list[Finding] = []
    if z >= STYLE_Z_STRONG:
        out.append(Finding(
            code="WRITING_STYLE_MISMATCH", layer=2, severity=Severity.HIGH, weight=0.72,
            human_text=f"This does not read like {profile.canonical_email}'s writing. "
                       f"Sentence length, punctuation and word choice are well outside "
                       f"how they have written in {profile.style.samples} previous "
                       f"messages.",
            evidence={"similarity": round(similarity, 4), "z": round(z, 2),
                      "baseline": profile.style.self_similarity_mean,
                      "samples": profile.style.samples},
        ))
    elif z >= STYLE_Z_NOTABLE:
        out.append(Finding(
            code="WRITING_STYLE_UNUSUAL", layer=2, severity=Severity.MEDIUM, weight=0.42,
            human_text=f"The writing style here is noticeably different from "
                       f"{profile.canonical_email}'s usual messages.",
            evidence={"similarity": round(similarity, 4), "z": round(z, 2),
                      "baseline": profile.style.self_similarity_mean},
        ))
    elif z <= STYLE_Z_MATCH:
        out.append(Finding(
            code="WRITING_STYLE_MATCH", layer=2, severity=Severity.INFO,
            weight=0.45, mitigating=True, scope=frozenset({1, 2}),
            human_text=f"The writing style matches {profile.canonical_email}'s previous "
                       f"messages.",
            evidence={"similarity": round(similarity, 4), "z": round(z, 2)},
        ))

    # Greeting and sign-off are habits people rarely vary and impersonators
    # rarely know. Only meaningful once the habit is actually established.
    greeting = FP.greeting_of(view.body_text or "")
    known_greetings = profile.style.greetings
    if greeting and known_greetings and sum(known_greetings.values()) >= 4:
        if greeting not in known_greetings:
            out.append(Finding(
                code="UNFAMILIAR_GREETING", layer=2, severity=Severity.LOW, weight=0.30,
                human_text=f"This message opens with \"{greeting}\", which "
                           f"{profile.canonical_email} has never used with you - they "
                           f"normally write \"{max(known_greetings, key=known_greetings.get)}\".",
                evidence={"greeting": greeting, "known": sorted(known_greetings)},
            ))
    return out


# ------------------------------------------------------------- behaviour

def _behaviour(view: MessageView, profile: FP.ContactProfile) -> list[Finding]:
    """Firsts in a long relationship.

    Weak individually and deliberately so - everyone sends a first attachment
    eventually. These exist to compound with the layers above, which is exactly
    how the invoice-fraud pattern presents: a correspondent of two years who has
    never once sent a payment document suddenly sends one.
    """
    rel = profile.relationship
    if rel.messages < 8:
        return []

    out: list[Finding] = []
    has_attachments = any(not a.is_inline for a in view.attachments)

    if has_attachments and not rel.ever_sent_attachments:
        out.append(Finding(
            code="FIRST_EVER_ATTACHMENT", layer=2, severity=Severity.MEDIUM, weight=0.40,
            human_text=f"{profile.canonical_email} has written to you {rel.messages} times "
                       f"and never attached a file before.",
            evidence={"history": rel.messages},
        ))

    if view.body_html or view.body_text:
        from . import layer3
        links = layer3.extract_links(view)
        web = [l for l in links if l.is_web and l.org]
        if web and not rel.ever_sent_links:
            out.append(Finding(
                code="FIRST_EVER_LINK", layer=2, severity=Severity.MEDIUM, weight=0.38,
                human_text=f"{profile.canonical_email} has never sent you a link before "
                           f"in {rel.messages} messages.",
                evidence={"history": rel.messages,
                          "orgs": sorted({l.org for l in web})[:5]},
            ))
        elif web and rel.link_orgs:
            unseen = sorted({l.org for l in web} - set(rel.link_orgs))
            if unseen and len(rel.link_orgs) >= 3:
                out.append(Finding(
                    code="UNFAMILIAR_LINK_TARGET", layer=2, severity=Severity.LOW,
                    weight=0.30,
                    human_text=f"This message links to {unseen[0]}, which "
                               f"{profile.canonical_email} has not linked to before.",
                    evidence={"unseen": unseen[:5], "usual": sorted(rel.link_orgs)[:5]},
                ))
    return out
