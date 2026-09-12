"""Layer 3 - content and payload.

Layers 0 and 1 judge who sent the message. This one judges what it is asking
the user to do: click a link, open a file, or scan a code. That is where the
attack actually lands, and it is the only layer that still works when the
sender is a genuinely compromised account - in that case the envelope is real,
the identity is real, and the payload is the sole thing out of place.

Layer 2 (sender fingerprinting) is intentionally not here; it is Phase 3.
"""

from __future__ import annotations

from .base import Finding, Severity, Tier
from .content import HtmlAnalysis
from .context import AnalysisContext
from . import attachments as A
from . import domains as D
from . import qr as QR
from . import urls as U
from .view import MessageView

# Beyond this many links, per-link findings are summarised rather than listed:
# a newsletter with 80 links should not produce 80 rows in the UI.
MAX_LINK_FINDINGS = 6


def run(view: MessageView, ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []

    html = view.html()
    links = _collect_links(view, html)

    out += _link_findings(links, ctx, view)
    out += _html_findings(html, view, ctx)
    out += _attachment_findings(view)
    out += _qr_findings(view, html, ctx)
    return out


def extract_links(view: MessageView) -> list[U.Link]:
    """Public entry point for the link corpus the engine stores."""
    return _collect_links(view, view.html())


def _collect_links(view: MessageView, html: HtmlAnalysis) -> list[U.Link]:
    """Links from the HTML part plus any the plain-text part carries alone.

    Both parts are read because the two are allowed to disagree, and a
    discrepancy between what the HTML renders and what the text alternative
    says is itself the trick in some kits.
    """
    links = list(html.links)
    seen = {(l.href or "").strip().lower() for l in links}
    for link in U.extract_from_text(view.body_text):
        key = (link.href or "").strip().lower()
        if key not in seen:
            seen.add(key)
            links.append(link)
    if html.meta_refresh:
        refresh = U.parse_link(html.meta_refresh, source="meta_refresh")
        if refresh:
            links.append(refresh)
    return links


# ------------------------------------------------------------------- links

def _link_findings(links: list[U.Link], ctx: AnalysisContext,
                   view: MessageView) -> list[Finding]:
    out: list[Finding] = []
    reference = set(ctx.reference_domains)
    emitted: set[str] = set()

    # A verified sender is allowed to rewrite its own links through a tracker.
    # Without DMARC the same rewrite proves nothing, so the exemption is not
    # granted - an attacker can put any anchor text in front of any tracker.
    sender_verified = (view.dmarc or "").lower() == "pass"

    def once(code: str) -> bool:
        """One finding per kind, however many links trigger it."""
        if code in emitted:
            return False
        emitted.add(code)
        return True

    for link in links:
        if link.scheme in U.DANGEROUS_SCHEMES and once("URL_DANGEROUS_SCHEME"):
            out.append(Finding(
                code="URL_DANGEROUS_SCHEME", layer=3, severity=Severity.HIGH, weight=0.75,
                human_text=f"A link in this message runs code or embeds content directly "
                           f"({link.scheme}:) instead of opening a web page.",
                evidence={"href": link.display, "scheme": link.scheme},
            ))
            continue

        if not link.is_web or not link.host:
            continue

        # The userinfo trick: everything before '@' is ignored by the browser,
        # so the visible "paypal.com" is decoration and evil.com is the host.
        if link.userinfo and once("URL_USERINFO_TRICK"):
            out.append(Finding(
                code="URL_USERINFO_TRICK", layer=3, severity=Severity.CRITICAL, weight=0.85,
                human_text=f"A link is written to look like it goes to "
                           f"\"{link.userinfo[:40]}\" but actually goes to {link.host}.",
                evidence={"href": link.display, "userinfo": link.userinfo[:80],
                          "real_host": link.host},
            ))

        tracked = sender_verified and U.is_tracker(link)

        claimed = U.anchor_claims_other_domain(link)
        if claimed and not tracked and once("URL_ANCHOR_MISMATCH"):
            out.append(Finding(
                code="URL_ANCHOR_MISMATCH", layer=3, severity=Severity.HIGH, weight=0.74,
                human_text=f"A link says it goes to {claimed} but actually goes to "
                           f"{link.host}.",
                evidence={"claimed": claimed, "real_host": link.host,
                          "anchor_text": link.anchor_text[:80]},
            ))

        homoglyph = D.homoglyph_check(link.host)
        if homoglyph and once("URL_HOMOGLYPH"):
            out.append(Finding(
                code="URL_HOMOGLYPH", layer=3, severity=Severity.CRITICAL, weight=0.88,
                human_text=f"A link uses a web address built from mixed alphabets to "
                           f"impersonate an ordinary one ({homoglyph[1]}).",
                evidence={"host": link.host, "detail": homoglyph[1]},
            ))

        if reference and link.org and link.org not in reference:
            match = ctx.nearest_reference_domain(link.host)
            if match and once("URL_LOOKALIKE_DOMAIN"):
                known, kind, confidence = match
                out.append(Finding(
                    code="URL_LOOKALIKE_DOMAIN", layer=3, severity=Severity.HIGH,
                    weight=round(0.78 * confidence, 3),
                    human_text=f"A link points to {link.org}, which imitates {known} - "
                               f"a domain you actually use.",
                    evidence={"host": link.host, "resembles": known, "kind": kind},
                ))

        brand = U.brand_in_subdomain(link, reference)
        if brand and once("URL_BRAND_IN_SUBDOMAIN"):
            out.append(Finding(
                code="URL_BRAND_IN_SUBDOMAIN", layer=3, severity=Severity.HIGH, weight=0.76,
                human_text=f"A link reads like {brand} at first glance, but the address "
                           f"it really opens is {link.org}.",
                evidence={"host": link.host, "brand": brand, "real_org": link.org},
            ))

        if U.is_ip_host(link.host) and once("URL_IP_HOST"):
            out.append(Finding(
                code="URL_IP_HOST", layer=3, severity=Severity.HIGH, weight=0.62,
                human_text=f"A link points straight at a numeric server address "
                           f"({link.host}) rather than a named website.",
                evidence={"host": link.host},
            ))

        redirect = U.open_redirect_target(link)
        if redirect:
            # airbnb.com forwarding to airbnb.sng.link is a deep-link service,
            # not a borrowed reputation. Only cross-organisation hops matter.
            target = U.parse_link(redirect, source="redirect")
            same_brand = bool(target and target.org and (
                target.org == link.org
                or D.registrable_label(target.org) == D.registrable_label(link.org)))
            if same_brand:
                redirect = None
        if redirect and tracked:
            redirect = None
        if redirect and once("URL_OPEN_REDIRECT"):
            out.append(Finding(
                code="URL_OPEN_REDIRECT", layer=3, severity=Severity.MEDIUM, weight=0.52,
                human_text=f"A link passes through {link.org} and then forwards somewhere "
                           f"else ({redirect[:60]}), borrowing a trusted name.",
                evidence={"host": link.host, "redirects_to": redirect[:200]},
            ))

        if U.is_shortener(link) and once("URL_SHORTENER"):
            out.append(Finding(
                code="URL_SHORTENER", layer=3, severity=Severity.LOW, weight=0.32,
                human_text=f"A link is hidden behind a shortener ({link.org}), so its real "
                           f"destination cannot be checked before clicking.",
                evidence={"href": link.display, "shortener": link.org},
            ))

        host_suffix = U.free_hosting_suffix(link)
        if host_suffix and once("URL_FREE_HOSTING"):
            out.append(Finding(
                code="URL_FREE_HOSTING", layer=3, severity=Severity.MEDIUM, weight=0.45,
                human_text=f"A link points to a page on {host_suffix}, a free hosting "
                           f"service commonly used for fake sign-in pages.",
                evidence={"host": link.host, "platform": host_suffix},
            ))

        # Credential wording is only interesting off a domain the user trusts;
        # on a known domain it is just the real login page.
        if link.org not in reference and not tracked:
            words = U.credential_words_in(link)
            if len(words) >= 2 and once("URL_CREDENTIAL_PATH"):
                out.append(Finding(
                    code="URL_CREDENTIAL_PATH", layer=3, severity=Severity.MEDIUM, weight=0.48,
                    human_text=f"A link on {link.org} leads to a sign-in or account page "
                               f"({', '.join(words[:3])}) on a site you do not normally use.",
                    evidence={"host": link.host, "words": words[:6]},
                ))

        if link.port and link.port not in (80, 443) and once("URL_NONSTANDARD_PORT"):
            out.append(Finding(
                code="URL_NONSTANDARD_PORT", layer=3, severity=Severity.LOW, weight=0.34,
                human_text=f"A link connects on an unusual network port ({link.port}), "
                           f"which normal websites do not use.",
                evidence={"host": link.host, "port": link.port},
            ))

        if len(out) >= MAX_LINK_FINDINGS * 2:
            break
    return out


# -------------------------------------------------------------------- HTML

def _html_findings(html: HtmlAnalysis, view: MessageView,
                   ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []

    for form in html.forms:
        action = U.parse_link(form.action, source="form_action")
        if form.has_password_input:
            out.append(Finding(
                code="HTML_CREDENTIAL_FORM", layer=3, severity=Severity.CRITICAL,
                weight=0.90, hard_tier=Tier.DANGER,
                human_text="This message contains a password box inside the email itself. "
                           "No legitimate organisation asks you to type a password into a "
                           "message.",
                evidence={"action": form.action[:200],
                          "inputs": form.input_names[:8]},
            ))
            break
        if action and action.is_web and action.org and action.org != D.org_domain(view.from_domain):
            out.append(Finding(
                code="HTML_FORM_OFFSITE", layer=3, severity=Severity.HIGH, weight=0.68,
                human_text=f"This message contains a form that sends whatever you type to "
                           f"{action.org}.",
                evidence={"action": form.action[:200], "target_org": action.org,
                          "inputs": form.input_names[:8]},
            ))
            break

    # Concealed text is filter poisoning: bulk innocuous words invisible to the
    # reader, there to dilute the message for statistical spam classifiers.
    # Almost every marketing email hides a preheader line, and many hide a
    # whole accessibility block. This fired 1,197 times on a real mailbox. Only
    # treat it as filter poisoning when the hidden text *dominates* the message
    # and there is enough of it to actually shift a classifier.
    if len(html.hidden_text) >= 1500 and len(html.hidden_text) > html.visible_chars * 1.5:
        out.append(Finding(
            code="HTML_HIDDEN_TEXT", layer=3, severity=Severity.MEDIUM, weight=0.46,
            human_text=f"This message hides {len(html.hidden_text)} characters of text that "
                       f"you cannot see, a trick used to slip past spam filters.",
            evidence={"hidden_chars": len(html.hidden_text),
                      "visible_chars": html.visible_chars,
                      "sample": html.hidden_text[:160]},
        ))

    # Text baked into a picture cannot be read by any text-based check - which
    # is exactly why it is done.
    images = html.inline_images
    if images and html.visible_chars < 60 and len(view.body_text.strip()) < 100:
        out.append(Finding(
            code="HTML_IMAGE_ONLY", layer=3, severity=Severity.MEDIUM, weight=0.44,
            human_text="This message is almost entirely a picture with no real text, which "
                       "prevents its contents from being checked.",
            evidence={"images": len(images), "visible_chars": html.visible_chars},
        ))

    if html.meta_refresh:
        out.append(Finding(
            code="HTML_META_REFRESH", layer=3, severity=Severity.MEDIUM, weight=0.50,
            human_text="This message tries to redirect you automatically to another page.",
            evidence={"target": html.meta_refresh[:200]},
        ))
    return out


# ------------------------------------------------------------- attachments

def _attachment_findings(view: MessageView) -> list[Finding]:
    out: list[Finding] = []
    body = f"{view.body_text}\n{view.subject}"

    for att in view.attachments:
        if att.is_inline and not att.filename:
            continue
        name = att.filename or "(unnamed)"

        override = A.bidi_override_in(att.filename)
        if override:
            out.append(Finding(
                code="ATTACHMENT_RLO_FILENAME", layer=3, severity=Severity.CRITICAL,
                weight=0.95, hard_tier=Tier.DANGER,
                human_text=f"An attachment's filename is rigged to display backwards, so "
                           f"it appears as \"{A.rendered_name(att.filename)[:50]}\" while "
                           f"actually being a {att.extension.upper()} file.",
                evidence={"filename": att.clean_name, "override": override,
                          "real_extension": att.extension},
            ))
            continue

        pair = A.double_extension(att)
        if pair:
            decoy, real = pair
            out.append(Finding(
                code="ATTACHMENT_DOUBLE_EXTENSION", layer=3, severity=Severity.CRITICAL,
                weight=0.92,
                human_text=f"\"{name}\" looks like a {decoy.upper()} but is actually a "
                           f"{real.upper()} program.",
                evidence={"filename": name, "decoy": decoy, "real": real},
            ))
            continue

        kind = A.category(att.extension)
        if kind == "executable":
            out.append(Finding(
                code="ATTACHMENT_EXECUTABLE", layer=3, severity=Severity.CRITICAL, weight=0.90,
                human_text=f"\"{name}\" is a program. Opening it runs code on your Mac.",
                evidence={"filename": name, "extension": att.extension},
            ))
        elif kind == "script":
            out.append(Finding(
                code="ATTACHMENT_SCRIPT", layer=3, severity=Severity.CRITICAL, weight=0.88,
                human_text=f"\"{name}\" is a script file that runs commands when opened.",
                evidence={"filename": name, "extension": att.extension},
            ))
        elif kind == "container":
            out.append(Finding(
                code="ATTACHMENT_CONTAINER", layer=3, severity=Severity.HIGH, weight=0.72,
                human_text=f"\"{name}\" is a disk-image or shortcut file. These are used to "
                           f"carry programs past security warnings.",
                evidence={"filename": name, "extension": att.extension},
            ))
        elif kind == "macro_office":
            out.append(Finding(
                code="ATTACHMENT_MACRO_DOCUMENT", layer=3, severity=Severity.HIGH, weight=0.74,
                human_text=f"\"{name}\" is a document that can run macros - small embedded "
                           f"programs.",
                evidence={"filename": name, "extension": att.extension},
            ))
        elif kind == "web":
            out.append(Finding(
                code="ATTACHMENT_HTML", layer=3, severity=Severity.HIGH, weight=0.72,
                human_text=f"\"{name}\" is a web page sent as a file. These usually open a "
                           f"fake sign-in form directly on your machine, where no website "
                           f"address is visible to check.",
                evidence={"filename": name, "extension": att.extension},
            ))
        elif kind == "archive" and A.mentions_password(body):
            out.append(Finding(
                code="ATTACHMENT_LOCKED_ARCHIVE", layer=3, severity=Severity.HIGH, weight=0.74,
                human_text=f"\"{name}\" is a password-protected archive and the password is "
                           f"in the message. Locking it this way stops it being scanned.",
                evidence={"filename": name, "extension": att.extension},
            ))
        elif kind == "onenote":
            out.append(Finding(
                code="ATTACHMENT_ONENOTE", layer=3, severity=Severity.HIGH, weight=0.70,
                human_text=f"\"{name}\" is a OneNote file, a format frequently used to hide "
                           f"clickable programs inside a document.",
                evidence={"filename": name, "extension": att.extension},
            ))

        mismatch = A.type_mismatch(att)
        if mismatch:
            ext, actual = mismatch
            out.append(Finding(
                code="ATTACHMENT_TYPE_MISMATCH", layer=3, severity=Severity.MEDIUM, weight=0.48,
                human_text=f"\"{name}\" is labelled as a .{ext} file but is actually sent as "
                           f"{actual}.",
                evidence={"filename": name, "extension": ext, "content_type": actual},
            ))
    return out


# ---------------------------------------------------------------------- QR

def _qr_findings(view: MessageView, html: HtmlAnalysis,
                 ctx: AnalysisContext) -> list[Finding]:
    """Codes carry URLs, so a decoded payload is re-run through the link checks.

    Without that the detector would only be able to say "there is a QR code
    here", which is true of a great many legitimate newsletters.
    """
    # Only images whose bytes are actually in the message count. A remote
    # <img src="https://cdn..."> cannot be scanned at all: we will not fetch it
    # (that would leak the open to the sender's server), so reporting it as
    # "unscanned" would fire on every newsletter with a logo and mean nothing.
    embedded = [a for a in view.attachments if (a.content_type or "").startswith("image/")]
    data_uri_images = [i for i in html.inline_images if i.is_data_uri]
    if not embedded and not data_uri_images:
        return []

    # The signature of an image-borne payload is that the image *is* the
    # message. A logo above two paragraphs of prose is not that.
    text_is_thin = html.visible_chars < 200 and len(view.body_text.strip()) < 200
    if not text_is_thin:
        return []

    if not QR.available():
        return [Finding(
            code="QR_UNSCANNED_IMAGE", layer=3, severity=Severity.INFO, weight=0.18,
            human_text="This message delivers its content as an image, so any code or link "
                       "inside it could not be checked.",
            evidence={"images": len(embedded) or len(data_uri_images),
                      "reason": "qr decoding unavailable"},
        )]

    payloads = QR.decode_all(view.image_payloads())
    if not payloads:
        return []

    out: list[Finding] = []
    for payload in payloads[:3]:
        link = U.parse_link(payload, source="qr")
        if link is None or not link.is_web:
            out.append(Finding(
                code="QR_CODE_PRESENT", layer=3, severity=Severity.LOW, weight=0.30,
                human_text="This message contains a QR code, which hides where it leads "
                           "until it is scanned.",
                evidence={"payload": payload[:120]},
            ))
            continue

        known = link.org in ctx.reference_domains
        severity = Severity.LOW if known else Severity.HIGH
        weight = 0.28 if known else 0.70
        out.append(Finding(
            code="QR_CODE_URL", layer=3, severity=severity, weight=weight,
            human_text=f"This message contains a QR code that opens {link.host}"
                       + ("." if known else ", a site you have no history with. Scanning it "
                                            "would move you onto your phone, away from these "
                                            "checks."),
            evidence={"host": link.host, "url": link.href[:200], "known_domain": known},
        ))
        # The decoded destination is a link like any other.
        out += _link_findings([link], ctx, view)
    return out
