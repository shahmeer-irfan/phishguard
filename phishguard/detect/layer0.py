"""Layer 0 - protocol truth.

Cryptographic and routing facts only. No content, no contact graph, no
guessing. These detectors are the cheapest and the most precise in the system,
which is why they run first and why one of them can short-circuit the verdict.

The load-bearing distinction: SPF and DKIM authenticate *domains*, never
people. `abdul@evil-abdul.com` passes all three checks perfectly. Layer 0 tells
you the envelope is genuine; it cannot tell you the human is.
"""

from __future__ import annotations

import re

from .base import Finding, Severity, Tier
from .context import AnalysisContext
from . import domains as D
from .view import MessageView

# Domains that sign outbound mail for other organisations by design.
_DELEGATED_SIGNERS = {
    "gappssmtp.com", "amazonses.com", "sendgrid.net", "mailgun.org",
    "mcsv.net", "mcdlv.net", "rsgsv.net", "sparkpostmail.com", "mandrillapp.com",
    "postmarkapp.com", "sendinblue.com", "brevo.com", "zoho.com", "hubspot.com",
    "salesforce.com", "intercom.io", "customeriomail.com", "klaviyomail.com",
    "mailchimp.com", "constantcontact.com", "icloud.com", "outlook.com",
}

_DMARC_POLICY_RE = re.compile(r"dmarc\s*=\s*\w+[^;]*?\bp\s*=\s*(\w+)", re.I)
_PASS = {"pass"}
_FAIL = {"fail", "permerror"}
_SOFT = {"softfail", "neutral", "none", "temperror"}


def dmarc_policy(view: MessageView) -> str | None:
    """The domain's published DMARC policy, lifted from the comment Google
    leaves in Authentication-Results: `dmarc=fail (p=REJECT sp=REJECT ...)`.

    It matters enormously. A DMARC failure against `p=none` is a
    misconfiguration; the same failure against `p=reject` is the domain owner
    explicitly stating this mail is forged.
    """
    if not view.auth_raw:
        return None
    m = _DMARC_POLICY_RE.search(" ".join(view.auth_raw.split()))
    return m.group(1).lower() if m else None


def run(view: MessageView, ctx: AnalysisContext) -> list[Finding]:
    out: list[Finding] = []
    from_domain = view.from_domain
    from_org = D.org_domain(from_domain)

    if not view.auth_present:
        out.append(Finding(
            code="AUTH_RESULTS_MISSING", layer=0, severity=Severity.LOW, weight=0.20,
            human_text="This message carries no delivery authentication record, so "
                       "there is no proof of who sent it.",
            evidence={"from_domain": from_domain},
        ))
        return out + _divergence(view, ctx, dmarc_ok=False)

    dmarc = (view.dmarc or "").lower()
    spf = (view.spf or "").lower()
    dkim = (view.dkim or "").lower()
    policy = dmarc_policy(view)
    dmarc_ok = dmarc in _PASS

    # ------------------------------------------------------------- DMARC

    if dmarc in _FAIL and policy in ("reject", "quarantine"):
        out.append(Finding(
            code="DMARC_FAIL_ENFORCED", layer=0, severity=Severity.CRITICAL, weight=0.95,
            hard_tier=Tier.DANGER,
            human_text=f"{from_domain} publishes a strict anti-forgery policy, and this "
                       f"message fails it. The real {from_domain} did not send this.",
            evidence={"dmarc": dmarc, "policy": policy, "from_domain": from_domain},
        ))
    elif dmarc in _FAIL:
        out.append(Finding(
            code="DMARC_FAIL", layer=0, severity=Severity.HIGH, weight=0.75,
            human_text=f"This message claims to be from {from_domain} but fails that "
                       f"domain's authentication checks.",
            evidence={"dmarc": dmarc, "policy": policy},
        ))
    elif dmarc in _SOFT or not dmarc:
        # No DMARC verdict is normal for older domains. It only becomes
        # interesting when nothing else vouches for the sender either.
        if spf not in _PASS and dkim not in _PASS:
            out.append(Finding(
                code="UNAUTHENTICATED_SENDER", layer=0, severity=Severity.MEDIUM, weight=0.50,
                human_text=f"Nothing verifies that this message really came from "
                           f"{from_domain}: no signature and no authorised sending server.",
                evidence={"spf": spf or None, "dkim": dkim or None, "dmarc": dmarc or None},
            ))

    # --------------------------------------------------------- SPF / DKIM

    # Reported individually only when DMARC did not already settle the question,
    # so a single forged message does not fan out into five overlapping alarms.
    if not dmarc_ok and dmarc not in _FAIL:
        if spf in _FAIL:
            out.append(Finding(
                code="SPF_FAIL", layer=0, severity=Severity.MEDIUM, weight=0.50,
                human_text=f"The server that sent this is not authorised to send mail "
                           f"for {view.spf_domain or from_domain}.",
                evidence={"spf": spf, "spf_domain": view.spf_domain},
            ))
        elif spf in _SOFT and spf != "none":
            out.append(Finding(
                code="SPF_SOFTFAIL", layer=0, severity=Severity.LOW, weight=0.28,
                human_text=f"The sending server is not on {view.spf_domain or from_domain}'s "
                           f"approved list, though the domain stops short of rejecting it.",
                evidence={"spf": spf, "spf_domain": view.spf_domain},
            ))
        if dkim in _FAIL:
            out.append(Finding(
                code="DKIM_FAIL", layer=0, severity=Severity.MEDIUM, weight=0.45,
                human_text="The message's digital signature does not check out - it was "
                           "either forged or altered in transit.",
                evidence={"dkim": dkim, "dkim_domain": view.dkim_domain},
            ))

    # The quiet one. A signature that *passes* still proves nothing when it was
    # applied by a domain the sender controls rather than the one in From:.
    # Only meaningful when DMARC did not pass, since a DMARC pass already
    # requires an aligned identifier.
    if dkim in _PASS and view.dkim_domain and from_org and not dmarc_ok:
        # Mail providers and ESPs sign on their customers' behalf as a matter
        # of course - every Google Workspace domain signs via gappssmtp.com.
        # Reporting that as a misaligned signature flags routine business mail.
        signer = D.org_domain(view.dkim_domain)
        if signer not in _DELEGATED_SIGNERS and not D.same_org(view.dkim_domain, from_domain):
            out.append(Finding(
                code="DKIM_UNALIGNED", layer=0, severity=Severity.MEDIUM, weight=0.50,
                human_text=f"This message is signed, but by {D.org_domain(view.dkim_domain)} "
                           f"rather than {from_org} - the signature does not vouch for the "
                           f"sender it claims to be from.",
                evidence={"dkim_domain": view.dkim_domain, "from_domain": from_domain},
            ))

    # ------------------------------------------------------------ easing

    # Forwarded mail legitimately breaks SPF: the forwarder becomes the sending
    # server. ARC records the original verdict, and honouring it is the single
    # biggest false-positive reduction available at this layer.
    if view.arc_present and not dmarc_ok and (spf in _FAIL | _SOFT or dkim in _FAIL):
        out.append(Finding(
            code="ARC_FORWARDED", layer=0, severity=Severity.INFO, weight=0.55,
            mitigating=True, scope=frozenset({0}),
            human_text="This message was forwarded, which breaks the usual sender checks "
                       "for harmless reasons.",
            evidence={"arc_present": True},
        ))

    if dmarc_ok:
        out.append(Finding(
            code="DMARC_PASS", layer=0, severity=Severity.INFO, weight=0.60,
            mitigating=True, scope=frozenset({0}),
            human_text=f"Verified as genuinely sent by {from_org}.",
            evidence={"dmarc": "pass", "from_domain": from_domain},
        ))

    return out + _divergence(view, ctx, dmarc_ok=dmarc_ok)


def _divergence(view: MessageView, ctx: AnalysisContext, dmarc_ok: bool) -> list[Finding]:
    """Reply-To and Return-Path disagreeing with From.

    Reply-To divergence is the classic business-email-compromise mechanic: the
    message looks like it came from a colleague, and the reply quietly goes
    somewhere else. It survives DMARC untouched, because Reply-To is not an
    authenticated identifier - which is exactly why it is checked separately.
    """
    out: list[Finding] = []
    from_domain = view.from_domain
    if not from_domain:
        return out

    reply_to = view.reply_to_addr
    if reply_to and not D.same_org(_domain_of(reply_to), from_domain):
        reply_is_free = D.is_freemail(_domain_of(reply_to))
        from_is_free = D.is_freemail(from_domain)
        if reply_is_free and not from_is_free:
            out.append(Finding(
                code="REPLY_TO_FREEMAIL", layer=0, severity=Severity.HIGH, weight=0.70,
                human_text=f"Replies to this message would go to {reply_to}, a personal "
                           f"mailbox unrelated to {from_domain}.",
                evidence={"reply_to": reply_to, "from_domain": from_domain},
            ))
        else:
            out.append(Finding(
                code="REPLY_TO_OFFDOMAIN", layer=0, severity=Severity.MEDIUM, weight=0.45,
                human_text=f"Replies would go to {reply_to}, not to the address this "
                           f"message appears to come from.",
                evidence={"reply_to": reply_to, "from_addr": view.from_addr},
            ))

    # Envelope-sender divergence is routine for newsletters and ticketing
    # systems, so it is only worth raising when nothing authenticated the
    # message in the first place.
    return_path = view.return_path_addr
    if return_path and not dmarc_ok and not D.same_org(_domain_of(return_path), from_domain):
        out.append(Finding(
            code="RETURN_PATH_OFFDOMAIN", layer=0, severity=Severity.LOW, weight=0.30,
            human_text=f"Bounces for this message go to {D.org_domain(_domain_of(return_path))}, "
                       f"which has no relationship to {from_domain}.",
            evidence={"return_path": return_path, "from_domain": from_domain},
        ))
    return out


def _domain_of(addr: str) -> str:
    return addr.rpartition("@")[2].lower() if addr and "@" in addr else ""
