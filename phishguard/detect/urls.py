"""URL dissection.

The link is where a phishing email cashes out. Everything before it is setup;
this is the part the victim actually clicks. Accordingly these checks are the
highest-yield content signals in the system.

Stdlib only, and no network: nothing here fetches a URL or follows a redirect.
Resolving shorteners means telling the attacker's infrastructure that the
message was opened and handing it the user's IP, so expansion belongs behind an
explicit opt-in (Phase 3), not in a background scan.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit

from . import domains as D

# Link shorteners. Not malicious in themselves - they are a blindfold, which is
# the point: the destination cannot be judged at all until it is expanded.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "bl.ink",
    "lnkd.in", "trib.al", "s.id", "v.gd", "t.ly", "shorte.st", "adf.ly",
    "short.io", "soo.gd", "clck.ru", "qps.ru", "u.to", "chilp.it", "lc.cx",
}

# Platforms that hand out free subdomains and HTTPS in minutes. Overwhelmingly
# legitimate in general use, overwhelmingly abused for credential pages.
FREE_HOSTING = {
    "pages.dev", "workers.dev", "vercel.app", "netlify.app", "web.app",
    "firebaseapp.com", "github.io", "gitlab.io", "glitch.me", "repl.co",
    "replit.dev", "ngrok.io", "ngrok-free.app", "onrender.com", "surge.sh",
    "r2.dev", "blob.core.windows.net", "s3.amazonaws.com",
    "storage.googleapis.com", "wixsite.com", "weeblysite.com", "square.site",
    "sites.google.com", "forms.gle", "formspree.io", "typeform.com",
    "notion.site", "webflow.io", "framer.website", "duckdns.org", "000webhostapp.com",
}

# Words that mark a page as asking for something it has no right to.
CREDENTIAL_WORDS = {
    "login", "logon", "signin", "sign-in", "auth", "authenticate", "verify",
    "verification", "validate", "account", "accounts", "secure", "security",
    "update", "confirm", "confirmation", "password", "passwd", "credential",
    "reset", "unlock", "recover", "recovery", "webmail", "owa", "office365",
    "o365", "mfa", "2fa", "otp", "token", "session", "billing", "invoice",
    "payment", "wallet", "seed", "mnemonic", "kyc",
}

# Query parameters that carry a second URL. An attacker who finds one of these
# on a trusted host gets to borrow that host's reputation.
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "next", "continue",
    "returnurl", "return_url", "return_to", "dest", "destination", "goto",
    "target", "r", "u", "link", "out", "forward", "to",
}

# Click-tracking domains. Practically every commercial sender rewrites its
# links through one of these, so the anchor text naming the brand while the
# href points at a tracker is the normal shape of legitimate mail - not a
# mismatch. Left unhandled this was the single largest remaining false-positive
# source on a real mailbox, flagging Binance, Airbnb and Stripe notifications.
#
# Suppression is conditional on DMARC: the tracker only gets the benefit of the
# doubt when the sending domain has already been cryptographically verified.
TRACKING_DOMAINS = {
    "awstrack.me", "sendgrid.net", "ct.sendgrid.net", "sparkpostmail.com",
    "mailgun.org", "mandrillapp.com", "list-manage.com", "mcsv.net", "mcdlv.net",
    "rsgsv.net", "createsend.com", "cmail19.com", "cmail20.com", "exct.net",
    "rs6.net", "hubspotlinks.com", "hs-sites.com", "pardot.com", "mktdns.com",
    "sendibt2.com", "sendibm1.com", "sendibm3.com", "klclick.com", "klclick1.com",
    "postmarkapp.com", "customeriomail.com", "intercom-mail.com", "braze.com",
    "sparkpost.com", "mixmax.com", "yesware.com", "bnc.lt", "sng.link",
    "app.link", "adj.st", "onelink.me", "go-mail.io", "mailanyone.net",
    "email.mg", "links.notifications", "e.customeriomail.com", "mail.crayo.ai",
}


def is_tracker(link: "Link") -> bool:
    host = link.host or ""
    return any(host == d or host.endswith("." + d) for d in TRACKING_DOMAINS)


DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}

_URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?|ftp)://[^\s<>"'\]\)]+
        |
        www\.[^\s<>"'\]\)]+
    )""",
)


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@dataclass
class Link:
    href: str
    anchor_text: str = ""
    source: str = "text"          # html_anchor | text | form_action | meta_refresh
    scheme: str = ""
    host: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    userinfo: str = ""
    org: str = ""

    @property
    def is_web(self) -> bool:
        return self.scheme in ("http", "https")

    @property
    def display(self) -> str:
        return self.href[:120]


def parse_link(href: str, anchor_text: str = "", source: str = "text") -> Link | None:
    """Split a href into the pieces the detectors reason about.

    Returns None for anchors that are not links at all (#fragments, mailto,
    empty) - those are noise, not evidence.
    """
    href = (href or "").strip()
    if not href or href.startswith("#"):
        return None

    lowered = href.lower()
    if lowered.startswith(("mailto:", "tel:", "sms:", "callto:")):
        return None

    candidate = href if "://" in href or ":" in href[:12] else f"http://{href}"
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return Link(href=href, anchor_text=anchor_text, source=source, scheme="malformed")

    link = Link(
        href=href, anchor_text=anchor_text or "", source=source,
        scheme=(parts.scheme or "").lower(), path=parts.path or "", query=parts.query or "",
    )

    # urlsplit puts everything before '@' into netloc; separating it matters
    # because the userinfo trick lives exactly there.
    netloc = parts.netloc or ""
    if "@" in netloc:
        link.userinfo, _, netloc = netloc.rpartition("@")
    host = netloc
    if host.startswith("["):                      # bracketed IPv6
        host = host.partition("]")[0].lstrip("[")
    elif ":" in host:
        host, _, port = host.partition(":")
        try:
            link.port = int(port)
        except ValueError:
            link.port = None
    link.host = host.strip().rstrip(".").lower()
    # A bare IP has no registrable domain. Running it through org_domain would
    # slice off the last two octets and invent one ("45.83.12.9" -> "12.9"),
    # which then shows up in user-facing text as a nonsense site name.
    link.org = link.host if is_ip_host(link.host) else D.org_domain(link.host)
    return link


def extract_from_text(text: str) -> list[Link]:
    out: list[Link] = []
    for match in _URL_RE.findall(text or ""):
        link = parse_link(match.rstrip(".,;:!?"), source="text")
        if link:
            out.append(link)
    return out


def is_shortener(link: Link) -> bool:
    return link.org in SHORTENERS or link.host in SHORTENERS


def free_hosting_suffix(link: Link) -> str | None:
    host = link.host
    for suffix in FREE_HOSTING:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return None


def credential_words_in(link: Link) -> list[str]:
    blob = unquote(f"{link.path} {link.query}").lower()
    tokens = set(re.split(r"[^a-z0-9]+", blob))
    return sorted(tokens & CREDENTIAL_WORDS)


def open_redirect_target(link: Link) -> str | None:
    """A nested URL smuggled through a query parameter."""
    for key, value in parse_qsl(link.query, keep_blank_values=False):
        if key.lower() not in REDIRECT_PARAMS:
            continue
        decoded = unquote(value)
        if "://" in decoded or decoded.startswith("//"):
            return decoded
    return None


def brand_in_subdomain(link: Link, reference_domains: set[str]) -> str | None:
    """`paypal.com.secure-login.ru` - the real brand demoted to a subdomain.

    Reads left-to-right like the genuine site, and resolves to something else
    entirely. Only the rightmost labels decide where a request actually goes.
    """
    if not link.host or not reference_domains:
        return None
    labels = link.host.split(".")
    if len(labels) < 3:
        return None
    subdomain_labels = set(labels[:-2])
    for known in reference_domains:
        if D.org_domain(link.host) == known:
            return None
        label = D.registrable_label(known)
        if len(label) >= 4 and label in subdomain_labels:
            return known
    return None


def anchor_claims_other_domain(link: Link) -> str | None:
    """Visible text naming one destination while the href points at another.

    The single most reliable content signal there is: every mail client shows
    the text and hides the href, so it is the only thing most people ever read.
    """
    text = (link.anchor_text or "").strip()
    if not text or len(text) > 200 or not link.is_web:
        return None

    # Prose containing dots is not a domain claim. A listing title like
    # "3br.10pax.duty free. seaside apartment" was being parsed as a hostname
    # and reported as a link mismatch on legitimate mail.
    if " " in text or len(text.split(".")) > 5:
        text_host = text.strip().strip("<>()[]").lower()
        if " " in text_host:
            return None

    claimed = parse_link(text, source="anchor_text")
    if claimed and claimed.host and "." in claimed.host:
        if claimed.org and link.org and claimed.org != link.org:
            return claimed.host
        return None

    # Bare domain as the link text: "click paypal.com".
    bare = re.fullmatch(r"[\w\-]+(?:\.[\w\-]+){1,3}", text.strip().strip("<>()[]"))
    if bare:
        host = text.strip().strip("<>()[]").lower()
        org = D.org_domain(host)
        if org and link.org and org != link.org and "." in host:
            return host
    return None


@dataclass
class LinkStats:
    links: list[Link] = field(default_factory=list)
    unique_orgs: set[str] = field(default_factory=set)

    def add(self, link: Link) -> None:
        self.links.append(link)
        if link.org:
            self.unique_orgs.add(link.org)
