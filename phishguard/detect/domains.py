"""Domain reasoning: organisational domains, freemail, lookalikes, homoglyphs.

Deliberately stdlib-only. `tldextract` would give a complete Public Suffix List,
but it wants to fetch and cache one, and Phase 1 has to work offline and in a
sandboxed .app. The embedded suffix table below covers the realistic space;
swapping in tldextract later is a one-function change (`org_domain`).
"""

from __future__ import annotations

import re
import unicodedata

# --------------------------------------------------------- public suffixes

# Multi-label suffixes where the registrable name is the *third* label from the
# right. Without this, foo.co.uk and bar.co.uk would look like the same
# organisation, and every UK sender would alias onto every other one.
_MULTI_SUFFIXES = {
    # country second-level
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "co.in", "net.in", "org.in", "ac.in", "edu.in", "gov.in", "firm.in", "gen.in",
    "com.bd", "net.bd", "org.bd", "edu.bd", "gov.bd",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "lg.jp",
    "co.kr", "or.kr", "go.kr", "ne.kr", "re.kr",
    "com.sg", "com.my", "com.hk", "com.tw", "com.tr", "com.mx", "com.ar",
    "com.co", "com.pe", "com.ve", "com.uy", "com.ec",
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "com.sa", "com.eg", "com.ng", "com.gh", "com.ke", "com.tz", "com.ma",
    "com.ua", "com.ru", "org.ru", "net.ru", "edu.ru", "gov.ru",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "com.es", "com.pl", "com.pt", "com.gr", "com.ro", "com.vn", "com.ph",
    "co.id", "or.id", "web.id", "ac.id", "go.id",
    "co.th", "in.th", "ac.th", "go.th",
    "com.ae", "net.ae", "org.ae", "gov.ae", "ac.ae",
    "com.qa", "com.kw", "com.bh", "com.om", "com.jo", "com.lb", "com.iq",
    "co.ke", "co.ug", "co.tz", "co.zm",
    # private registries and app-hosting suffixes: separate tenants, so they
    # must not collapse into one "organisation"
    "eu.com", "us.com", "uk.com", "gb.com", "cn.com", "de.com", "br.com",
    "github.io", "gitlab.io", "blogspot.com", "herokuapp.com", "web.app",
    "azurewebsites.net", "firebaseapp.com", "pages.dev", "workers.dev",
    "vercel.app", "netlify.app", "glitch.me", "repl.co", "ngrok.io",
    "ngrok-free.app", "onrender.com", "surge.sh", "weeblysite.com",
    "sharepoint.com", "myshopify.com", "wixsite.com", "square.site",
}

# Mailbox providers where the domain says nothing about the sender's identity.
FREEMAIL = {
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.fr", "yahoo.de",
    "yahoo.com.br", "yahoo.ca", "yahoo.com.au", "ymail.com", "rocketmail.com",
    "outlook.com", "outlook.co.uk", "hotmail.com", "hotmail.co.uk",
    "hotmail.fr", "hotmail.it", "live.com", "live.co.uk", "msn.com",
    "aol.com", "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "pm.me", "tutanota.com", "tuta.io",
    "gmx.com", "gmx.de", "gmx.net", "web.de", "mail.com", "email.com",
    "yandex.com", "yandex.ru", "zoho.com", "fastmail.com", "hushmail.com",
    "hey.com", "mail.ru", "inbox.ru", "list.ru", "bk.ru", "rambler.ru",
    "qq.com", "163.com", "126.com", "sina.com", "foxmail.com",
    "naver.com", "daum.net", "hanmail.net",
    "rediffmail.com", "sify.com",
    "t-online.de", "orange.fr", "free.fr", "laposte.net", "wanadoo.fr", "sfr.fr",
    "libero.it", "virgilio.it", "alice.it", "tiscali.it",
    "uol.com.br", "bol.com.br", "terra.com.br",
    "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "cox.net",
    "bellsouth.net", "charter.net", "btinternet.com", "sky.com",
    "talktalk.net", "virginmedia.com", "shaw.ca", "rogers.com",
    # throwaway providers: not freemail exactly, but identity-free in the same way
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "yopmail.com",
    "temp-mail.org", "sharklasers.com", "throwawaymail.com",
}

# Words attackers bolt onto a real brand to build a cousin domain.
COUSIN_AFFIXES = {
    "secure", "security", "login", "signin", "account", "accounts", "verify",
    "verification", "update", "support", "help", "service", "services", "mail",
    "email", "webmail", "portal", "billing", "invoice", "invoices", "payment",
    "payments", "payroll", "hr", "finance", "admin", "auth", "sso", "id",
    "online", "web", "app", "my", "team", "corp", "inc", "ltd", "group",
    "official", "alert", "alerts", "notice", "notify", "care", "center",
    "centre", "desk", "net", "info", "global", "intl", "new", "confirm",
}


def org_domain(domain: str) -> str:
    """Registrable domain (eTLD+1). 'mail.foo.co.uk' -> 'foo.co.uk'."""
    if not domain:
        return ""
    labels = domain.strip().lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def registrable_label(domain: str) -> str:
    """The part an attacker actually chooses: 'foo' from 'foo.co.uk'."""
    org = org_domain(domain)
    return org.split(".", 1)[0] if org else ""


def is_freemail(domain: str) -> bool:
    return org_domain(domain) in FREEMAIL or domain.lower() in FREEMAIL


def same_org(a: str, b: str) -> bool:
    if not a or not b:
        return False
    return org_domain(a) == org_domain(b)


# ------------------------------------------------------------- similarity

def damerau_levenshtein(a: str, b: str, cap: int = 4) -> int:
    """Optimal string alignment distance, short-circuited at `cap`.

    Transpositions count as one edit because adjacent-key typos are exactly
    what a lookalike domain imitates ('gmial', 'mircosoft').
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > cap:
            return cap + 1
        prev2, prev = prev, cur
    return prev[len(b)]


# Glyph pairs that survive a glance at 10pt in a mail client.
_CONFUSABLE_PAIRS = [
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"),
    ("0", "o"), ("1", "l"), ("l", "i"), ("5", "s"), ("3", "e"),
    ("7", "t"), ("8", "b"), ("9", "g"), ("2", "z"), ("4", "a"), ("6", "g"),
]


def visual_normalise(text: str) -> str:
    """Collapse a label to its visual skeleton.

    'paypa1', 'paypaI' and 'paypal' all become 'paypal'; 'rnicrosoft' becomes
    'microsoft'. Two labels sharing a skeleton but not spelling is the single
    highest-confidence lookalike signal available without DNS.
    """
    out = text.lower().replace("-", "").replace("_", "")
    for src, dst in _CONFUSABLE_PAIRS:
        out = out.replace(src, dst)
    return out


def lookalike_kind(candidate: str, known: str) -> tuple[str, float] | None:
    """Classify how `candidate` imitates `known`. None when it does not.

    Returns (kind, confidence). Ordered most to least conclusive.
    """
    c_org, k_org = org_domain(candidate), org_domain(known)
    if not c_org or not k_org or c_org == k_org:
        return None

    c_label, k_label = registrable_label(c_org), registrable_label(k_org)
    if not c_label or not k_label or len(k_label) < 4:
        return None  # 3-letter names collide by chance far too often

    # Checked before the visual test: an identical name under a different TLD
    # is a TLD swap, not a glyph trick, and the two want different wording in
    # the UI. The visual skeletons are trivially equal here, so the more
    # specific case has to win first.
    if c_label == k_label:
        return ("tld_swap", 0.80)

    if visual_normalise(c_label) == visual_normalise(k_label):
        return ("visual", 0.95)

    dist = damerau_levenshtein(c_label, k_label)
    if dist == 1 and len(k_label) >= 5:
        return ("typo", 0.85)
    if dist == 2 and len(k_label) >= 9:
        return ("typo", 0.70)

    # Cousin domain: the real name plus a plausible business word.
    # 'company-payroll.com', 'secure-company.net', 'companysupport.com'.
    if k_label in c_label and len(c_label) > len(k_label):
        extra = c_label.replace(k_label, "", 1).strip("-_.")
        if extra in COUSIN_AFFIXES:
            return ("cousin", 0.80)
        if extra and len(extra) <= 12:
            return ("cousin", 0.60)
    return None


# -------------------------------------------------------------- homoglyphs

_SCRIPT_PREFIXES = ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW",
                    "ARMENIAN", "CHEROKEE", "DEVANAGARI", "HAN", "HANGUL")


def _scripts_in(text: str) -> set[str]:
    found: set[str] = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        for prefix in _SCRIPT_PREFIXES:
            if name.startswith(prefix):
                found.add(prefix)
                break
    return found


def decode_punycode(domain: str) -> str | None:
    """Unicode form of an IDN, or None when the domain is plain ASCII."""
    if "xn--" not in domain.lower():
        return None
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError, ValueError):
        return None


def homoglyph_check(domain: str) -> tuple[str, str] | None:
    """(kind, detail) when the domain uses deceptive characters.

    Mixed scripts inside one label is the giveaway: legitimate IDNs are
    written in a single script, while 'аpple.com' with a Cyrillic 'а' is not.
    """
    if not domain:
        return None
    decoded = decode_punycode(domain)
    subject = decoded or domain

    if decoded:
        for label in decoded.split("."):
            scripts = _scripts_in(label)
            if len(scripts) > 1:
                return ("mixed_script", f"{domain} renders as {decoded}")
        if any(ord(ch) > 127 for ch in decoded):
            return ("punycode", f"{domain} renders as {decoded}")

    if any(ord(ch) > 127 for ch in subject):
        for label in subject.split("."):
            if len(_scripts_in(label)) > 1:
                return ("mixed_script", subject)
    return None


# --------------------------------------------------------- display names

_NAME_CLEAN_RE = re.compile(r"[^a-z0-9\s]+")
_NAME_TITLES = {"mr", "mrs", "ms", "dr", "prof", "sir", "eng", "engr", "capt"}
_EMAIL_IN_TEXT_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w{2,}")


def normalise_display_name(name: str) -> str:
    """Fold a display name to a comparison key.

    Case, punctuation, titles and word order are all things an impersonator
    varies freely, so none of them may be part of the identity.
    'Dr. Abdul Rehman' and 'REHMAN, ABDUL' both become 'abdul rehman'.
    """
    if not name:
        return ""
    cleaned = _NAME_CLEAN_RE.sub(" ", name.strip().lower())
    words = [w for w in cleaned.split() if w and w not in _NAME_TITLES]
    # Drop a trailing org suffix people put in display names: "Abdul | Acme".
    return " ".join(sorted(words)) if len(words) <= 4 else " ".join(sorted(words[:4]))


def emails_in_text(text: str) -> list[str]:
    return [m.lower() for m in _EMAIL_IN_TEXT_RE.findall(text or "")]
