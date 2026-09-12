"""Identifier redaction for anything that leaves the device.

Its own module because it is the single security-relevant function in the
codebase: Layer 4 is the only component that transmits message content, and
this is the last thing that runs before it does.

Two failure modes, and they pull in opposite directions. Under-redacting leaks
the user's banking details to a third party. Over-redacting destroys the text
so thoroughly that the intent question becomes unanswerable, which quietly
disables the layer instead. The shape of a request has to survive: "change the
account to [ACCOUNT]" is exactly as classifiable as the real number.

The financial patterns carry most of the weight here, because the messages that
reach Layer 4 at all are disproportionately the ones about payments - so an
account number is the most likely sensitive string in the text being sent.
"""

from __future__ import annotations

import re

# URLs carry the worst secrets in the whole message. Password-reset links,
# magic-link logins, unsubscribe tokens and cloud-console verification links all
# put live single-use credentials in the query string - a real AWS root-account
# email in testing carried `?token=...&key=...` that would have gone straight to
# the API.
#
# The intent question only ever needs to know *where* a link points, never the
# credentials attached to it, so everything after the path is dropped.
_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w{2,}")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
_LONG_DIGITS_RE = re.compile(r"\b\d{6,}\b")

# Financial identifiers, most specific first. Case-insensitive and
# separator-tolerant throughout, because real mail writes these however it
# likes: "GB29NWBK60161331926819", "gb29 nwbk 6016 1331 9268 19", "Gb29-Nwbk-".
# An earlier version anchored on [A-Z]{2} and missed every lowercase IBAN.
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_IBAN_RE = re.compile(
    r"\b[A-Za-z]{2}\d{2}(?:[ -]?[A-Za-z0-9]{2,4}){2,8}\b"
)
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_SORT_CODE_RE = re.compile(r"\b\d{2}[- ]\d{2}[- ]\d{2}\b")

# Keyword-anchored catch-all for what the shape rules miss - SWIFT/BIC codes,
# domestic account numbers, anything a bank invents next.
#
# Anchoring on the *label* rather than the value is what makes this safe. An
# unanchored "redact any 8+ alphanumeric run" rule would eat ordinary words and
# leave a body that says nothing; requiring "account:" or "iban:" in front means
# it only fires where the writer has already declared what follows.
_LABELLED_RE = re.compile(
    r"\b(iban|swift|bic|account|acct|a/c|routing|aba|sort\s?code|wallet"
    r"|beneficiary)\b"
    r"\s*(?:number|no\.?|code|#)?\s*[:=]?\s*"
    r"([A-Za-z0-9][A-Za-z0-9 -]{4,38}[A-Za-z0-9])",
    re.I,
)

# Ordinary words that follow "account" or "reference" in normal prose. Without
# this the label rule swallows real sentences: "account details attached" would
# become "account [ACCOUNT]" and the model would lose the request entirely.
_PROSE_AFTER_LABEL = re.compile(
    r"^(?:details?|information|info|number|numbers|manager|name|holder|"
    r"balance|statement|summary|team|is|are|was|has|have|will|to|for|of|"
    r"and|the|below|above|attached|updated|new|old)\b",
    re.I,
)


def _trimmed(placeholder: str):
    """Replace a match with `placeholder`, handing back anything it over-ate.

    The IBAN and card patterns allow internal spaces, which makes them greedy
    across the word boundary: "GB29NWBK6016... now" matches through " now" and
    the sentence loses a word. Trailing groups that carry no digits are not part
    of an account number, so they are put back.
    """
    def sub(match: re.Match) -> str:
        matched = match.group(0)
        tail = ""
        while True:
            head, sep, last = matched.rpartition(" ")
            if not sep or any(c.isdigit() for c in last):
                break
            matched, tail = head, sep + last + tail
        if not any(c.isdigit() for c in matched):
            return match.group(0)
        return placeholder + tail
    return sub


def _strip_url(match: re.Match) -> str:
    """Keep scheme, host and a short path. Drop query, fragment and userinfo."""
    url = match.group(0)
    rest = url.split("://", 1)[1] if "://" in url else url
    scheme = url.split("://", 1)[0] if "://" in url else "https"
    rest = rest.split("#", 1)[0].split("?", 1)[0]
    if "@" in rest.split("/", 1)[0]:
        rest = rest.split("@", 1)[1]        # userinfo can hide credentials too
    host, _, path = rest.partition("/")
    segments = [seg for seg in path.split("/") if seg][:2]
    # Long opaque path segments are tokens in disguise.
    segments = [seg if len(seg) <= 24 else "[TOKEN]" for seg in segments]
    tail = "/" + "/".join(segments) if segments else ""
    return f"{scheme}://{host}{tail}" + ("/[...]" if path.strip("/") and not segments else "")


def _mask_email(addr: str) -> str:
    """Keep the domain, drop the person. The domain carries the signal."""
    local, _, domain = addr.partition("@")
    return f"[USER]@{domain}" if domain else "[EMAIL]"


def _mask_labelled(match: re.Match) -> str:
    label, value = match.group(1), match.group(2)
    if _PROSE_AFTER_LABEL.match(value.strip()):
        return match.group(0)          # ordinary prose, leave it alone
    if not any(ch.isdigit() for ch in value):
        # A run of pure letters after "account" is a name or a sentence, not an
        # identifier - except for SWIFT/BIC, which is genuinely all letters.
        if label.lower() not in ("swift", "bic"):
            return match.group(0)
    return f"{label} [ACCOUNT]"


# Markup that survives into the plain-text body. Outlook conditional comments
# are "downlevel-revealed" - the `<!-->` closes early, so everything after it is
# real text as far as any parser is concerned - and a good deal of inline CSS
# comes through with them. It is pure noise for an intent question, it costs
# tokens, and it dilutes the prose the model is meant to be reading.
_MARKUP_NOISE_RE = re.compile(
    r"<!--.*?-->|<!\[endif\]>?|<!\[if[^\]]*\]>?|<[a-zA-Z/!][^>]{0,400}>",
    re.S,
)
_CSS_DECL_RE = re.compile(
    r"[a-zA-Z-]+\s*:\s*[^;{}]{1,60};(?:\s*[a-zA-Z-]+\s*:\s*[^;{}]{1,60};){2,}"
)


def strip_markup(text: str) -> str:
    """Remove markup and CSS fragments from a body meant to be read as prose."""
    out = _MARKUP_NOISE_RE.sub(" ", text or "")
    out = _CSS_DECL_RE.sub(" ", out)
    return " ".join(out.split())


def redact(text: str, own_addresses: set[str] | None = None) -> str:
    """Replace identifiers with placeholders, preserving the request's shape."""
    out = strip_markup(text or "")
    for addr in own_addresses or ():
        if addr:
            out = out.replace(addr, "[YOUR-ADDRESS]")

    # URLs first: their query strings would otherwise survive every later rule.
    out = _URL_RE.sub(_strip_url, out)
    out = _ETH_RE.sub("[WALLET]", out)
    out = _BTC_RE.sub("[WALLET]", out)
    out = _IBAN_RE.sub(_trimmed("[IBAN]"), out)
    out = _CARD_RE.sub(_trimmed("[CARD-NUMBER]"), out)
    out = _SORT_CODE_RE.sub("[SORT-CODE]", out)
    out = _LABELLED_RE.sub(_mask_labelled, out)
    out = _EMAIL_RE.sub(lambda m: _mask_email(m.group(0)), out)
    out = _PHONE_RE.sub("[PHONE]", out)
    out = _LONG_DIGITS_RE.sub("[NUMBER]", out)
    return out


def leaks(original: str, redacted: str, min_len: int = 6) -> list[str]:
    """Tokens containing digits that survived redaction.

    Exists so the property can be asserted in tests rather than eyeballed - the
    only honest way to know a redactor works is to check nothing came through.
    """
    out: list[str] = []
    for token in re.split(r"\s+", strip_markup(original or "")):
        stripped = token.strip(".,;:!?()[]<>\"'")
        if len(stripped) < min_len or not any(c.isdigit() for c in stripped):
            continue
        if stripped not in redacted:
            continue
        # A URL that survives stripping unchanged had nothing to strip: no
        # query string, no long opaque segments. "company.com/blog/post-1" is
        # a destination, not a credential.
        if stripped.lower().startswith(("http://", "https://")):
            match = _URL_RE.match(stripped)
            if match and _strip_url(match) == stripped:
                continue
        out.append(stripped)
    return out
