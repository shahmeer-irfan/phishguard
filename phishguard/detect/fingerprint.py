"""Sender fingerprinting - feature extraction and profiles.

This is the email twin of a voiceprint. Two independent fingerprints per
contact:

**Technical** - how their mail is *produced*. Mail client, Message-ID shape,
MIME structure, header order, timezone, sending infrastructure. Deterministic,
free to compute, and hard to fake because an attacker would have to reproduce
a whole software stack rather than a writing style.

**Stylometric** - how the person *writes*. Function-word distribution,
punctuation habits, sentence length, greetings and sign-offs.

Stylometry here is a classical function-word feature vector rather than a neural
embedding, deliberately. Three reasons: it works on the 20-50 messages a real
contact actually has (embeddings want more), every dimension is nameable so the
UI can say *why* something looked wrong, and it adds no 500 MB dependency to a
signed .app bundle. `style_vector()` is the seam - swap its body for a
sentence-transformer later and nothing above it changes.
"""

from __future__ import annotations

import math
import re
import statistics
from dataclasses import dataclass, field
from typing import Any, Iterable

# The 60 most frequent English function words. Authorship attribution has used
# these since Mosteller and Wallace: they are chosen unconsciously, stay stable
# across topics, and survive the fact that an impersonator controls the subject
# matter completely but not their own grammar.
FUNCTION_WORDS = [
    "the", "of", "and", "to", "a", "in", "that", "is", "was", "it", "for",
    "as", "with", "his", "on", "be", "at", "by", "i", "this", "had", "not",
    "are", "but", "from", "or", "have", "an", "they", "which", "you", "were",
    "her", "all", "she", "there", "would", "their", "we", "him", "been",
    "has", "when", "who", "will", "more", "if", "no", "out", "so", "said",
    "what", "up", "its", "about", "into", "than", "them", "can", "only",
]

GREETING_RE = re.compile(
    r"^\s*(hi|hello|hey|dear|good\s+(?:morning|afternoon|evening)|greetings|"
    r"salaam|assalam|aoa|yo|hiya|morning|afternoon)\b[^\n]{0,40}",
    re.I,
)
SIGNOFF_RE = re.compile(
    r"^\s*(thanks|thank you|regards|best regards|best|kind regards|cheers|"
    r"sincerely|yours|br|rgds|take care|talk soon|many thanks|warm regards)\b",
    re.I,
)
_QUOTE_RE = re.compile(r"^\s*(>|On .{5,60} wrote:|-{2,}\s*Original Message)", re.I)
_WORD_RE = re.compile(r"[a-zA-Z']+")
_SENTENCE_RE = re.compile(r"[.!?]+[\s\n]|\n\n")
_EMOJI_RE = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF]"
)
_URL_RE = re.compile(r"https?://\S+")

# Order defines the vector layout. Never reorder without bumping PROFILE_VERSION.
SCALAR_FEATURES = [
    "avg_sentence_len", "sentence_len_sd", "avg_word_len", "type_token_ratio",
    "comma_rate", "period_rate", "exclaim_rate", "question_rate",
    "semicolon_rate", "dash_rate", "ellipsis_rate", "apostrophe_rate",
    "uppercase_word_rate", "lowercase_start_rate", "contraction_rate",
    "emoji_rate", "digit_rate", "paragraph_rate", "line_len_mean",
    "double_space_rate",
]
PROFILE_VERSION = "fp-1"

# Below this, a profile is an anecdote rather than a baseline. Reporting a
# "style mismatch" off three samples would be noise dressed as evidence.
# Matched to the stylometry floor after real-mail testing. At three samples the
# profile cannot distinguish "unusual for this sender" from "not yet observed",
# and it reported CRITICAL fingerprint mismatches on ordinary university mail
# with five prior messages.
MIN_SAMPLES_TECHNICAL = 12

# Authorship attribution needs real samples. At five messages the estimate of a
# contact's own variance is itself so noisy that ordinary short notes from the
# genuine sender land several "standard deviations" from their own baseline -
# measured, not assumed. Twelve is where that stops happening; below it the
# layer stays silent rather than guessing.
MIN_SAMPLES_STYLE = 12

# Word floor for a message to contribute to, or be judged against, a style
# profile. Set from what real mail looks like rather than from what stylometry
# would prefer: a great deal of genuine correspondence is one or two short
# sentences, and a floor high enough to please the statistics would exclude
# most of a normal mailbox and leave the layer with nothing to model.
MIN_WORDS_FOR_STYLE = 12


# ------------------------------------------------------------------ helpers

def strip_quoted(body: str) -> str:
    """Drop quoted history and signature blocks.

    Without this every reply inherits the style of whoever is being quoted, and
    the profile converges on the mailing list rather than the person.
    """
    lines: list[str] = []
    for line in (body or "").splitlines():
        if _QUOTE_RE.match(line):
            break
        if line.strip() in ("--", "-- ", "__"):
            break
        lines.append(line)
    return "\n".join(lines)


def message_id_shape(message_id: str | None) -> str:
    """Structural signature of a Message-ID.

    Mail clients generate these to fixed recipes, so the *shape* is close to a
    serial number for the software while the value itself is unique per message.
    'CAF+abc123@mail.gmail.com' -> 'a+a9@mail.gmail.com'.
    """
    if not message_id:
        return ""
    local, _, domain = message_id.rpartition("@")
    if not local:
        local, domain = message_id, ""
    shape: list[str] = []
    prev = ""
    for ch in local:
        if ch.isalpha():
            cls = "a"
        elif ch.isdigit():
            cls = "9"
        else:
            cls = ch
        if cls != prev or cls not in ("a", "9"):
            shape.append(cls)
        prev = cls
    return f"{''.join(shape)}@{domain.lower()}"


# ------------------------------------------------------- stylometric vector

def style_features(body: str) -> dict[str, float]:
    """Named style features. Every value is a rate, so length cannot dominate."""
    text = strip_quoted(body or "")
    text = _URL_RE.sub(" ", text)  # URLs are not prose
    words = _WORD_RE.findall(text)
    n_words = len(words) or 1
    n_chars = len(text) or 1

    sentences = [s for s in _SENTENCE_RE.split(text) if s.strip()]
    sent_lens = [len(_WORD_RE.findall(s)) for s in sentences] or [0]
    lines = [l for l in text.splitlines() if l.strip()]

    lowered = [w.lower() for w in words]
    feats: dict[str, float] = {
        "avg_sentence_len": statistics.fmean(sent_lens),
        "sentence_len_sd": statistics.pstdev(sent_lens) if len(sent_lens) > 1 else 0.0,
        "avg_word_len": sum(len(w) for w in words) / n_words,
        "type_token_ratio": len(set(lowered)) / n_words,
        "comma_rate": text.count(",") / n_words,
        "period_rate": text.count(".") / n_words,
        "exclaim_rate": text.count("!") / n_words,
        "question_rate": text.count("?") / n_words,
        "semicolon_rate": text.count(";") / n_words,
        "dash_rate": (text.count(" - ") + text.count("--") + text.count("—")) / n_words,
        "ellipsis_rate": text.count("...") / n_words,
        "apostrophe_rate": text.count("'") / n_words,
        "uppercase_word_rate": sum(1 for w in words if w.isupper() and len(w) > 1) / n_words,
        "lowercase_start_rate": sum(1 for s in sentences if s.strip()[:1].islower()) / max(len(sentences), 1),
        "contraction_rate": sum(1 for w in lowered if "'" in w) / n_words,
        "emoji_rate": len(_EMOJI_RE.findall(text)) / n_words,
        "digit_rate": sum(ch.isdigit() for ch in text) / n_chars,
        "paragraph_rate": text.count("\n\n") / max(len(lines), 1),
        "line_len_mean": statistics.fmean([len(l) for l in lines]) if lines else 0.0,
        "double_space_rate": text.count("  ") / n_words,
    }

    counts = {w: 0 for w in FUNCTION_WORDS}
    for w in lowered:
        if w in counts:
            counts[w] += 1
    for w in FUNCTION_WORDS:
        feats[f"fw_{w}"] = counts[w] / n_words
    return feats


def style_vector(body: str) -> list[float]:
    """Ordered vector. The seam for swapping in embeddings later."""
    feats = style_features(body)
    return [feats[k] for k in SCALAR_FEATURES] + [feats[f"fw_{w}"] for w in FUNCTION_WORDS]


VECTOR_LEN = len(SCALAR_FEATURES) + len(FUNCTION_WORDS)


def greeting_of(body: str) -> str:
    for line in strip_quoted(body).splitlines():
        if not line.strip():
            continue
        m = GREETING_RE.match(line)
        return re.sub(r"[^a-z ]+", "", m.group(1).lower()).strip() if m else ""
    return ""


def signoff_of(body: str) -> str:
    lines = [l for l in strip_quoted(body).splitlines() if l.strip()]
    for line in reversed(lines[-4:]):
        m = SIGNOFF_RE.match(line)
        if m:
            return re.sub(r"[^a-z ]+", "", m.group(1).lower()).strip()
    return ""


# --------------------------------------------------------------- similarity

def cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return max(-1.0, min(1.0, dot / (na * nb)))


# Hard bound on any single scaled dimension. A feature the contact happened
# never to use has near-zero spread in their history, so the first message that
# does use it divides by almost nothing and produces an enormous value - which
# then dominates the cosine on its own and reads as "this is a different
# person". Clipping means one unseen word is worth exactly one dimension of
# disagreement, which is what it actually is.
SCALED_CLIP = 6.0

# Floor on a dimension's spread. Most features here are rates in [0, 1], so a
# minimum spread of 0.01 is the smallest difference worth treating as real;
# anything finer is sampling noise from a few dozen messages.
MIN_SCALE = 0.01


def scaled(vec: list[float], scale: list[float]) -> list[float]:
    """Divide each dimension by its spread across the corpus, then clip.

    Without the division, `line_len_mean` (tens) drowns out `exclaim_rate`
    (hundredths) and the cosine measures little except message width. Without
    the clip, a rarely-used dimension does the same thing in reverse.
    """
    out: list[float] = []
    for v, s in zip(vec, scale):
        x = v / s if s > 1e-9 else 0.0
        out.append(max(-SCALED_CLIP, min(SCALED_CLIP, x)))
    return out


# ------------------------------------------------------------------ profile

@dataclass
class TechnicalProfile:
    x_mailers: dict[str, int] = field(default_factory=dict)
    msgid_shapes: dict[str, int] = field(default_factory=dict)
    mime_signatures: dict[str, int] = field(default_factory=dict)
    header_orders: dict[str, int] = field(default_factory=dict)
    tz_offsets: dict[str, int] = field(default_factory=dict)
    origin_orgs: dict[str, int] = field(default_factory=dict)
    dkim_domains: dict[str, int] = field(default_factory=dict)
    send_hours: dict[str, int] = field(default_factory=dict)
    samples: int = 0

    DIMENSIONS = ("x_mailers", "msgid_shapes", "mime_signatures", "header_orders",
                  "tz_offsets", "origin_orgs", "dkim_domains")

    # A value seen exactly once does not establish a habit.
    #
    # This is the Layer-2 equivalent of the contact-graph poisoning gate, and it
    # closes the same hole from the other side. Profiles are built from stored
    # history, and history contains attacks that have not been detected yet - an
    # undetected impersonation is in the corpus by definition. If one appearance
    # were enough to mark a mail client or Message-ID shape as normal for this
    # contact, every attack would vouch for itself the moment it was indexed,
    # and the second message from the same attacker would sail through.
    MIN_OCCURRENCES_FOR_KNOWN = 2

    def observe(self, field_name: str, value: Any) -> None:
        if value in (None, ""):
            return
        bucket = getattr(self, field_name)
        bucket[str(value)] = bucket.get(str(value), 0) + 1

    def share(self, field_name: str, value: Any) -> float:
        """What fraction of this contact's history used this value."""
        bucket = getattr(self, field_name)
        total = sum(bucket.values())
        if not total or value in (None, ""):
            return 0.0
        return bucket.get(str(value), 0) / total

    def is_known(self, field_name: str, value: Any) -> bool:
        if value in (None, ""):
            return False
        return getattr(self, field_name).get(str(value), 0) >= self.MIN_OCCURRENCES_FOR_KNOWN

    def seen_once(self, field_name: str, value: Any) -> bool:
        if value in (None, ""):
            return False
        return getattr(self, field_name).get(str(value), 0) == 1

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in
                (*self.DIMENSIONS, "send_hours", "samples")}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "TechnicalProfile":
        p = TechnicalProfile()
        for k, v in (d or {}).items():
            if hasattr(p, k):
                setattr(p, k, v)
        return p


@dataclass
class StyleProfile:
    centroid: list[float] = field(default_factory=list)
    scale: list[float] = field(default_factory=list)
    self_similarity_mean: float = 0.0
    self_similarity_sd: float = 0.0
    mean_words: float = 0.0
    greetings: dict[str, int] = field(default_factory=dict)
    signoffs: dict[str, int] = field(default_factory=dict)
    samples: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "centroid": self.centroid, "scale": self.scale,
            "self_similarity_mean": self.self_similarity_mean,
            "self_similarity_sd": self.self_similarity_sd,
            "mean_words": self.mean_words,
            "greetings": self.greetings, "signoffs": self.signoffs,
            "samples": self.samples,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "StyleProfile":
        p = StyleProfile()
        for k, v in (d or {}).items():
            if hasattr(p, k):
                setattr(p, k, v)
        return p

    def similarity(self, body: str) -> float | None:
        if not self.centroid or self.samples < MIN_SAMPLES_STYLE:
            return None
        vec = scaled(style_vector(body), self.scale)
        return cosine(vec, self.centroid)

    def word_count(self, body: str) -> int:
        return len(_WORD_RE.findall(strip_quoted(body or "")))

    def effective_sd(self) -> float:
        """Spread, widened for how little evidence it was estimated from.

        A standard deviation computed from a dozen messages is itself an
        estimate, and a confident one is exactly what produces false
        accusations. The 1/sqrt(n) term shrinks as real history accumulates.
        """
        return max(self.self_similarity_sd, 0.03 + 0.20 / max(self.samples, 1) ** 0.5)

    def z_score(self, similarity: float, n_words: int | None = None) -> float:
        """How unusual this similarity is *for this contact*.

        The absolute cosine is meaningless on its own - some people write very
        consistently and some ramble. Normalising by the contact's own spread is
        what stops the consistent writers generating false positives and the
        erratic ones hiding real mismatches.

        Short messages are discounted. Every feature here is a rate over tokens,
        so its sampling error grows as 1/sqrt(n): a fifteen-word note genuinely
        cannot be placed as precisely as a two-hundred-word one, and scoring it
        as though it could is how a real sender gets accused of being an impostor.
        """
        z = (self.self_similarity_mean - similarity) / self.effective_sd()
        if n_words and self.mean_words:
            confidence = min(1.0, (n_words / self.mean_words) ** 0.5)
            z *= confidence
        return z


@dataclass
class RelationshipProfile:
    sent_links: int = 0
    sent_attachments: int = 0
    messages: int = 0
    mean_recipients: float = 0.0
    link_orgs: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"sent_links": self.sent_links, "sent_attachments": self.sent_attachments,
                "messages": self.messages, "mean_recipients": self.mean_recipients,
                "link_orgs": self.link_orgs}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "RelationshipProfile":
        p = RelationshipProfile()
        for k, v in (d or {}).items():
            if hasattr(p, k):
                setattr(p, k, v)
        return p

    @property
    def ever_sent_links(self) -> bool:
        return self.sent_links > 0

    @property
    def ever_sent_attachments(self) -> bool:
        return self.sent_attachments > 0


@dataclass
class ContactProfile:
    canonical_email: str
    technical: TechnicalProfile = field(default_factory=TechnicalProfile)
    style: StyleProfile = field(default_factory=StyleProfile)
    relationship: RelationshipProfile = field(default_factory=RelationshipProfile)
    version: str = PROFILE_VERSION

    @property
    def usable_technical(self) -> bool:
        return self.technical.samples >= MIN_SAMPLES_TECHNICAL

    @property
    def usable_style(self) -> bool:
        return self.style.samples >= MIN_SAMPLES_STYLE


# ---------------------------------------------------------------- building

@dataclass
class SampleMessage:
    """The minimum a profile builder needs. Kept separate from MessageView so
    profiles can be built straight from database rows without constructing the
    heavier detection view."""
    body_text: str = ""
    x_mailer: str | None = None
    message_id: str | None = None
    mime_signature: str | None = None
    header_order_hash: str | None = None
    tz_offset: int | None = None
    origin_org: str | None = None
    dkim_domain: str | None = None
    hour: int | None = None
    n_recipients: int = 1
    has_links: bool = False
    has_attachments: bool = False
    link_orgs: Iterable[str] = ()


def build_profile(canonical_email: str, samples: list[SampleMessage]) -> ContactProfile:
    """Aggregate a contact's history into a profile."""
    profile = ContactProfile(canonical_email=canonical_email)
    tech, rel = profile.technical, profile.relationship

    bodies: list[str] = []
    for s in samples:
        tech.samples += 1
        tech.observe("x_mailers", s.x_mailer)
        tech.observe("msgid_shapes", message_id_shape(s.message_id))
        tech.observe("mime_signatures", s.mime_signature)
        tech.observe("header_orders", s.header_order_hash)
        tech.observe("tz_offsets", s.tz_offset)
        tech.observe("origin_orgs", s.origin_org)
        tech.observe("dkim_domains", s.dkim_domain)
        if s.hour is not None:
            tech.send_hours[str(s.hour)] = tech.send_hours.get(str(s.hour), 0) + 1

        rel.messages += 1
        rel.sent_links += 1 if s.has_links else 0
        rel.sent_attachments += 1 if s.has_attachments else 0
        rel.mean_recipients += s.n_recipients
        for org in s.link_orgs:
            if org:
                rel.link_orgs[org] = rel.link_orgs.get(org, 0) + 1

        body = strip_quoted(s.body_text or "")
        if len(_WORD_RE.findall(body)) >= MIN_WORDS_FOR_STYLE:
            bodies.append(s.body_text)

    if rel.messages:
        rel.mean_recipients = round(rel.mean_recipients / rel.messages, 2)

    if len(bodies) >= MIN_SAMPLES_STYLE:
        _fit_style(profile.style, bodies)
    for body in bodies:
        g, so = greeting_of(body), signoff_of(body)
        if g:
            profile.style.greetings[g] = profile.style.greetings.get(g, 0) + 1
        if so:
            profile.style.signoffs[so] = profile.style.signoffs.get(so, 0) + 1
    return profile


def _fit_style(style: StyleProfile, bodies: list[str]) -> None:
    vectors = [style_vector(b) for b in bodies]

    # Per-dimension spread, computed on this contact's own corpus.
    scale: list[float] = []
    for i in range(VECTOR_LEN):
        column = [v[i] for v in vectors]
        sd = statistics.pstdev(column) if len(column) > 1 else 0.0
        mean = statistics.fmean(column)
        scale.append(max(sd, abs(mean) * 0.25, MIN_SCALE))
    style.scale = scale

    normalised = [scaled(v, scale) for v in vectors]
    style.centroid = [statistics.fmean([v[i] for v in normalised]) for i in range(VECTOR_LEN)]

    # Leave-one-out self-similarity: how close this person's own messages sit to
    # their centroid. This is the yardstick every future message is measured
    # against, so it must be computed the same way one will be.
    sims: list[float] = []
    for i, vec in enumerate(normalised):
        if len(normalised) > 1:
            others = [v for j, v in enumerate(normalised) if j != i]
            centre = [statistics.fmean([v[k] for v in others]) for k in range(VECTOR_LEN)]
        else:
            centre = style.centroid
        sims.append(cosine(vec, centre))
    style.self_similarity_mean = round(statistics.fmean(sims), 4)
    style.self_similarity_sd = round(
        statistics.pstdev(sims) if len(sims) > 1 else 0.05, 4)
    style.samples = len(bodies)
    style.mean_words = round(statistics.fmean(
        [len(_WORD_RE.findall(strip_quoted(b))) for b in bodies]), 1)
