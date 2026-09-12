"""Regressions for bugs found by audit rather than by a failing test.

Every test here corresponds to a defect that existed in shipped code and passed
the whole suite. They are kept together so the class of mistake stays visible:
none of these were caught by testing what the code was *supposed* to do - they
came from measuring what it actually did.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.db.store import SCHEMA_VERSION, Store  # noqa: E402
from phishguard.detect import layer3, profiles  # noqa: E402
from phishguard.detect.context import AnalysisContext  # noqa: E402
from phishguard.detect.engine import analyse  # noqa: E402
from phishguard.detect.redact import leaks, redact  # noqa: E402
from phishguard.detect.view import MessageView  # noqa: E402
from phishguard.parse.message import parse_rfc822  # noqa: E402


# ------------------------------------------------------------- redaction

# Real formats, written the way real mail writes them. The original redactor
# anchored IBANs on [A-Z]{2} and passed every lowercase one straight through to
# the API - in the one component that transmits message content off the device.
FINANCIAL = [
    "pay to GB29NWBK60161331926819 today",
    "pay to gb29nwbk60161331926819 today",
    "pay to Gb29Nwbk60161331926819 today",
    "pay to GB29 NWBK 6016 1331 9268 19 today",
    "pay to DE89 3704 0044 0532 0130 00 today",
    "sort code 20-00-00 acct 12345678",
    "swift NWBKGB2L account 12345678",
    "routing 021000021 account 000123456789",
    "card 4111 1111 1111 1111 exp 12/27",
    "send to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq please",
    "send to 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7 please",
    "reference 887766554433 on the transfer",
]

# Ordinary business prose. A redactor that mangles these has silently disabled
# the layer instead of protecting it - the model cannot classify a request it
# can no longer read.
PROSE = [
    "Can we move the meeting to Tuesday afternoon please?",
    "The Q3 report shows revenue up 12% year over year.",
    "Your account details are attached for review.",
    "The account manager will call you back today.",
    "Please confirm receipt of the attached invoice.",
    "Reference the spec in section 4 before you start.",
    "I'll send the deck before the review on Thursday.",
    "We have 15 people confirmed for the workshop.",
]


def test_no_financial_identifier_survives_redaction():
    for text in FINANCIAL:
        out = redact(text, set())
        assert not leaks(text, out), f"{text!r} leaked {leaks(text, out)} as {out!r}"


def test_lowercase_iban_is_redacted():
    """The specific miss: the pattern required uppercase country codes."""
    for variant in ("GB29NWBK60161331926819", "gb29nwbk60161331926819",
                    "Gb29Nwbk60161331926819"):
        assert variant not in redact(f"send it to {variant}", set())


def test_redaction_does_not_eat_the_following_word():
    """The patterns allow internal spaces, so they ran past the word boundary
    and swallowed the next word along with the number."""
    assert redact("pay to GB29NWBK60161331926819 now", set()).endswith(" now")
    assert "exp 12/27" in redact("card 4111 1111 1111 1111 exp 12/27", set())


def test_ordinary_prose_is_left_alone():
    for text in PROSE:
        assert redact(text, set()) == text, f"over-redacted: {text!r}"


# Found only by running Layer 4 against a real mailbox: password-reset links,
# magic-link logins and cloud-console verification mails carry live single-use
# credentials in the query string. A real AWS root-account email was sending
# `?token=...&key=...` straight to the API.
CREDENTIAL_URLS = [
    "Verify at https://signin.aws.amazon.com/noMfa?action=verifyEmail"
    "&token=LQDSyIkrHF3LaDjz0bU2F7wPFf&key=AQEDAHjMwJfuh-ohxMDQKpdYSt8 now",
    "Reset here: https://account.example.com/reset/eyJhbGciOiJIUzI1NiJ9abcdefgh",
    "Sign in: https://app.example.com/magic?t=9f8e7d6c5b4a3f2e1d0c9b8a7",
    "Confirm: https://example.com/verify?email=x@y.com&code=884213",
]


def test_url_credentials_never_leave_the_device():
    for text in CREDENTIAL_URLS:
        out = redact(text, set())
        assert "token=" not in out and "key=" not in out and "code=" not in out
        assert not leaks(text, out), f"{text!r} leaked {leaks(text, out)}"


def test_url_host_survives_so_intent_is_still_answerable():
    """Stripping must not destroy the question. Where a link points is the
    whole signal; the credential attached to it never is."""
    out = redact("Click https://signin.aws.amazon.com/noMfa?token=SECRET123456", set())
    assert "signin.aws.amazon.com" in out
    assert "SECRET123456" not in out


def test_markup_noise_is_stripped_before_sending():
    """Outlook conditional comments are downlevel-revealed, so their contents
    reach any parser as real text. It is noise, it costs tokens, and it dilutes
    the prose the model is meant to read."""
    from phishguard.detect.redact import strip_markup

    raw = ('Keep track <!--[if !mso]> <!--> <div style="height:48px;width:268px;'
           'color:red;"> of your account')
    out = strip_markup(raw)
    assert "Keep track" in out and "of your account" in out
    assert "mso" not in out and "width:268px" not in out


def test_request_shape_survives_redaction():
    """Redacted text still has to be classifiable, or Layer 4 is switched off."""
    out = redact("Please change the account to GB29NWBK60161331926819 before Friday "
                 "and keep this between us.", set())
    for phrase in ("change the account", "before Friday", "between us"):
        assert phrase in out


# --------------------------------------------------------------- profiles

def test_old_contacts_still_get_a_profile():
    """Profiles were built by pulling the newest 4000 messages and sifting them
    per contact, so a long-standing correspondent whose mail all predated that
    window got no profile - Layer 2 silently switched itself off for exactly
    the relationships it matters most for."""
    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    acct = store.get_or_create_account("me@x.com")

    def add(gid, frm, when):
        raw = (f"From: P <{frm}>\r\nTo: me@x.com\r\nSubject: s\r\n"
               f"Message-ID: <{gid}@d.com>\r\nX-Mailer: Mail\r\n\r\n"
               f"this message has plenty of words in it to serve as a style sample").encode()
        store.upsert_message(acct, {"id": gid, "labelIds": ["INBOX"],
                                    "received_at": when}, parse_rfc822(raw), raw)

    for i in range(14):  # must clear MIN_SAMPLES_TECHNICAL
        add(f"old{i}", "old@friend.com", f"2020-01-{i + 1:02d}T09:00:00+00:00")
    for i in range(4100):
        add(f"new{i}", f"bulk{i % 50}@spam.com", "2025-09-01T09:00:00+00:00")

    profiles.build_all(store, acct)
    assert "old@friend.com" in profiles.load_all(store, acct), \
        "contact outside the recent window was dropped"
    store.close()


def test_profile_build_does_not_rescan_the_mailbox_per_contact():
    """The old query was O(contacts x messages): 40 contacts over 320 messages
    meant 12,800 row reads to build 40 profiles."""
    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    acct = store.get_or_create_account("me@x.com")
    for c in range(30):
        for m in range(14):  # must clear MIN_SAMPLES_TECHNICAL
            raw = (f"From: P{c} <p{c}@d{c}.com>\r\nTo: me@x.com\r\nSubject: s\r\n"
                   f"Message-ID: <a{m}@d{c}.com>\r\nX-Mailer: Mail\r\n\r\n"
                   f"this message has plenty of words in it to serve as a style sample").encode()
            store.upsert_message(acct, {"id": f"c{c}m{m}", "labelIds": ["INBOX"],
                                        "received_at": "2025-08-01T09:00:00+00:00"},
                                 parse_rfc822(raw), raw)

    # sqlite3's own trace hook, since Connection.execute is read-only.
    reads = {"n": 0}

    def trace(sql: str) -> None:
        if "FROM messages" in sql:
            reads["n"] += 1

    store.conn.set_trace_callback(trace)
    report = profiles.build_all(store, acct)
    store.conn.set_trace_callback(None)

    assert report.built == 30
    # One message query per contact, not one per contact per message.
    assert reads["n"] <= 40, f"{reads['n']} message queries for 30 contacts"
    store.close()


# ------------------------------------------------------------ performance

def test_html_is_parsed_once_per_message():
    """analyse() and the engine's link-corpus write each parsed independently,
    so every message with an HTML body was parsed twice per pass."""
    calls = {"n": 0}
    import phishguard.detect.content as content

    original = content.analyse_html

    def counting(html):
        calls["n"] += 1
        return original(html)

    content.analyse_html = counting
    try:
        html = "<p>hi</p>" + "".join(
            f'<a href="https://x{i}.com">link {i}</a>' for i in range(20))
        view = MessageView(gmail_id="t", body_html=html,
                           from_addr="a@b.com", from_domain="b.com")
        ctx = AnalysisContext(account_id=0)
        analyse(view, ctx)
        layer3.extract_links(view)          # what the engine does next
    finally:
        content.analyse_html = original
    assert calls["n"] == 1, f"HTML parsed {calls['n']} times for one message"


# --------------------------------------------------------------- metadata

def test_schema_version_tracks_the_schema():
    """It sat at "1" through four schema changes, which made it worthless as a
    migration signal."""
    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    recorded = store.conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'version'").fetchone()["value"]
    assert recorded == SCHEMA_VERSION

    tables = {r["name"] for r in store.conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    for late_addition in ("contact_profiles", "intent_cache", "message_links",
                          "domain_intel"):
        assert late_addition in tables
    assert int(SCHEMA_VERSION) > 1, "version not bumped after schema changes"
    store.close()


def test_llm_call_counter_is_populated():
    """AnalysisReport advertised `llm_calls` and never incremented it."""
    from phishguard.detect import intent
    from phishguard.detect.engine import Engine

    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    acct = store.get_or_create_account("me@x.com")
    raw = (b"From: Someone <a@b.com>\r\nTo: me@x.com\r\nSubject: hi\r\n"
           b"Reply-To: other@gmail.com\r\n"
           b"Authentication-Results: mx.google.com; dmarc=pass (p=NONE) header.from=b.com"
           b"\r\n\r\nplease review the attached document when you can")
    store.upsert_message(acct, {"id": "m1", "labelIds": ["INBOX"],
                                "received_at": "2025-09-01T09:00:00+00:00"},
                         parse_rfc822(raw), raw)

    class Stub:
        def classify(self, view, ctx):
            return intent.IntentResult(
                data={"intent": "benign", "confidence": 0.9,
                      "one_line_reason": "ordinary"}, cached=False)

    engine = Engine(store, acct, intent_client=Stub())
    report = engine.analyse_pending()
    assert report.llm_calls == 1, f"counter reported {report.llm_calls}"
    assert "llm calls" in str(report)
    store.close()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {exc}")
        except Exception as exc:
            failed += 1
            print(f"  ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    raise SystemExit(1 if failed else 0)
