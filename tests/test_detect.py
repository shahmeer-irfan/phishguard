"""Phase 1 detection tests.

The important ones are the last three: they cover the cases where a naive
implementation gets the answer confidently wrong.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.db.store import Store  # noqa: E402
from phishguard.detect import domains as D  # noqa: E402
from phishguard.detect.base import Severity, Tier  # noqa: E402
from phishguard.detect.context import build_context  # noqa: E402
from phishguard.detect.engine import Engine, analyse  # noqa: E402
from phishguard.detect.scoring import fuse, noisy_or  # noqa: E402
from phishguard.detect.view import MessageView  # noqa: E402
from phishguard.parse.message import parse_rfc822  # noqa: E402
from test_offline import LEGIT, SPOOFED  # noqa: E402


def _mail(*, frm, display="", reply_to="", return_path="", dmarc=None, spf=None,
          dkim=None, dkim_domain=None, arc=False, policy=None, subject="hi"):
    """Hand-built MessageView. Faster and far clearer than crafting RFC822 for
    every permutation of authentication results."""
    raw = None
    if dmarc:
        raw = f"mx.google.com; dmarc={dmarc} (p={policy or 'NONE'} sp=NONE dis=NONE) " \
              f"header.from={frm.rpartition('@')[2]}"
    return MessageView(
        gmail_id="test", subject=subject,
        from_addr=frm, from_display=display, from_domain=frm.rpartition("@")[2],
        reply_to_addr=reply_to, return_path_addr=return_path,
        spf=spf, dkim=dkim, dkim_domain=dkim_domain, dmarc=dmarc,
        arc_present=arc, auth_raw=raw, auth_present=bool(raw),
    )


def _codes(verdict):
    return {f.code for f in verdict.findings}


def _store_with_history():
    """A mailbox where Abdul is an established correspondent."""
    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    account = store.get_or_create_account("victim@gmail.com")

    def add(gid, frm, display, labels, n=1):
        for i in range(n):
            store.upsert_message(account, {
                "id": f"{gid}-{i}", "labelIds": labels, "received_at": "2025-08-01T00:00:00+00:00",
            }, parse_rfc822(
                f"From: {display} <{frm}>\r\nTo: victim@gmail.com\r\n"
                f"Subject: s{i}\r\n\r\nbody".encode()))

    # Received from Abdul, and written back to him: an established relationship.
    add("in", "abdul@company.com", "Abdul Rehman", ["INBOX"], n=6)
    store.upsert_message(account, {"id": "out-1", "labelIds": ["SENT"]},
                         parse_rfc822(b"From: victim@gmail.com\r\n"
                                      b"To: Abdul Rehman <abdul@company.com>\r\n"
                                      b"Subject: re\r\n\r\nok"))
    return store, account


# ------------------------------------------------------------------ layer 0

def test_dmarc_fail_with_reject_policy_is_hard_danger():
    v = analyse(_mail(frm="ceo@bigbank.com", dmarc="fail", policy="REJECT"),
                build_ctx())
    assert v.tier is Tier.DANGER
    assert "DMARC_FAIL_ENFORCED" in _codes(v)
    assert v.score > 0.9


def test_dmarc_fail_without_enforcement_is_softer():
    v = analyse(_mail(frm="x@smallco.com", dmarc="fail", policy="NONE"), build_ctx())
    assert "DMARC_FAIL_ENFORCED" not in _codes(v)
    assert "DMARC_FAIL" in _codes(v)
    assert v.tier is Tier.DANGER or v.tier is Tier.CAUTION


def test_reply_to_freemail_flagged_even_when_dmarc_passes():
    """The BEC mechanic. The domain is genuine; the conversation is redirected.
    Reply-To is not an authenticated identifier, so DMARC cannot cover it."""
    v = analyse(_mail(frm="ceo@company.com", dmarc="pass",
                      reply_to="ceo.private@gmail.com"), build_ctx())
    assert "REPLY_TO_FREEMAIL" in _codes(v)
    assert v.tier is not Tier.SAFE


def test_dkim_pass_but_unaligned():
    """A passing signature applied by a domain the attacker owns."""
    v = analyse(_mail(frm="billing@paypal.com", dkim="pass",
                      dkim_domain="mailer-xyz.ru", dmarc="none"), build_ctx())
    assert "DKIM_UNALIGNED" in _codes(v)


def test_arc_damps_forwarding_breakage():
    without = analyse(_mail(frm="x@news.com", spf="fail", dmarc="none"), build_ctx())
    with_arc = analyse(_mail(frm="x@news.com", spf="fail", dmarc="none", arc=True),
                       build_ctx())
    assert with_arc.score < without.score
    assert "ARC_FORWARDED" in _codes(with_arc)


def test_clean_authenticated_mail_is_safe():
    v = analyse(_mail(frm="noreply@github.com", dmarc="pass", spf="pass", dkim="pass"),
                build_ctx())
    assert v.tier is Tier.SAFE


# ------------------------------------------------------------------ layer 1

def test_display_name_impersonation_from_unknown_address():
    """The flagship case, and the email twin of the voice-note scenario:
    a known name arriving from an address that name has never used."""
    store, account = _store_with_history()
    ctx = build_context(store, account)
    v = analyse(_mail(frm="abdulrehman.finance@gmail.com", display="Abdul Rehman",
                      dmarc="pass", spf="pass", dkim="pass"), ctx)
    assert "DISPLAY_NAME_IMPERSONATION_FREEMAIL" in _codes(v)
    assert v.tier is Tier.DANGER
    store.close()


def test_real_abdul_is_not_flagged():
    """The false-positive half of the same test. Without this the detector is
    just a machine for accusing the user's actual colleagues."""
    store, account = _store_with_history()
    ctx = build_context(store, account)
    v = analyse(_mail(frm="abdul@company.com", display="Abdul Rehman",
                      dmarc="pass", spf="pass", dkim="pass"), ctx)
    assert not any(c.startswith("DISPLAY_NAME_IMPERSONATION") for c in _codes(v))
    assert "ESTABLISHED_CORRESPONDENT" in _codes(v)
    assert v.tier is Tier.SAFE
    store.close()


def test_cousin_domain_detected():
    store, account = _store_with_history()
    ctx = build_context(store, account)
    v = analyse(_mail(frm="abdul@company-payroll.com", display="Abdul Rehman",
                      dmarc="pass"), ctx)
    codes = _codes(v)
    assert any(c.startswith("LOOKALIKE_DOMAIN") for c in codes)
    assert v.tier is not Tier.SAFE
    store.close()


def test_display_name_carrying_a_foreign_address():
    v = analyse(_mail(frm="attacker@random.ru", display="billing@paypal.com",
                      dmarc="pass"), build_ctx())
    assert "DISPLAY_NAME_IS_FOREIGN_ADDRESS" in _codes(v)


def test_first_contact_alone_is_not_an_alarm():
    """Most legitimate mail from a new supplier or recruiter is first contact.
    It must compound with other evidence, never fire on its own."""
    v = analyse(_mail(frm="recruiter@newagency.com", display="Sara Malik",
                      dmarc="pass", spf="pass", dkim="pass"), build_ctx())
    assert "FIRST_CONTACT" in _codes(v)
    assert v.tier is Tier.SAFE


# ------------------------------------------------- the three that matter most

def test_dmarc_pass_cannot_excuse_impersonation():
    """The single most important assertion in Phase 1.

    An attacker who registers their own domain passes SPF, DKIM and DMARC
    perfectly. If reassuring findings were allowed to damp identity findings,
    the product would clear the exact attack it exists to catch.
    """
    store, account = _store_with_history()
    ctx = build_context(store, account)
    v = analyse(_mail(frm="abdul@evil-abdul.com", display="Abdul Rehman",
                      dmarc="pass", spf="pass", dkim="pass"), ctx)
    assert "DMARC_PASS" in _codes(v)                      # protocol is happy
    assert "DISPLAY_NAME_IMPERSONATION" in _codes(v)      # identity is not
    assert v.tier is Tier.DANGER, f"got {v.tier} at {v.score}"
    store.close()


def test_contact_graph_does_not_poison_itself():
    """A single phishing message must not establish the impersonator as a
    legitimate reference identity for the next one."""
    store, account = _store_with_history()
    # One inbound message from a fake Abdul, exactly as ingestion would record it.
    store.upsert_message(account, {"id": "phish-1", "labelIds": ["INBOX"]},
                         parse_rfc822(b"From: Abdul Rehman <abdul@evil-abdul.com>\r\n"
                                      b"To: victim@gmail.com\r\nSubject: x\r\n\r\nhi"))
    ctx = build_context(store, account)

    targets = {t.canonical_email for t in ctx.impersonation_targets("Abdul Rehman")}
    assert targets == {"abdul@company.com"}       # the fake is not reference-grade
    assert "evil-abdul.com" not in ctx.reference_domains

    v = analyse(_mail(frm="abdul@evil-abdul.com", display="Abdul Rehman",
                      dmarc="pass"), ctx)
    assert "DISPLAY_NAME_IMPERSONATION" in _codes(v)
    store.close()


def test_own_sent_mail_is_never_scored():
    store, account = _store_with_history()
    engine = Engine(store, account)
    report = engine.analyse_pending()
    sent = store.conn.execute(
        """SELECT COUNT(*) c FROM messages m LEFT JOIN verdicts v ON v.message_id = m.id
           WHERE m.labels_json LIKE '%SENT%' AND v.id IS NOT NULL""").fetchone()["c"]
    assert sent == 0, "outbound mail was scored"
    assert report.skipped >= 1
    assert report.analysed > 0
    store.close()


# ------------------------------------------------------------- domain logic

def test_org_domain():
    assert D.org_domain("mail.foo.co.uk") == "foo.co.uk"
    assert D.org_domain("a.b.company.com") == "company.com"
    assert D.org_domain("evil.github.io") == "evil.github.io"  # separate tenants
    assert D.org_domain("company.com") == "company.com"


def test_lookalike_kinds():
    assert D.lookalike_kind("paypa1.com", "paypal.com")[0] == "visual"
    assert D.lookalike_kind("rnicrosoft.com", "microsoft.com")[0] == "visual"
    assert D.lookalike_kind("cornpany.com", "company.com")[0] == "visual"
    assert D.lookalike_kind("cornpany.co", "company.com")[0] == "visual"
    assert D.lookalike_kind("compamy.com", "company.com")[0] == "typo"
    assert D.lookalike_kind("company.co", "company.com")[0] == "tld_swap"
    assert D.lookalike_kind("company-payroll.com", "company.com")[0] == "cousin"
    assert D.lookalike_kind("secure-company.net", "company.com")[0] == "cousin"
    # Unrelated names must not match, or every report becomes noise.
    assert D.lookalike_kind("github.com", "company.com") is None
    assert D.lookalike_kind("bbc.co.uk", "abc.com") is None


def test_homoglyph_detection():
    # 'аpple.com' with a Cyrillic а, punycode-encoded as a real client sends it.
    assert D.homoglyph_check("xn--pple-43d.com") is not None
    assert D.homoglyph_check("apple.com") is None
    assert D.homoglyph_check("company.co.uk") is None


def test_display_name_normalisation():
    n = D.normalise_display_name
    assert n("Dr. Abdul Rehman") == n("REHMAN, ABDUL") == n("abdul  rehman")
    assert n("Abdul") != n("Abdul Rehman")


def test_freemail_classification():
    assert D.is_freemail("gmail.com") and D.is_freemail("mail.ru")
    assert not D.is_freemail("company.com")


# -------------------------------------------------------------- fusion maths

def test_noisy_or_is_bounded_and_saturating():
    assert noisy_or([]) == 0.0
    assert abs(noisy_or([0.5, 0.5]) - 0.75) < 1e-9
    assert noisy_or([0.4] * 20) < 1.0
    # Order must not matter, and weak signals must not sum past strong ones.
    assert noisy_or([0.9, 0.1]) == noisy_or([0.1, 0.9])
    assert noisy_or([0.2, 0.2, 0.2]) < 0.7


def test_hard_verdict_short_circuits_fusion():
    from phishguard.detect.base import Finding

    findings = [
        Finding("HARD", 0, Severity.CRITICAL, 0.9, "forged", hard_tier=Tier.DANGER),
        Finding("GOOD", 1, Severity.INFO, 0.9, "known sender", mitigating=True),
    ]
    assert fuse(findings).tier is Tier.DANGER


def test_end_to_end_on_the_rfc822_fixtures():
    spoof = analyse(MessageView.from_parsed(parse_rfc822(SPOOFED)), build_ctx())
    legit = analyse(MessageView.from_parsed(parse_rfc822(LEGIT)), build_ctx())
    assert spoof.tier is Tier.DANGER and spoof.score > legit.score
    assert legit.tier is Tier.SAFE
    assert spoof.headline  # something to actually show the user


def build_ctx():
    from phishguard.detect.context import AnalysisContext
    return AnalysisContext(account_id=0, account_email="victim@gmail.com")


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
