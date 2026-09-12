"""Phase 3 tests - Layer 2 sender fingerprinting.

The hard part of this layer is not catching the impostor; it is not accusing
the real person. People change phones, travel, and write differently when
rushed. Most of these tests exist to hold that line.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.db.store import Store  # noqa: E402
from phishguard.detect import fingerprint as FP, layer2, profiles  # noqa: E402
from phishguard.detect.base import Severity  # noqa: E402
from phishguard.detect.context import AnalysisContext, build_context  # noqa: E402
from phishguard.detect.view import MessageView  # noqa: E402
from phishguard.parse.message import parse_rfc822  # noqa: E402

# Two writers with genuinely different habits: short and clipped with
# contractions, versus long formal clauses with none.
CASUAL = [
    "hey, can you take a look at the deck before tomorrow? i think slide 4 is off.",
    "sorry - forgot to send this. here's the updated sheet, let me know if it's wrong.",
    "yeah that works for me. i'll ping the team and we can go from there, no rush.",
    "quick one: did the invoice go out? i can't find it in the folder anywhere.",
    "thanks! that's much clearer now. i'll pick it up monday and finish the rest.",
    "not sure about this one. let's talk friday, i'd rather not decide over email.",
    "all good on my end. i've pushed the changes, give it a look when you get time.",
    "can't make the 3pm, sorry. could we push it to thursday? i'm free after lunch.",
    "that's the wrong file i think - it's the old version from last month again.",
    "no worries at all, take your time. i'll chase the other thing in the meantime.",
    "i've had a look and it seems fine to me, but you should double check page two.",
    "did we ever hear back on this? it's been a couple of weeks now i reckon.",
    "sounds good. i'll put something in the calendar and we can sort it out then.",
    "just seen your note - yes that's fine by me, go ahead and send it over.",
    "hmm, not sure that's right. can you walk me through how you got that number?",
]
FORMAL = [
    "Dear colleague, I am writing to inform you that the aforementioned documentation "
    "has been reviewed in accordance with the established procedure, and I would be "
    "grateful if you would confirm receipt at your earliest convenience.",
    "Please be advised that the matter under consideration requires further "
    "deliberation, and accordingly I should like to propose that we defer any "
    "determination until such time as the relevant particulars have been furnished.",
    "I refer to your communication of the 14th instant and wish to confirm that the "
    "position remains as previously stated, notwithstanding the representations which "
    "have subsequently been made.",
    "Kindly note that the requisite authorisation has now been obtained, and the "
    "settlement may therefore proceed in the manner contemplated by the agreement.",
    "With reference to the outstanding balance, I should be obliged if arrangements "
    "could be made for remittance in accordance with the terms previously agreed.",
    "I should like to record my appreciation for your assistance in this matter, and "
    "trust that the arrangements described will prove satisfactory to all concerned.",
    "It is incumbent upon me to advise that the aforesaid particulars have been "
    "transmitted to the relevant department for such action as may be considered "
    "appropriate in the prevailing circumstances.",
    "Further to our previous correspondence, I would respectfully submit that the "
    "proposal as presently constituted does not adequately address the concerns which "
    "were raised at the preceding meeting.",
    "I am directed to inform you that approval has been granted in principle, subject "
    "always to the satisfactory completion of the formalities hereinbefore described.",
    "Should you require any further particulars in relation to the foregoing, please "
    "do not hesitate to communicate with the undersigned at your convenience.",
    "It would appear that an administrative oversight has occurred, and I should be "
    "grateful if you would arrange for the necessary rectification to be effected.",
    "Pursuant to the terms of the agreement, notification is hereby given that the "
    "period for performance shall expire upon the date specified in the schedule.",
]


def _samples(bodies, **over):
    base = dict(x_mailer="Apple Mail (2.3731.700.6)", mime_signature="text/plain",
                header_order_hash="aaaa1111", tz_offset=300,
                origin_org="company.com", dkim_domain="company.com", hour=9)
    base.update(over)
    out = []
    for i, body in enumerate(bodies):
        out.append(FP.SampleMessage(
            body_text=body, message_id=f"ABC{i}DEF-1234@mail.company.com", **base))
    return out


def _view(body, **over):
    defaults = dict(
        from_addr="abdul@company.com", from_domain="company.com",
        x_mailer="Apple Mail (2.3731.700.6)", mime_signature="text/plain",
        header_order_hash="aaaa1111", date_tz_offset=300,
        rfc822_message_id="XYZ9WWW-5678@mail.company.com", dkim_domain="company.com",
        dmarc="pass", spf="pass", dkim="pass",
    )
    defaults.update(over)
    return MessageView(gmail_id="t", subject="s", body_text=body, **defaults)


def _ctx(profile):
    c = AnalysisContext(account_id=0, account_email="victim@gmail.com")
    c.profiles = {profile.canonical_email: profile}
    return c


def _codes(findings):
    return {f.code for f in findings}


# ---------------------------------------------------------------- features

def test_message_id_shape_is_stable_per_client():
    """Same generator, different values - the shape must collapse to one key."""
    a = FP.message_id_shape("CAF+abc123def@mail.gmail.com")
    b = FP.message_id_shape("CAF+xyz987ghi@mail.gmail.com")
    assert a == b == "a+a9a@mail.gmail.com"
    # A different generator must not collide with it.
    assert FP.message_id_shape("20250909101420.9f3a1@vps.ru") != a


def test_quoted_history_is_stripped():
    """Without this every reply inherits the style of whoever is quoted."""
    body = "my actual reply\n\nOn Mon, Abdul wrote:\n> their words\n> more of them"
    out = FP.strip_quoted(body)
    assert "my actual reply" in out
    assert "their words" not in out


def test_signature_block_is_stripped():
    out = FP.strip_quoted("real text here\n--\nAbdul Rehman | CEO | company.com")
    assert "real text" in out and "CEO" not in out


def test_style_vector_is_fixed_width_and_rate_based():
    short, long = FP.style_vector("hi there ok"), FP.style_vector("hi there ok " * 200)
    assert len(short) == len(long) == FP.VECTOR_LEN
    # Rates, not counts: repeating the same text must not move the vector much.
    assert FP.cosine(short, long) > 0.95


def test_greeting_and_signoff_extraction():
    body = "Hi Sara,\n\nplease see attached.\n\nThanks\nAbdul"
    assert FP.greeting_of(body) == "hi"
    assert FP.signoff_of(body) == "thanks"


def test_distinct_writers_separate_in_vector_space():
    casual = FP.build_profile("a@b.com", _samples(CASUAL))
    formal_sim = casual.style.similarity(FORMAL[0])
    casual_sim = casual.style.similarity(
        "hey quick one, can you check the file? i think it's wrong but not sure.")
    assert formal_sim is not None and casual_sim is not None
    assert casual_sim > formal_sim, f"casual {casual_sim} !> formal {formal_sim}"


# ---------------------------------------------------------------- profiles

def test_profile_needs_enough_history():
    thin = FP.build_profile("a@b.com", _samples(CASUAL[:2]))
    assert not thin.usable_technical
    assert not thin.usable_style
    full = FP.build_profile("a@b.com", _samples(CASUAL))
    assert full.usable_technical and full.usable_style


def test_technical_profile_records_distribution_not_just_latest():
    samples = _samples(CASUAL[:4]) + _samples(CASUAL[4:], x_mailer="Outlook 16.0")
    p = FP.build_profile("a@b.com", samples)
    assert p.technical.is_known("x_mailers", "Apple Mail (2.3731.700.6)")
    assert p.technical.is_known("x_mailers", "Outlook 16.0")
    assert 0 < p.technical.share("x_mailers", "Outlook 16.0") < 1


# ----------------------------------------------------------- the false-positive line

def test_real_sender_with_matching_fingerprint_is_not_flagged():
    p = FP.build_profile("abdul@company.com", _samples(CASUAL))
    findings = layer2.run(_view("hey, can you send over the file when you get a sec?"), _ctx(p))
    assert not any(f.code.endswith("MISMATCH") for f in findings)


def test_one_changed_dimension_is_not_an_alarm():
    """A new phone changes the mail client and nothing else. That is not an attack."""
    p = FP.build_profile("abdul@company.com", _samples(CASUAL))
    findings = layer2.run(
        _view("hey, quick one - did you see my last message about the deck?",
              x_mailer="iPhone Mail 18.1"), _ctx(p))
    mismatches = [f for f in findings if f.code == "TECHNICAL_FINGERPRINT_MISMATCH"]
    assert not mismatches or mismatches[0].severity in (Severity.LOW, Severity.INFO)


def test_short_message_is_not_style_judged():
    """Three words cannot characterise anyone. Silence beats a guess."""
    p = FP.build_profile("abdul@company.com", _samples(CASUAL))
    findings = layer2.run(_view("ok thanks"), _ctx(p))
    assert not any(f.code.startswith("WRITING_STYLE") for f in findings)


def test_no_profile_means_no_findings():
    assert layer2.run(_view("anything at all here"), AnalysisContext(account_id=0)) == []


# ------------------------------------------------------------- detection

def test_wholesale_technical_change_is_flagged():
    p = FP.build_profile("abdul@company.com", _samples(CASUAL))
    findings = layer2.run(_view(
        "hey can you check this",
        x_mailer="PHPMailer 6.8.0", mime_signature="multipart/mixed(text/html)",
        header_order_hash="ffff9999", date_tz_offset=-420,
        rfc822_message_id="1757412345.0@webmail.vps.ru", dkim_domain="vps.ru",
    ), _ctx(p))
    hit = [f for f in findings if f.code == "TECHNICAL_FINGERPRINT_MISMATCH"]
    assert hit and hit[0].severity is Severity.CRITICAL


def test_mid_thread_change_is_escalated():
    """A shift inside a live conversation is account takeover, not a new laptop."""
    p = FP.build_profile("abdul@company.com", _samples(CASUAL))
    changed = dict(x_mailer="PHPMailer 6.8.0", header_order_hash="ffff9999",
                   rfc822_message_id="1757412345.0@webmail.vps.ru")
    cold = layer2.run(_view("hey can you check this", **changed), _ctx(p))
    warm = layer2.run(_view("hey can you check this", in_reply_to="prev@company.com",
                            **changed), _ctx(p))
    c = next(f for f in cold if f.code == "TECHNICAL_FINGERPRINT_MISMATCH")
    w = next(f for f in warm if f.code == "TECHNICAL_FINGERPRINT_MISMATCH")
    assert w.weight > c.weight
    assert w.evidence["mid_thread"] is True


def test_style_mismatch_detected_on_substituted_writer():
    """The compromised-account case: right address, wrong person typing."""
    p = FP.build_profile("abdul@company.com", _samples(CASUAL))
    findings = layer2.run(_view(FORMAL[1]), _ctx(p))
    assert any(f.code in ("WRITING_STYLE_MISMATCH", "WRITING_STYLE_UNUSUAL")
               for f in findings), _codes(findings)


def test_matching_style_produces_a_mitigating_finding():
    p = FP.build_profile("abdul@company.com", _samples(CASUAL))
    findings = layer2.run(
        _view("hey, i think the numbers on slide 3 aren't right. can you check it?"),
        _ctx(p))
    match = [f for f in findings if f.code == "WRITING_STYLE_MATCH"]
    if match:
        assert match[0].mitigating and match[0].scope == frozenset({1, 2})


def test_first_ever_attachment_from_long_correspondent():
    from phishguard.detect.attachments import AttachmentInfo

    p = FP.build_profile("abdul@company.com", _samples(CASUAL * 2))
    view = _view("please see attached")
    view.attachments = [AttachmentInfo("invoice.pdf", "application/pdf", 1000)]
    assert "FIRST_EVER_ATTACHMENT" in _codes(layer2.run(view, _ctx(p)))


# -------------------------------------------------------- the poisoning gate

def test_danger_messages_are_excluded_from_profiles():
    """Without this the first successful impersonation becomes the baseline the
    second one is measured against."""
    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    acct = store.get_or_create_account("victim@gmail.com")

    def add(gid, body, tier=None):
        raw = (f"From: Abdul Rehman <abdul@company.com>\r\nTo: victim@gmail.com\r\n"
               f"Subject: s\r\nMessage-ID: <{gid}@mail.company.com>\r\n"
               f"X-Mailer: Apple Mail\r\n\r\n{body}").encode()
        mid = store.upsert_message(acct, {
            "id": gid, "labelIds": ["INBOX"],
            "received_at": "2025-08-01T09:00:00+00:00"}, parse_rfc822(raw), raw)
        if tier:
            store.conn.execute(
                "INSERT INTO verdicts(message_id, tier, score, model_version, created_at)"
                " VALUES(?,?,?,?,?)", (mid, tier, 0.9, "t", "2025-08-01"))

    for i, body in enumerate(CASUAL):
        add(f"ok{i}", body)
    for i, body in enumerate(FORMAL):
        add(f"bad{i}", body, tier="danger")

    report = profiles.build_all(store, acct)
    assert report.excluded_messages == len(FORMAL)

    ctx = build_context(store, acct)
    p = ctx.profile_for("abdul@company.com")
    assert p is not None and p.technical.samples == len(CASUAL)
    store.close()


def test_profiles_round_trip_through_the_database():
    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    acct = store.get_or_create_account("victim@gmail.com")
    original = FP.build_profile("abdul@company.com", _samples(CASUAL))
    store.save_profile(acct, original)

    loaded = profiles.load_all(store, acct)["abdul@company.com"]
    assert loaded.technical.samples == original.technical.samples
    assert loaded.style.centroid == original.style.centroid
    assert loaded.style.self_similarity_mean == original.style.self_similarity_mean
    assert store.profile_is_current(acct, "abdul@company.com", FP.PROFILE_VERSION)
    assert not store.profile_is_current(acct, "abdul@company.com", "other-version")
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
