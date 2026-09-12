"""Phases 4 and 5, plus the security work.

No network and no API key. Layer 4 is tested through a stub client, because
what matters here is the contract around the model - redaction, banding,
caching, and the refusal to let a confident answer override a cryptographic
fact - not the model's own judgement.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.db.store import Store  # noqa: E402
from phishguard.detect import intent  # noqa: E402
from phishguard.detect.base import Tier  # noqa: E402
from phishguard.detect.context import AnalysisContext  # noqa: E402
from phishguard.detect.engine import analyse  # noqa: E402
from phishguard.detect.scoring import CAUTION_THRESHOLD  # noqa: E402
from phishguard.detect.view import MessageView  # noqa: E402
from phishguard.evaluate import harness, synth  # noqa: E402
from phishguard.parse.message import parse_rfc822  # noqa: E402
from phishguard import security  # noqa: E402


def _ctx():
    c = AnalysisContext(account_id=0, account_email="victim@gmail.com")
    c.reference_domains = {"company.com": 1.0}
    return c


def _view(**over):
    d = dict(gmail_id="t", subject="Hello", from_addr="a@example.com",
             from_domain="example.com", body_text="Some body text.",
             dmarc="pass", spf="pass", dkim="pass", auth_present=True,
             auth_raw="mx.google.com; dmarc=pass (p=NONE) header.from=example.com")
    d.update(over)
    return MessageView(**d)


class StubClient:
    """Stands in for IntentClient. Records what it was asked."""

    def __init__(self, data, *, error=None):
        self.data, self.error = data, error
        self.calls: list[str] = []

    def classify(self, view, ctx):
        self.calls.append(view.gmail_id)
        return intent.IntentResult(data=self.data, error=self.error)


# ------------------------------------------------------------- redaction

def test_redaction_removes_identifiers_but_keeps_shape():
    text = ("Hi, wire the payment to IBAN GB29NWBK60161331926819, account "
            "12345678901, or call me on +44 7700 900123. Reply to "
            "cfo.private@gmail.com. Card 4111 1111 1111 1111.")
    out = intent.redact(text, {"victim@gmail.com"})

    for secret in ("GB29NWBK60161331926819", "12345678901", "900123",
                   "4111 1111 1111 1111", "cfo.private@"):
        assert secret not in out, secret
    # The request must remain classifiable after redaction.
    assert "wire the payment" in out
    # Domains survive, because the domain is the part that carries signal.
    assert "gmail.com" in out


def test_redaction_masks_the_users_own_address():
    out = intent.redact("Sent to victim@gmail.com regarding your order",
                        {"victim@gmail.com"})
    assert "victim@gmail.com" not in out and "[YOUR-ADDRESS]" in out


def test_prompt_never_contains_raw_body_identifiers():
    ctx = _ctx()
    view = _view(body_text="Please pay IBAN GB29NWBK60161331926819 today",
                 subject="Invoice for victim@gmail.com")
    prompt = intent.build_user_prompt(view, ctx)
    assert "GB29NWBK60161331926819" not in prompt
    assert "victim@gmail.com" not in prompt


def test_prompt_hash_is_stable_and_content_sensitive():
    ctx = _ctx()
    a = intent.build_user_prompt(_view(body_text="one"), ctx)
    b = intent.build_user_prompt(_view(body_text="one"), ctx)
    c = intent.build_user_prompt(_view(body_text="two"), ctx)
    assert intent.prompt_hash(a) == intent.prompt_hash(b)
    assert intent.prompt_hash(a) != intent.prompt_hash(c)


# ------------------------------------------------------------- the band

def test_band_excludes_the_already_decided():
    assert not intent.in_band(0.02)   # rules already say it is fine
    assert not intent.in_band(0.97)   # rules already say it is forged
    assert intent.in_band(0.45)       # genuinely unclear


def test_llm_is_not_called_for_an_obviously_forged_message():
    """A p=reject DMARC failure is settled. Paying for a second opinion - and
    shipping the message off-device to get it - buys nothing."""
    stub = StubClient({"intent": "payment_redirection", "confidence": 0.9})
    view = _view(dmarc="fail",
                 auth_raw="mx.google.com; dmarc=fail (p=REJECT) header.from=example.com")
    verdict = analyse(view, _ctx(), stub)
    assert verdict.tier is Tier.DANGER
    assert stub.calls == [], "LLM was called on an already-decided message"


def test_llm_is_not_called_for_clean_mail():
    stub = StubClient({"intent": "benign", "confidence": 0.9})
    analyse(_view(from_addr="x@company.com", from_domain="company.com"), _ctx(), stub)
    assert stub.calls == []


def test_llm_is_called_in_the_ambiguous_band():
    stub = StubClient({"intent": "benign", "confidence": 0.9,
                       "one_line_reason": "ordinary note"})
    # Reply-To divergence alone lands mid-band.
    analyse(_view(reply_to_addr="someone.else@gmail.com"), _ctx(), stub)
    assert stub.calls == ["t"]


# ----------------------------------------------------------- findings

def test_payment_redirection_escalates():
    stub = StubClient({"intent": "payment_redirection", "confidence": 0.9,
                       "urgency": "high", "one_line_reason": "asks to change bank details"})
    plain = analyse(_view(reply_to_addr="x@gmail.com"), _ctx())
    with_llm = analyse(_view(reply_to_addr="x@gmail.com"), _ctx(), stub)
    assert with_llm.score > plain.score
    assert "INTENT_PAYMENT_REDIRECTION" in {f.code for f in with_llm.findings}


def test_prompt_injection_in_body_is_itself_a_finding():
    """Only an attack writes instructions to an automated reviewer."""
    findings = intent.to_findings(intent.IntentResult(data={
        "intent": "credential_request", "confidence": 0.8,
        "prompt_injection_attempt": True,
        "one_line_reason": "body contains instructions telling scanners to approve it",
    }))
    assert "PROMPT_INJECTION_IN_BODY" in {f.code for f in findings}


def test_benign_verdict_cannot_clear_a_hard_danger():
    """The model is one witness, never the judge."""
    stub = StubClient({"intent": "benign", "confidence": 0.99,
                       "one_line_reason": "looks completely fine"})
    view = _view(dmarc="fail",
                 auth_raw="mx.google.com; dmarc=fail (p=REJECT) header.from=example.com")
    assert analyse(view, _ctx(), stub).tier is Tier.DANGER


def test_benign_mitigation_is_scoped_away_from_identity():
    findings = intent.to_findings(intent.IntentResult(data={
        "intent": "benign", "confidence": 0.9, "one_line_reason": "fine"}))
    benign = next(f for f in findings if f.code == "INTENT_BENIGN")
    assert benign.mitigating and benign.scope == frozenset({3, 4})
    # It must not be able to excuse a Layer-1 impersonation.
    assert not benign.applies_to(1)


def test_errors_and_refusals_produce_no_findings():
    assert intent.to_findings(intent.IntentResult(data={}, error="rate limited")) == []
    assert intent.to_findings(intent.IntentResult(data={})) == []


def test_low_confidence_is_downgraded_not_ignored():
    hi = intent.to_findings(intent.IntentResult(data={
        "intent": "credential_request", "confidence": 0.95, "one_line_reason": "x"}))
    lo = intent.to_findings(intent.IntentResult(data={
        "intent": "credential_request", "confidence": 0.2, "one_line_reason": "x"}))
    assert hi[0].weight > lo[0].weight > 0


def test_cache_prevents_a_second_call():
    tmp = tempfile.mkdtemp()
    store = Store(Path(tmp) / "t.db")
    client = intent.IntentClient(store=store)
    key = "deadbeef" * 8
    client._store(key, None, {"intent": "benign", "confidence": 0.9}, 100, 20)
    assert client._cached(key) == {"intent": "benign", "confidence": 0.9}
    assert client._cached("0" * 64) is None
    store.close()


# ------------------------------------------------------- synthetic attacks

def _sources(n=6):
    return [synth.SourceMessage(
        gmail_id=f"g{i}", from_addr=f"person{i}@company.com",
        from_display=f"Person {i}", subject="Project update",
        body_text="Here is the latest on the project, let me know what you think.",
        to_addr="victim@gmail.com") for i in range(n)]


def test_every_transform_produces_parseable_mail():
    made = synth.generate(_sources(), per_transform=2)
    assert made
    for msg in made:
        parsed = parse_rfc822(msg.raw)
        assert parsed.parse_error is None, f"{msg.transform}: {parsed.parse_error}"
        assert parsed.from_addr, msg.transform
        assert msg.label == "attack"


def test_all_seven_techniques_are_generated():
    made = synth.generate(_sources(10), per_transform=3)
    assert {m.transform for m in made} == set(synth.TRANSFORM_FNS)


def test_generation_is_deterministic_for_a_seed():
    a = synth.generate(_sources(), per_transform=2, seed=7)
    b = synth.generate(_sources(), per_transform=2, seed=7)
    c = synth.generate(_sources(), per_transform=2, seed=8)
    assert [m.raw for m in a] == [m.raw for m in b]
    assert [m.raw for m in a] != [m.raw for m in c]


def test_one_attack_per_contact_per_transform():
    """Twenty variations on one contact would let a detector look good by
    learning a single relationship."""
    made = synth.generate(_sources(3), per_transform=10)
    by_transform: dict[str, list[str]] = {}
    for m in made:
        by_transform.setdefault(m.transform, []).append(m.impersonated)
    for transform, targets in by_transform.items():
        assert len(targets) == len(set(targets)), transform


def test_generated_attacks_are_actually_caught():
    """End-to-end: the generator and the detector must agree on what an attack
    is, or the evaluation measures nothing."""
    ctx = _ctx()
    made = synth.generate(_sources(8), per_transform=3)
    caught = 0
    for msg in made:
        view = MessageView.from_parsed(parse_rfc822(msg.raw))
        if analyse(view, ctx).score >= CAUTION_THRESHOLD:
            caught += 1
    assert caught / len(made) >= 0.7, f"only {caught}/{len(made)} caught"


# --------------------------------------------------------------- metrics

def test_metrics_arithmetic():
    m = harness.Metrics(tp=8, fp=2, tn=90, fn=4)
    assert abs(m.precision - 0.8) < 1e-9
    assert abs(m.recall - 8 / 12) < 1e-9
    assert abs(m.false_positive_rate - 2 / 92) < 1e-9
    assert 0 < m.f1 < 1
    assert harness.Metrics().precision == 0.0  # no division by zero


def test_evaluation_separates_attacks_from_benign():
    ctx = _ctx()
    samples = []
    for src in _sources(6):
        raw = (f"From: {src.from_display} <{src.from_addr}>\r\nTo: {src.to_addr}\r\n"
               f"Subject: {src.subject}\r\n"
               f"Authentication-Results: mx.google.com; dmarc=pass (p=NONE) "
               f"header.from=company.com\r\n\r\n{src.body_text}").encode()
        samples.append(harness.Sample(
            view=MessageView.from_parsed(parse_rfc822(raw)), label="benign"))
    for msg in synth.generate(_sources(6), per_transform=2):
        samples.append(harness.Sample(
            view=MessageView.from_parsed(parse_rfc822(msg.raw)),
            label="attack", transform=msg.transform))

    result = harness.evaluate(samples, ctx)
    assert result["overall"]["recall"] >= 0.7
    assert result["mean_score"]["attack"] > result["mean_score"]["benign"]


def test_ablation_shows_layers_are_cumulative():
    ctx = _ctx()
    samples = [harness.Sample(
        view=MessageView.from_parsed(parse_rfc822(m.raw)),
        label="attack", transform=m.transform)
        for m in synth.generate(_sources(8), per_transform=3)]
    rows = harness.ablate(samples, ctx)
    assert [r["layers"] for r in rows] == ["0", "0-1", "0-2", "0-3"]
    assert rows[-1]["recall"] >= rows[0]["recall"], "adding layers lost recall"


def test_threshold_sweep_is_monotone_in_recall():
    ctx = _ctx()
    samples = [harness.Sample(
        view=MessageView.from_parsed(parse_rfc822(m.raw)),
        label="attack", transform=m.transform)
        for m in synth.generate(_sources(6), per_transform=2)]
    rows = harness.sweep_thresholds(samples, ctx, steps=10)
    recalls = [r["recall"] for r in rows]
    assert recalls == sorted(recalls, reverse=True), "recall must fall as the bar rises"


def test_report_states_its_caveats():
    """Numbers without their limitations are worse than no numbers."""
    assert len(harness.CAVEATS) >= 3
    joined = " ".join(harness.CAVEATS).lower()
    assert "spam filter" in joined and "synthetic" in joined


# -------------------------------------------------------------- security

def test_status_reports_honestly_and_warns():
    st = security.status()
    assert set(st) >= {"keychain_available", "sqlcipher_available",
                       "database_encrypted", "warnings"}
    # Whenever protection is missing, the user must be told in plain words.
    if not st["database_encrypted"]:
        assert st["warnings"], "unprotected store produced no warning"
        assert any("UNENCRYPTED" in w or "Keychain" in w for w in st["warnings"])


def test_token_store_falls_back_to_a_private_file():
    tmp = Path(tempfile.mkdtemp())
    store = security.TokenStore(tmp / "token.json")
    backend = store.write('{"refresh_token": "secret"}')
    assert backend in ("keychain", "file")
    assert store.read() == '{"refresh_token": "secret"}'
    if backend == "file":
        assert (tmp / "token.json").exists()
    store.delete()
    assert store.read() is None


def test_encryption_request_fails_loudly_when_unavailable():
    """Silently handing back a plaintext database to a caller that asked for
    encryption is the one outcome worse than no encryption."""
    tmp = Path(tempfile.mkdtemp())
    if security.encryption_available() and security.keychain_available():
        return  # would actually succeed here
    try:
        Store(tmp / "enc.db", encrypt=True)
    except RuntimeError as exc:
        assert "encryption requested" in str(exc)
    else:
        raise AssertionError("Store(encrypt=True) silently opened in the clear")


def test_store_reports_whether_it_is_encrypted():
    tmp = Path(tempfile.mkdtemp())
    store = Store(tmp / "t.db")
    assert isinstance(store.encrypted, bool)
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
