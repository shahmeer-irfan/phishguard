"""Offline tests: parser and store, no Gmail credentials required.

Run with pytest, or directly:  python tests/test_offline.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.db.store import Store  # noqa: E402
from phishguard.parse import headers as H  # noqa: E402
from phishguard.parse.message import parse_rfc822  # noqa: E402

# A synthetic BEC attempt carrying every Layer-0/1 tell at once: display-name
# spoof, lookalike domain, divergent Reply-To and Return-Path, failed DMARC,
# and a double-extension attachment.
SPOOFED = b"""\
Delivered-To: victim@gmail.com
Received: by 2002:a05:6214:1a8f with SMTP id abc123;
        Tue, 09 Sep 2025 03:14:21 -0700 (PDT)
Received: from mail.cheap-vps.ru (mail.cheap-vps.ru. [45.83.12.9])
        by mx.google.com with ESMTPS id d9si123456
        for <victim@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384);
        Tue, 09 Sep 2025 03:14:20 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=fail header.i=@company-payroll.com header.s=sel1 header.b=QbXz9;
       spf=softfail (google.com: domain of transitioning bounce@cheap-vps.ru does not
       designate 45.83.12.9 as permitted sender) smtp.mailfrom=bounce@cheap-vps.ru;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=company-payroll.com
Return-Path: <bounce@cheap-vps.ru>
Message-ID: <20250909101420.9f3a1@mail.cheap-vps.ru>
Date: Tue, 9 Sep 2025 15:14:20 +0500
From: "Abdul Rehman" <abdul.rehman@company-payroll.com>
Reply-To: abdulrehman.finance@gmail.com
To: victim@gmail.com
Subject: =?utf-8?B?VVJHRU5UOiB1cGRhdGVkIGJhbmsgZGV0YWlscw==?=
X-Mailer: PHPMailer 6.8.0
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUTER"

--OUTER
Content-Type: multipart/alternative; boundary="INNER"

--INNER
Content-Type: text/plain; charset="utf-8"

Hi, please update our payroll account before 3pm today. New IBAN attached.

--INNER
Content-Type: text/html; charset="utf-8"

<html><body><p>Please <a href="http://bit.ly/x9k2">verify here</a></p>
<span style="font-size:0">ignore this filler text</span></body></html>

--INNER--
--OUTER
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA

--OUTER--
"""

LEGIT = b"""\
Received: from mail-wr1-f52.google.com (mail-wr1-f52.google.com. [209.85.221.52])
        by mx.google.com with ESMTPS id x1si999
        for <victim@gmail.com>;
        Mon, 08 Sep 2025 01:02:03 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@company.com header.s=google header.b=AbCd;
       spf=pass (google.com: domain of abdul@company.com designates 209.85.221.52
       as permitted sender) smtp.mailfrom=abdul@company.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=company.com
Return-Path: <abdul@company.com>
Message-ID: <CAF+abc123def@mail.gmail.com>
Date: Mon, 8 Sep 2025 13:02:01 +0500
From: Abdul Rehman <abdul@company.com>
To: victim@gmail.com
Subject: lunch thursday?
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Works for me. See you at 1.
"""


def test_spoofed_headers():
    m = parse_rfc822(SPOOFED)
    assert m.parse_error is None, m.parse_error

    assert m.from_display == "Abdul Rehman"
    assert m.from_addr == "abdul.rehman@company-payroll.com"
    assert m.from_domain == "company-payroll.com"
    # The two tells that matter most and that a human skimming Gmail never sees.
    assert m.reply_to_addr == "abdulrehman.finance@gmail.com"
    assert m.return_path_addr == "bounce@cheap-vps.ru"

    assert m.subject == "URGENT: updated bank details"  # RFC 2047 B-encoded
    assert m.date_tz_offset == 300  # +05:00, kept as a fingerprint feature
    assert m.x_mailer == "PHPMailer 6.8.0"


def test_spoofed_auth_results():
    a = parse_rfc822(SPOOFED).auth
    assert a.authserv_id == "mx.google.com"
    assert a.spf == "softfail"
    assert a.spf_domain == "cheap-vps.ru"
    assert a.dkim == "fail"
    assert a.dkim_domain == "company-payroll.com"
    assert a.dmarc == "fail"
    assert a.dmarc_domain == "company-payroll.com"
    assert a.arc_present is False


def test_received_chain():
    hops = parse_rfc822(SPOOFED).hops
    assert len(hops) == 2
    # Index 0 is the hop closest to us; the last is the claimed origin.
    origin = hops[-1]
    assert origin.from_host == "mail.cheap-vps.ru"
    assert origin.from_ip == "45.83.12.9"
    assert origin.by_host == "mx.google.com"
    assert origin.with_proto == "ESMTPS"
    assert origin.hop_time is not None
    # The "by" clause IP must not be mistaken for the sender's.
    assert hops[0].from_ip != "45.83.12.9"


def test_mime_and_attachments():
    m = parse_rfc822(SPOOFED)
    assert m.mime_signature == (
        "multipart/mixed(multipart/alternative(text/plain,text/html),"
        "application/octet-stream)"
    )
    assert len(m.attachments) == 1
    att = m.attachments[0]
    assert att.filename == "invoice.pdf.exe"
    assert att.is_inline is False
    assert len(att.sha256) == 64

    assert "payroll account" in m.body_text
    # Hidden text is preserved rather than rendered away - it is evidence.
    assert "ignore this filler text" in m.body_html


def test_legit_message_differs():
    spoof, legit = parse_rfc822(SPOOFED), parse_rfc822(LEGIT)
    assert legit.auth.dmarc == "pass"
    assert legit.reply_to_addr == ""
    # Same claimed human, different technical fingerprint: this contrast is the
    # entire basis of Layer 2.
    assert spoof.from_display == legit.from_display
    assert spoof.header_order_hash != legit.header_order_hash
    assert spoof.x_mailer != legit.x_mailer


def test_address_canonicalisation():
    # Gmail folds dots and +tags; other providers do not fold dots.
    assert H.canonical_address("A.B+news@Gmail.com") == "ab@gmail.com"
    assert H.canonical_address("a.b+news@company.com") == "a.b@company.com"
    assert H.canonical_address("Abdul <ABDUL@Company.COM>") == "abdul@company.com"
    assert H.split_address("x@Example.Com.") == ("x", "example.com")


def test_malformed_input_does_not_raise():
    for junk in (b"", b"not an email at all", b"From: <<<broken\r\n\r\nbody",
                 b"Subject: =?bogus-charset?Q?x?=\r\n\r\nhi"):
        m = parse_rfc822(junk)
        assert isinstance(m.from_addr, str)  # partial result, never an exception


def test_store_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "t.db")
        account = store.get_or_create_account("victim@gmail.com")

        for gid, raw, labels in (("g1", SPOOFED, ["INBOX"]), ("g2", LEGIT, ["INBOX"])):
            meta = {"id": gid, "threadId": f"t{gid}", "historyId": "100",
                    "labelIds": labels, "snippet": "...", "sizeEstimate": len(raw),
                    "received_at": "2025-09-09T10:14:20+00:00"}
            store.upsert_message(account, meta, parse_rfc822(raw), raw)

        # Idempotent: re-ingesting must not duplicate.
        meta = {"id": "g1", "labelIds": ["INBOX", "IMPORTANT"], "historyId": "101"}
        store.upsert_message(account, meta, parse_rfc822(SPOOFED), SPOOFED)

        assert store.stats(account)["messages"] == 2
        row = store.conn.execute(
            "SELECT labels_json FROM messages WHERE gmail_id = 'g1'").fetchone()
        assert "IMPORTANT" in json.loads(row["labels_json"])  # labels refreshed

        assert store.raw_message(1) == SPOOFED  # raw survives for re-analysis

        hops = store.conn.execute(
            "SELECT COUNT(*) c FROM received_hops").fetchone()["c"]
        assert hops == 3
        atts = store.conn.execute("SELECT COUNT(*) c FROM attachments").fetchone()["c"]
        assert atts == 1

        # Two different addresses claiming the same display name is precisely
        # the impersonation case the product exists to catch.
        contacts = {c["canonical_email"] for c in store.top_contacts(account)}
        assert contacts == {"abdul.rehman@company-payroll.com", "abdul@company.com"}

        breakdown = {b["dmarc"]: b["n"] for b in store.auth_breakdown(account)}
        assert breakdown == {"fail": 1, "pass": 1}
        store.close()


def test_history_watermark_only_advances():
    with tempfile.TemporaryDirectory() as tmp:
        store = Store(Path(tmp) / "t.db")
        account = store.get_or_create_account("a@b.com")
        store.advance_history_id(account, "500")
        store.advance_history_id(account, "400")  # stale page, must be ignored
        assert store.sync_state(account)["history_id"] == "500"
        store.advance_history_id(account, "900")
        assert store.sync_state(account)["history_id"] == "900"
        store.close()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
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
