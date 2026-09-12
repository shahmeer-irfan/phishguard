"""Seed a demo mailbox that exercises every detection layer.

Not a test - a fixture for looking at. Each message is chosen to light up one
layer so the UI shows the whole range: genuine mail, a forged envelope, an
impersonation, a compromised account, and three payload attacks.

    PHISHGUARD_HOME=./demo3 python tools/seed_demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard import config as C
from phishguard.db.store import Store
from phishguard.parse.message import parse_rfc822

USER = "shahmeer@company.com"


def auth(domain: str, result: str = "pass", policy: str = "NONE") -> str:
    return (f"Authentication-Results: mx.google.com; "
            f"dkim={result} header.i=@{domain} header.s=g; "
            f"spf={result} smtp.mailfrom=x@{domain}; "
            f"dmarc={result} (p={policy} sp={policy} dis=NONE) header.from={domain}")


def put(store, acct, gid, *, frm, disp, subj, body="", html_body=None, extra="",
        auth_hdr=None, mailer="Apple Mail (2.3731.700.6)", msgid=None,
        attach=None, labels=("INBOX",), tz="+0500"):
    domain = frm.rpartition("@")[2]
    head = [
        f"From: {disp} <{frm}>", f"To: {USER}", f"Subject: {subj}",
        f"Message-ID: <{msgid or gid + 'XKCD-4471'}@mail.{domain}>",
        f"X-Mailer: {mailer}", auth_hdr or auth(domain),
        f"Date: Mon, 8 Sep 2025 13:02:01 {tz}", "MIME-Version: 1.0",
    ]
    if extra:
        head.append(extra.rstrip("\r\n"))

    if attach:
        name, payload = attach
        head.append('Content-Type: multipart/mixed; boundary="B"')
        rest = ("\r\n--B\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n"
                "--B\r\nContent-Type: application/octet-stream; name=\"" + name + "\"\r\n"
                "Content-Disposition: attachment; filename=\"" + name + "\"\r\n"
                "Content-Transfer-Encoding: base64\r\n\r\n" + payload + "\r\n--B--\r\n")
    elif html_body:
        head.append('Content-Type: text/html; charset="utf-8"')
        rest = "\r\n" + html_body
    else:
        head.append('Content-Type: text/plain; charset="utf-8"')
        rest = "\r\n" + body

    raw = ("\r\n".join(head) + "\r\n" + rest).encode()
    store.upsert_message(acct, {"id": gid, "labelIds": list(labels),
                                "received_at": "2025-09-08T09:00:00+00:00"},
                         parse_rfc822(raw), raw)


# Fourteen genuine notes, enough to build a Layer-2 writing baseline.
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
]

FORMAL_TAKEOVER = (
    "Dear Sir/Madam, I am writing in connection with an outstanding matter requiring "
    "your immediate consideration. The remittance particulars previously furnished are "
    "no longer operative and we should be most grateful if you would arrange for "
    "settlement to be directed to the revised account specified hereunder, treating "
    "this correspondence as strictly confidential pending the conclusion of the review."
)


def main() -> int:
    store = Store(C.load().db_path)
    acct = store.get_or_create_account(USER)

    for i, body in enumerate(CASUAL):
        put(store, acct, f"ok{i}", frm="abdul@company.com", disp="Abdul Rehman",
            subj="re: project", body=body)

    store.upsert_message(acct, {"id": "sent1", "labelIds": ["SENT"]}, parse_rfc822(
        ("From: " + USER + "\r\nTo: Abdul Rehman <abdul@company.com>\r\n"
         "Subject: re: project\r\n\r\nsounds good, thanks").encode()))

    # --- genuine, must stay clean -------------------------------------
    put(store, acct, "legit1", frm="noreply@github.com", disp="GitHub",
        subj="[phishguard] Pull request #12 merged",
        html_body='<p>Your pull request was merged into main.</p>'
                  '<a href="https://github.com/x/y/pull/12">View the pull request</a>')
    put(store, acct, "legit2", frm="news@company.com", disp="Company News",
        subj="Weekly update",
        html_body='<img src="https://cdn.company.com/logo.png" width="200" height="60">'
                  '<h1>Weekly update</h1><p>We shipped three features this week and '
                  'fixed a number of bugs across the platform. Read more below, and '
                  'let us know what you think.</p>'
                  '<a href="https://company.com/blog/1">Release notes</a> '
                  '<a href="https://company.com/unsubscribe?id=9">Unsubscribe</a>'
                  '<img src="https://track.company.com/p.gif" width="1" height="1">')
    put(store, acct, "legit3", frm="receipts@stripe.com", disp="Stripe",
        subj="Your receipt from Company Ltd",
        body="Thanks for your payment. Your receipt is available in the dashboard.")

    # --- Layer 0: forged envelope, domain publishes p=reject -----------
    put(store, acct, "a_forge", frm="abdul@company.com", disp="Abdul Rehman",
        subj="URGENT: updated bank details",
        body="Please update our payroll account before 3pm today.",
        auth_hdr=auth("company.com", "fail", "REJECT"),
        extra="Return-Path: <bounce@cheap-vps.ru>")

    # --- Layer 0: genuine sender, replies diverted ---------------------
    put(store, acct, "a_reply", frm="ceo@company.com", disp="Tariq Mahmood",
        subj="Quick favour",
        body="Are you at your desk? I need a transfer processed before the board call.",
        extra="Reply-To: tariq.mahmood.finance@gmail.com")

    # --- Layer 1: known name, personal mailbox -------------------------
    put(store, acct, "a_free", frm="abdulrehman.finance@gmail.com", disp="Abdul Rehman",
        subj="Payment - new account details",
        body="Hi, our bank flagged the old account so please use the updated details "
             "for this week's invoice. IBAN GB29NWBK60161331926819.",
        auth_hdr=auth("gmail.com"))

    # --- Layer 1: cousin domain ----------------------------------------
    put(store, acct, "a_cousin", frm="hr@company-payroll.com", disp="Payroll Team",
        subj="Salary revision 2025",
        html_body='<p>Please review your revised salary before Friday.</p>'
                  '<a href="https://company-payroll.com/account/login/verify">'
                  'Review now</a>')

    # --- Layer 2: compromised account, mid-thread ----------------------
    put(store, acct, "a_takeover", frm="abdul@company.com", disp="Abdul Rehman",
        subj="re: project", body=FORMAL_TAKEOVER,
        mailer="PHPMailer 6.8.0", msgid="1757412345.0@webmail-vps", tz="-0700",
        extra="In-Reply-To: <ok3XKCD-4471@mail.company.com>")

    # --- Layer 3: userinfo trick pointing at a raw IP ------------------
    put(store, acct, "a_url", frm="billing@invoices-co.com", disp="Accounts",
        subj="Invoice overdue",
        html_body='<p>Your account is overdue.</p><a href='
                  '"http://company.com@45.83.12.9/secure/login/verify">'
                  'https://company.com/billing</a>')

    # --- Layer 3: credential form inside the email ---------------------
    put(store, acct, "a_form", frm="no-reply@notices.net", disp="IT Helpdesk",
        subj="Mailbox storage full",
        html_body='<p>Sign in to keep your mailbox active.</p>'
                  '<form action="https://owa-login.pages.dev/c" method="post">'
                  '<input name="email"><input type="password" name="pw">'
                  '<input type="submit"></form>')

    # --- Layer 3: double-extension payload -----------------------------
    put(store, acct, "a_attach", frm="supplier@globaltrade.co", disp="Global Trade",
        subj="Invoice attached",
        body="Please see the attached invoice for this month.",
        attach=("Invoice_8841.pdf.exe", "TVqQAAMAAAAEAAAA"))

    total = store.stats(acct)["messages"]
    store.close()
    print(f"seeded {total} messages for {USER}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
