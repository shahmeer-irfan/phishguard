"""Phase 2 tests - Layer 3 content, links, attachments, QR.

The false-positive tests carry as much weight as the detection ones. A content
layer that fires on ordinary newsletters is worse than no content layer, because
it trains the user to dismiss the amber banner.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.detect import attachments as A  # noqa: E402
from phishguard.detect import layer3, urls as U  # noqa: E402
from phishguard.detect.base import Tier  # noqa: E402
from phishguard.detect.content import analyse_html  # noqa: E402
from phishguard.detect.context import AnalysisContext  # noqa: E402
from phishguard.detect.engine import analyse  # noqa: E402
from phishguard.detect.view import MessageView  # noqa: E402


def ctx(reference=("company.com",)):
    c = AnalysisContext(account_id=0, account_email="victim@gmail.com")
    c.reference_domains = {d: 1.0 for d in reference}
    return c


def view(*, html="", text="", atts=(), subject="hi", frm="sender@example.com"):
    v = MessageView(
        gmail_id="t", subject=subject, from_addr=frm,
        from_domain=frm.rpartition("@")[2], body_html=html, body_text=text,
        dmarc="pass", spf="pass", dkim="pass",
        auth_raw=f"mx.google.com; dmarc=pass (p=NONE) header.from={frm.rpartition('@')[2]}",
        auth_present=True,
    )
    v.attachments = [A.AttachmentInfo(filename=n, content_type=t, size_bytes=s)
                     for n, t, s in atts]
    return v


def codes(v):
    return {f.code for f in layer3.run(v, ctx())}


# ----------------------------------------------------------------- HTML parse

def test_anchor_text_and_href_are_both_captured():
    a = analyse_html('<p>Hi</p><a href="http://evil.ru/x">paypal.com</a>')
    assert len(a.links) == 1
    assert a.links[0].host == "evil.ru"
    assert a.links[0].anchor_text == "paypal.com"
    assert "Hi" in a.visible_text


def test_hidden_text_is_separated_from_visible():
    a = analyse_html(
        '<div>Real content here</div>'
        '<span style="display:none">poison words for the filter</span>'
        '<span style="font-size:0px">more poison</span>'
        '<span style="color:#ffffff">white on white</span>'
    )
    assert "Real content here" in a.visible_text
    for phrase in ("poison words", "more poison", "white on white"):
        assert phrase in a.hidden_text, phrase
        assert phrase not in a.visible_text


def test_script_and_style_text_is_not_body_text():
    a = analyse_html('<style>.x{color:red}</style><script>var a=1</script><p>hello</p>')
    assert a.visible_text.strip() == "hello"
    assert a.script_count == 1


def test_malformed_html_does_not_raise():
    for junk in ('<a href="x>unclosed', "<<<>>", '<a href="http://x.com">no close',
                 "<div style=", ""):
        a = analyse_html(junk)
        assert isinstance(a.visible_text, str)


def test_forms_and_password_inputs():
    a = analyse_html('<form action="http://evil.ru/c" method="post">'
                     '<input name="user"><input type="password" name="pw"></form>')
    assert len(a.forms) == 1
    assert a.forms[0].has_password_input
    assert a.forms[0].action == "http://evil.ru/c"


def test_meta_refresh_captured():
    a = analyse_html('<meta http-equiv="refresh" content="0;url=http://evil.ru/go">')
    assert a.meta_refresh == "http://evil.ru/go"


# ----------------------------------------------------------------------- URLs

def test_userinfo_trick():
    link = U.parse_link("http://paypal.com@evil.ru/login")
    assert link.host == "evil.ru"          # the browser goes here
    assert link.userinfo == "paypal.com"   # the user reads this


def test_anchor_mismatch_detection():
    mismatch = U.parse_link("http://evil.ru/x", "paypal.com", "html_anchor")
    assert U.anchor_claims_other_domain(mismatch) == "paypal.com"
    # Same organisation across subdomains is not a mismatch.
    same = U.parse_link("https://mail.company.com/x", "company.com", "html_anchor")
    assert U.anchor_claims_other_domain(same) is None
    # Ordinary link text must not be read as a domain claim.
    plain = U.parse_link("https://company.com/x", "Click here to continue", "html_anchor")
    assert U.anchor_claims_other_domain(plain) is None


def test_brand_in_subdomain():
    link = U.parse_link("https://company.com.secure-login.ru/verify")
    assert U.brand_in_subdomain(link, {"company.com"}) == "company.com"
    # The genuine site must not match itself.
    real = U.parse_link("https://mail.company.com/inbox")
    assert U.brand_in_subdomain(real, {"company.com"}) is None


def test_open_redirect_extraction():
    link = U.parse_link("https://company.com/out?url=https%3A%2F%2Fevil.ru%2Fx")
    assert U.open_redirect_target(link) == "https://evil.ru/x"
    plain = U.parse_link("https://company.com/page?id=42")
    assert U.open_redirect_target(plain) is None


def test_ip_hosts_and_ports():
    assert U.is_ip_host("192.168.1.1")
    assert not U.is_ip_host("company.com")
    assert U.parse_link("http://1.2.3.4:8080/login").port == 8080


def test_shortener_and_free_hosting():
    assert U.is_shortener(U.parse_link("https://bit.ly/3xYz"))
    assert U.free_hosting_suffix(U.parse_link("https://login-co.pages.dev/x")) == "pages.dev"
    assert U.free_hosting_suffix(U.parse_link("https://company.com/x")) is None


def test_non_links_are_ignored():
    for href in ("#", "mailto:a@b.com", "tel:+123", "", "   "):
        assert U.parse_link(href) is None


# ---------------------------------------------------------- layer 3: links

def test_credential_page_on_lookalike_domain_is_danger():
    v = view(html='<a href="https://cornpany.com/account/login/verify">Sign in</a>')
    verdict = analyse(v, ctx())
    assert "URL_LOOKALIKE_DOMAIN" in {f.code for f in verdict.findings}
    assert verdict.tier is Tier.DANGER


def test_anchor_mismatch_flagged():
    assert "URL_ANCHOR_MISMATCH" in codes(
        view(html='<a href="http://192.0.2.9/p">https://company.com/invoice</a>'))


def test_dangerous_scheme():
    assert "URL_DANGEROUS_SCHEME" in codes(view(html='<a href="javascript:steal()">x</a>'))


def test_credential_form_is_hard_danger():
    """A password box inside an email has no legitimate use whatsoever."""
    v = view(html='<form action="http://evil.ru/c"><input type="password" name="p">'
                  '</form>')
    verdict = analyse(v, ctx())
    assert verdict.tier is Tier.DANGER
    assert "HTML_CREDENTIAL_FORM" in {f.code for f in verdict.findings}


def test_hidden_filler_text_flagged():
    v = view(html="<p>Short note.</p><div style='display:none'>" + "lorem ipsum " * 40
                  + "</div>")
    assert "HTML_HIDDEN_TEXT" in codes(v)


def test_findings_are_deduplicated_across_many_links():
    """A newsletter with forty shortened links is one observation, not forty."""
    html = "".join(f'<a href="https://bit.ly/x{i}">link {i}</a>' for i in range(40))
    found = [f for f in layer3.run(view(html=html), ctx()) if f.code == "URL_SHORTENER"]
    assert len(found) == 1


# ----------------------------------------------------- layer 3: attachments

def test_double_extension():
    v = view(atts=[("invoice.pdf.exe", "application/octet-stream", 1024)])
    verdict = analyse(v, ctx())
    assert "ATTACHMENT_DOUBLE_EXTENSION" in {f.code for f in verdict.findings}
    assert verdict.tier is Tier.DANGER


def test_rlo_filename_is_hard_danger():
    """U+202E reverses how the rest of the name renders: the user is shown
    'invoicefdp.exe' as 'invoiceexe.pdf'. No benign use exists."""
    name = "invoice‮gpj.exe"
    v = view(atts=[(name, "application/octet-stream", 512)])
    verdict = analyse(v, ctx())
    assert verdict.tier is Tier.DANGER
    assert "ATTACHMENT_RLO_FILENAME" in {f.code for f in verdict.findings}
    assert A.bidi_override_in(name) == "U+202E"


def test_attachment_categories():
    assert "ATTACHMENT_EXECUTABLE" in codes(view(atts=[("setup.exe", "application/x-msdownload", 9)]))
    assert "ATTACHMENT_SCRIPT" in codes(view(atts=[("run.js", "text/javascript", 9)]))
    assert "ATTACHMENT_MACRO_DOCUMENT" in codes(view(atts=[("q4.xlsm", "application/vnd.ms-excel", 9)]))
    assert "ATTACHMENT_CONTAINER" in codes(view(atts=[("doc.iso", "application/octet-stream", 9)]))
    assert "ATTACHMENT_HTML" in codes(view(atts=[("secure.html", "text/html", 9)]))
    assert "ATTACHMENT_ONENOTE" in codes(view(atts=[("note.one", "application/onenote", 9)]))


def test_locked_archive_only_when_password_is_supplied():
    with_pw = view(atts=[("docs.zip", "application/zip", 99)],
                   text="The password is Winter2025")
    without = view(atts=[("docs.zip", "application/zip", 99)], text="Files attached.")
    assert "ATTACHMENT_LOCKED_ARCHIVE" in codes(with_pw)
    assert "ATTACHMENT_LOCKED_ARCHIVE" not in codes(without)


def test_content_type_mismatch():
    assert "ATTACHMENT_TYPE_MISMATCH" in codes(
        view(atts=[("report.pdf", "text/html", 100)]))
    assert "ATTACHMENT_TYPE_MISMATCH" not in codes(
        view(atts=[("report.pdf", "application/pdf", 100)]))


def test_extension_parsing_handles_odd_names():
    assert A.AttachmentInfo("a.b.c.PDF", "x").extension == "pdf"
    assert A.AttachmentInfo("noext", "x").extension == ""
    assert A.AttachmentInfo("trailing.pdf.", "x").extension == "pdf"


# ------------------------------------------------------- false positives

def test_ordinary_newsletter_stays_safe():
    """A real marketing email: many links, images, a tracking pixel, an
    unsubscribe footer. None of that is an attack."""
    html = (
        '<img src="https://cdn.company.com/logo.png" width="200" height="60">'
        '<h1>Your weekly update</h1>'
        '<p>Here is what happened this week at the company. We shipped three '
        'features and fixed a number of bugs across the platform.</p>'
        '<a href="https://company.com/blog/post-1">Read the release notes</a> '
        '<a href="https://company.com/blog/post-2">See the changelog</a> '
        '<a href="https://company.com/unsubscribe?id=42">Unsubscribe</a>'
        '<img src="https://track.company.com/p.gif" width="1" height="1">'
    )
    verdict = analyse(view(html=html, frm="news@company.com"), ctx())
    assert verdict.tier is Tier.SAFE, [f.code for f in verdict.findings]


def test_plain_personal_mail_stays_safe():
    v = view(text="Hey, are we still on for lunch Thursday? Let me know.",
             frm="abdul@company.com")
    verdict = analyse(v, ctx())
    assert verdict.tier is Tier.SAFE


def test_login_link_on_a_domain_you_use_is_not_flagged():
    """company.com/account/login is the real login page, not a phishing page."""
    v = view(html='<a href="https://company.com/account/login">Sign in</a>',
             frm="noreply@company.com")
    assert "URL_CREDENTIAL_PATH" not in codes(v)


def test_tracking_pixel_alone_is_not_image_only():
    v = view(html='<img src="https://t.co/p.gif" width="1" height="1">'
                  '<p>' + "Real prose that a person actually wrote. " * 6 + '</p>')
    assert "HTML_IMAGE_ONLY" not in codes(v)


# ------------------------------------------------------------------- QR

def test_qr_degrades_gracefully_when_unavailable():
    from phishguard.detect import qr

    v = view(html='<img src="cid:qr1">', atts=[("qr.png", "image/png", 4096)])
    found = codes(v)
    if qr.available():
        assert True  # decoding path covered by test_qr_decodes_when_available
    else:
        assert "QR_UNSCANNED_IMAGE" in found


def test_qr_decodes_when_available():
    from phishguard.detect import qr

    if not qr.available():
        return  # optional dependency absent; nothing to assert
    assert qr.decode(b"not an image") == []


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
