"""Attachment classification.

Filename-driven, because that is what the user sees and what the operating
system dispatches on. Content sniffing is a Phase 3 concern; the cheap checks
here catch the overwhelming majority and cost nothing.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Unicode bidirectional overrides. There is no legitimate reason for one of
# these to appear in an attachment filename: their only effect is to reverse
# how the extension renders, so "invoice<RLO>fdp.exe" is displayed to the user
# as "invoiceexe.pdf". Presence alone is proof of intent.
BIDI_OVERRIDES = {
    "‪", "‫", "‬", "‭", "‮",   # LRE RLE PDF LRO RLO
    "⁦", "⁧", "⁨", "⁩",             # isolates
    "‎", "‏",                                 # LRM RLM
}

EXECUTABLE = {
    "exe", "scr", "com", "pif", "msi", "msp", "cpl", "jar", "app", "dmg",
    "pkg", "deb", "rpm", "run", "bin", "gadget", "msix", "appx",
}
SCRIPT = {
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "psc1", "bat",
    "cmd", "sh", "hta", "reg", "scf", "inf", "url", "application", "msc",
    "settingcontent-ms", "library-ms", "chm", "vb", "vbscript", "ws",
}
# Containers exist to smuggle the above past scanners and past the
# mark-of-the-web that would otherwise warn the user on opening.
CONTAINER = {"iso", "img", "vhd", "vhdx", "cab", "ace", "arj", "lnk", "xz"}
ARCHIVE = {"zip", "rar", "7z", "tar", "gz", "bz2", "tgz", "zipx"}
MACRO_OFFICE = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlsb", "xlam", "ppam"}
LEGACY_OFFICE = {"doc", "xls", "ppt", "dot", "xlt", "pot", "rtf"}
WEB = {"html", "htm", "shtml", "xhtml", "mhtml", "mht", "svg"}
NOTE = {"one", "onepkg"}

# Extensions a sender plausibly means to send. Used for the double-extension
# check: "invoice.pdf.exe" is only interesting because ".pdf" looks intended.
DOCUMENT_LOOKING = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf",
    "jpg", "jpeg", "png", "gif", "zip", "odt", "ods", "eml", "msg", "xml", "json",
}

_EXPECTED_TYPES = {
    "pdf": {"application/pdf"},
    "zip": {"application/zip", "application/x-zip-compressed", "application/octet-stream"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "png": {"image/png"},
    "jpg": {"image/jpeg"},
    "jpeg": {"image/jpeg"},
    "gif": {"image/gif"},
    "html": {"text/html"},
    "htm": {"text/html"},
    "txt": {"text/plain"},
}

_PASSWORD_HINT_RE = re.compile(
    r"\b(?:pass(?:word|wd|code)?|pwd|p/w|unlock\s+code|decryption\s+key)\b\s*(?:is|:|=)?",
    re.I,
)


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int = 0
    is_inline: bool = False
    sha256: str = ""

    @property
    def clean_name(self) -> str:
        return "".join(c for c in self.filename if c not in BIDI_OVERRIDES)

    @property
    def extensions(self) -> list[str]:
        """All dotted suffixes, lowercased, left to right."""
        name = self.clean_name.strip().rstrip(". ")
        parts = [p for p in name.split(".")[1:] if p and len(p) <= 20]
        return [unicodedata.normalize("NFKC", p).lower() for p in parts]

    @property
    def extension(self) -> str:
        exts = self.extensions
        return exts[-1] if exts else ""


def bidi_override_in(filename: str) -> str | None:
    for ch in filename or "":
        if ch in BIDI_OVERRIDES:
            return f"U+{ord(ch):04X}"
    return None


def rendered_name(filename: str) -> str:
    """How a filename containing an RLO actually appears to the user."""
    if "‮" not in (filename or ""):
        return filename
    head, _, tail = filename.partition("‮")
    return head + tail[::-1]


def category(ext: str) -> str | None:
    if ext in EXECUTABLE:
        return "executable"
    if ext in SCRIPT:
        return "script"
    if ext in CONTAINER:
        return "container"
    if ext in MACRO_OFFICE:
        return "macro_office"
    if ext in WEB:
        return "web"
    if ext in ARCHIVE:
        return "archive"
    if ext in LEGACY_OFFICE:
        return "legacy_office"
    if ext in NOTE:
        return "onenote"
    return None


def double_extension(att: AttachmentInfo) -> tuple[str, str] | None:
    """(decoy, real) when a dangerous extension hides behind a harmless one."""
    exts = att.extensions
    if len(exts) < 2:
        return None
    real = exts[-1]
    decoy = exts[-2]
    if decoy in DOCUMENT_LOOKING and category(real) in ("executable", "script", "container"):
        return (decoy, real)
    return None


def type_mismatch(att: AttachmentInfo) -> tuple[str, str] | None:
    """Declared MIME type contradicting the extension."""
    ext = att.extension
    expected = _EXPECTED_TYPES.get(ext)
    if not expected:
        return None
    actual = (att.content_type or "").split(";")[0].strip().lower()
    if not actual or actual in expected:
        return None
    # A generic octet-stream label is lazy rather than deceptive.
    if actual == "application/octet-stream":
        return None
    return (ext, actual)


def mentions_password(body: str) -> bool:
    """Whether the body hands over an archive password.

    A password-protected archive cannot be scanned by any gateway, which is the
    entire reason attackers use one - and they must then supply the password in
    the message itself for the victim to open it.
    """
    return bool(_PASSWORD_HINT_RE.search(body or ""))
