"""HTML dissection.

Built on stdlib `html.parser` rather than BeautifulSoup, and that is a
deliberate trade. A lenient tree-builder silently *repairs* malformed markup -
which is precisely the markup phishing kits ship, because broken tags are how
they get a mail client to render one thing while a scanner reads another. A
streaming parser sees the document as sent.

Never raises: a parser that dies on hostile input is a detection blind spot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

from .urls import Link, parse_link

# Elements whose text is markup, not prose.
_NON_TEXT = {"script", "style", "head", "title", "meta", "link"}

_HIDDEN_DECLS = (
    "display:none", "visibility:hidden", "opacity:0",
    "font-size:0", "font-size:1px", "font-size:0px", "font-size:0pt",
    "max-height:0", "line-height:0", "mso-hide:all",
)
_INVISIBLE_COLOURS = {"#fff", "#ffffff", "white", "#fefefe", "transparent",
                      "rgba(0,0,0,0)", "#f8f8f8", "#fcfcfc"}

_ZERO_DIM_RE = re.compile(r"\b(?:width|height)\s*[:=]\s*['\"]?\s*([0-3])(?:px)?\b", re.I)
_FONT_SIZE_RE = re.compile(r"font-size\s*:\s*([\d.]+)\s*(px|pt|em|rem)?", re.I)
_COLOR_RE = re.compile(r"(?<!-)\bcolor\s*:\s*([^;]+)", re.I)


def _squash(style: str) -> str:
    return re.sub(r"\s+", "", (style or "")).lower()


def _is_hidden_style(style: str, attrs: dict[str, str]) -> bool:
    """Whether an element is rendered invisible.

    Covers the common family: display/visibility/opacity, zero font size, and
    white-on-white. Zero dimensions count only on containers, since a 1x1 image
    is a tracking pixel rather than concealed text.
    """
    squashed = _squash(style)
    if any(decl in squashed for decl in _HIDDEN_DECLS):
        return True

    m = _FONT_SIZE_RE.search(squashed)
    if m:
        try:
            size = float(m.group(1))
            unit = (m.group(2) or "px").lower()
            if (unit in ("px", "pt") and size <= 2) or (unit in ("em", "rem") and size <= 0.15):
                return True
        except ValueError:
            pass

    m = _COLOR_RE.search(squashed)
    if m and m.group(1).strip() in _INVISIBLE_COLOURS:
        return True

    if attrs.get("hidden") is not None:
        return True
    return False


@dataclass
class ImageRef:
    src: str
    is_data_uri: bool = False
    width: str | None = None
    height: str | None = None
    alt: str = ""

    @property
    def is_tracking_pixel(self) -> bool:
        def tiny(v: str | None) -> bool:
            return bool(v) and re.fullmatch(r"\s*[0-3]\s*(px)?\s*", v or "", re.I) is not None
        return tiny(self.width) and tiny(self.height)


@dataclass
class FormRef:
    action: str = ""
    method: str = ""
    has_password_input: bool = False
    input_names: list[str] = field(default_factory=list)


@dataclass
class HtmlAnalysis:
    links: list[Link] = field(default_factory=list)
    images: list[ImageRef] = field(default_factory=list)
    forms: list[FormRef] = field(default_factory=list)
    meta_refresh: str | None = None

    visible_text: str = ""
    hidden_text: str = ""
    script_count: int = 0
    parse_error: str | None = None

    @property
    def visible_chars(self) -> int:
        return len(self.visible_text.strip())

    @property
    def inline_images(self) -> list[ImageRef]:
        return [i for i in self.images if not i.is_tracking_pixel]


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out = HtmlAnalysis()
        self._skip_depth = 0
        self._hidden_stack: list[str] = []
        self._anchor: Link | None = None
        self._anchor_text: list[str] = []
        self._form: FormRef | None = None

    # -- helpers ---------------------------------------------------------

    @property
    def _hidden(self) -> bool:
        return bool(self._hidden_stack)

    def _push_hidden(self, tag: str, attrs: dict[str, str]) -> None:
        if _is_hidden_style(attrs.get("style", ""), attrs):
            self._hidden_stack.append(tag)

    # -- HTMLParser hooks -------------------------------------------------

    def handle_starttag(self, tag: str, attrs_list) -> None:
        tag = tag.lower()
        attrs = {k.lower(): (v or "") for k, v in attrs_list}

        if tag in _NON_TEXT:
            self._skip_depth += 1
            if tag == "script":
                self.out.script_count += 1
            if tag == "meta":
                self._skip_depth -= 1  # void element, never closed
                if attrs.get("http-equiv", "").lower() == "refresh":
                    content = attrs.get("content", "")
                    m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", content, re.I)
                    if m:
                        self.out.meta_refresh = m.group(1).strip()
            return

        self._push_hidden(tag, attrs)

        if tag == "a":
            self._anchor = parse_link(attrs.get("href", ""), source="html_anchor")
            self._anchor_text = []
        elif tag == "img":
            src = attrs.get("src", "")
            self.out.images.append(ImageRef(
                src=src[:200], is_data_uri=src.lower().startswith("data:"),
                width=attrs.get("width"), height=attrs.get("height"),
                alt=attrs.get("alt", "")[:120],
            ))
        elif tag == "form":
            self._form = FormRef(action=attrs.get("action", ""),
                                 method=attrs.get("method", "").lower())
            self.out.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            itype = attrs.get("type", "text").lower()
            name = attrs.get("name") or attrs.get("id") or itype
            self._form.input_names.append(name[:60])
            if itype == "password":
                self._form.has_password_input = True

    def handle_startendtag(self, tag, attrs_list) -> None:
        self.handle_starttag(tag, attrs_list)
        if tag.lower() not in ("meta", "img", "input", "br", "hr"):
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _NON_TEXT:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._hidden_stack and self._hidden_stack[-1] == tag:
            self._hidden_stack.pop()
        if tag == "a" and self._anchor is not None:
            self._anchor.anchor_text = " ".join("".join(self._anchor_text).split())[:300]
            self.out.links.append(self._anchor)
            self._anchor = None
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._anchor is not None:
            self._anchor_text.append(data)
        if self._hidden:
            self.out.hidden_text += data
        else:
            self.out.visible_text += data


def analyse_html(html: str) -> HtmlAnalysis:
    """Parse an HTML body. Always returns a result; failures are recorded."""
    parser = _Collector()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception as exc:
        parser.out.parse_error = f"{type(exc).__name__}: {exc}"

    out = parser.out
    if parser._anchor is not None:      # unclosed <a> at end of document
        parser._anchor.anchor_text = " ".join("".join(parser._anchor_text).split())[:300]
        out.links.append(parser._anchor)
    out.visible_text = " ".join(out.visible_text.split())
    out.hidden_text = " ".join(out.hidden_text.split())
    return out
