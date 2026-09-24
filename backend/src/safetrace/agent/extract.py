"""렌더링 후 DOM 직렬화 결과에서 구조 특징을 뽑는다.

페이지 main world 에서 JS 로 추출하면 공격자가 프로토타입을 덮어써 추출값을 조작할 수 있으므로,
직렬화된 HTML 을 Python 표준 파서로 해석한다. 결과는 모두 불신 데이터이며 길이 상한을 적용한다.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from safetrace.schemas import DomSummary, FormInfo, ObservedLink, Relation

MAX_LINKS = 300
MAX_TEXT = 4000
_SKIP_TEXT_TAGS = {"script", "style", "noscript", "template", "svg", "head"}
_CARD_HINT = re.compile(r"card|cc-?num|cvc|cvv|카드|expir|유효기간", re.I)
_PHONE_HINT = re.compile(r"phone|mobile|tel|휴대|전화", re.I)
_IDNUM_HINT = re.compile(r"jumin|ssn|rrn|resident|주민|생년월일|birth", re.I)
_PW_HINT = re.compile(r"passw|pwd|비밀번호|pin", re.I)
_WS = re.compile(r"\s+")


def _clip(s: str, n: int) -> str:
    return s[:n]


class _Parser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self.lang = ""
        self.text_parts: list[str] = []
        self.text_len = 0
        self.element_count = 0
        self.script_count = 0
        self.iframe_count = 0
        self.links: list[ObservedLink] = []
        self.forms: list[FormInfo] = []
        self.orphan_inputs: FormInfo = FormInfo()
        self._skip_depth = 0
        self._in_title = False
        self._in_a: ObservedLink | None = None
        self._a_text: list[str] = []
        self._form: FormInfo | None = None
        self.meta_refresh: str = ""

    def _abs(self, href: str) -> str:
        try:
            return urljoin(self.base_url, href.strip())
        except ValueError:
            return ""

    def _add_link(self, url: str, relation: Relation, text: str = "") -> None:
        if len(self.links) >= MAX_LINKS or not url:
            return
        if urlsplit(url).scheme not in ("http", "https"):
            return
        self.links.append(ObservedLink(url=_clip(url, 2048), relation=relation, text=_clip(text, 200)))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        self.element_count += 1
        if tag in _SKIP_TEXT_TAGS:
            self._skip_depth += 1
        if tag == "html" and a.get("lang"):
            self.lang = _clip(a["lang"], 16)
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\"]+)", a.get("content", ""), re.I)
            if m:
                self.meta_refresh = self._abs(m.group(1))
                self._add_link(self.meta_refresh, Relation.REDIRECT, "meta refresh")
        elif tag == "a" and a.get("href"):
            self._in_a = ObservedLink(url=_clip(self._abs(a["href"]), 2048) or "about:blank",
                                      relation=Relation.LINK)
            self._a_text = []
        elif tag == "script":
            self.script_count += 1
            if a.get("src"):
                self._add_link(self._abs(a["src"]), Relation.SCRIPT)
        elif tag == "iframe":
            self.iframe_count += 1
            if a.get("src"):
                self._add_link(self._abs(a["src"]), Relation.RESOURCE)
        elif tag in ("img", "link") and (a.get("src") or a.get("href")):
            if tag == "link" and a.get("rel", "").lower() not in ("stylesheet", "preload", "icon"):
                return
            self._add_link(self._abs(a.get("src") or a.get("href", "")), Relation.RESOURCE)
        elif tag == "form":
            action = self._abs(a.get("action", "")) if a.get("action") else self.base_url
            self._form = FormInfo(action=_clip(action, 2048), method=_clip(a.get("method", "get").lower(), 10))
            self._add_link(action, Relation.FORM_ACTION)
        elif tag in ("input", "select", "textarea"):
            self._on_input(tag, a)

    def _on_input(self, tag: str, a: dict[str, str]) -> None:
        itype = (a.get("type") or ("text" if tag == "input" else tag)).lower()[:32]
        if itype in ("hidden", "submit", "button", "image", "reset"):
            return
        target = self._form if self._form is not None else self.orphan_inputs
        hint = " ".join((a.get("name", ""), a.get("id", ""), a.get("placeholder", ""),
                         a.get("autocomplete", ""), a.get("aria-label", "")))
        if len(target.input_types) < 50:
            target.input_types.append(itype)
            name = a.get("name") or a.get("id") or ""
            if name:
                target.input_names.append(_clip(name, 64))
        if itype == "password" or _PW_HINT.search(hint):
            target.has_password = True
        if _CARD_HINT.search(hint) or "cc-" in a.get("autocomplete", ""):
            target.has_card_like = True
        if itype == "tel" or _PHONE_HINT.search(hint):
            target.has_phone = True
        if _IDNUM_HINT.search(hint):
            target.has_id_number_like = True

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TEXT_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag == "title":
            self._in_title = False
        elif tag == "a" and self._in_a is not None:
            text = _WS.sub(" ", "".join(self._a_text)).strip()
            self._add_link(self._in_a.url, Relation.LINK, text)
            self._in_a = None
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 256:
            self.title = _clip((self.title + data).strip(), 256)
            return
        if self._skip_depth:
            return
        if self._in_a is not None:
            self._a_text.append(data)
        if self.text_len < MAX_TEXT:
            chunk = _WS.sub(" ", data).strip()
            if chunk:
                self.text_parts.append(chunk)
                self.text_len += len(chunk) + 1


def extract(html: str, base_url: str) -> tuple[DomSummary, list[FormInfo], list[ObservedLink], str]:
    """(DOM 요약, 폼 목록, 관찰 링크, meta refresh 대상)"""
    p = _Parser(base_url)
    try:
        p.feed(html)
        p.close()
    except (AssertionError, ValueError):  # 손상된 마크업도 부분 결과는 유지
        pass
    if p._form is not None:
        p.forms.append(p._form)
    if p.orphan_inputs.input_types:
        p.orphan_inputs.action = "(no form)"
        p.forms.append(p.orphan_inputs)
    base_host = urlsplit(base_url).hostname or ""
    for f in p.forms:
        host = urlsplit(f.action).hostname if f.action.startswith("http") else None
        f.external_action = bool(host and host != base_host)
    summary = DomSummary(
        title=p.title,
        lang=p.lang,
        text_excerpt=_clip(" ".join(p.text_parts), MAX_TEXT),
        element_count=p.element_count,
        script_count=p.script_count,
        iframe_count=p.iframe_count,
        link_count=len(p.links),
        html_bytes=len(html.encode("utf-8", "ignore")),
    )
    return summary, p.forms, p.links, p.meta_refresh
