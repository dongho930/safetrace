import httpx
import pytest

from safetrace.agent.extract import extract
from safetrace.ingest.kisa import load_api_json, load_csv
from safetrace.reputation.safebrowsing import SafeBrowsingClient
from safetrace.schemas import Relation, ReputationResult

# ─────────────── DOM 추출 ───────────────


def test_extract_forms_links_and_text():
    html = """<html lang="ko"><head><title>T</title><meta http-equiv="refresh" content="3; url=/next">
    <script src="https://cdn.x.com/a.js"></script><style>.x{}</style></head><body>
    <p>보이는 문구</p><script>var hidden = "숨은 스크립트 문구";</script>
    <form action="https://other.example/post" method="POST">
      <input type="text" name="user"><input type="password" name="pw"><input type="hidden" name="t">
      <input name="card_number" autocomplete="cc-number"><input type="tel" name="phone">
    </form>
    <input type="password" id="orphan">
    <a href="/rel">상대 링크</a><a href="javascript:void(0)">js</a><iframe src="https://ads.example/f"></iframe>
    </body></html>"""
    s, forms, links, meta = extract(html, "http://site.example/dir/page")
    assert s.title == "T" and s.lang == "ko"
    assert "보이는 문구" in s.text_excerpt and "숨은" not in s.text_excerpt
    assert s.script_count == 2 and s.iframe_count == 1
    f = forms[0]
    assert f.method == "post" and f.has_password and f.has_card_like and f.has_phone and f.external_action
    assert "hidden" not in f.input_types
    assert forms[1].action == "(no form)" and forms[1].has_password
    urls = {(link.url, link.relation) for link in links}
    assert ("http://site.example/rel", Relation.LINK) in urls
    assert ("http://site.example/next", Relation.REDIRECT) in urls
    assert ("https://cdn.x.com/a.js", Relation.SCRIPT) in urls
    assert ("https://other.example/post", Relation.FORM_ACTION) in urls
    assert not any(u.startswith("javascript") for u, _ in urls)
    assert meta == "http://site.example/next"


def test_extract_survives_broken_markup():
    s, forms, links, _ = extract("<html><body><form><input type=password <a href='x'>" * 50, "http://a.b/")
    assert s.element_count > 0


# ─────────────── KISA 적재 ───────────────

KISA_CSV = "날짜,홈페이지주소\n2025-08-01,naver-login.xyz/a\n2025-08-01,http://naver-login.xyz/a\n" \
           "2025-08-02,https://10.0.0.1/admin\n2025-08-03,\n2025-08-04,http://kb-star.top:8080/x\n"


@pytest.mark.parametrize("enc", ["utf-8", "utf-8-sig", "cp949"])
def test_kisa_csv(enc):
    res = load_csv(KISA_CSV.encode(enc))
    assert [r.normalized_url for r in res.records] == ["http://naver-login.xyz/a", "http://kb-star.top:8080/x"]
    assert res.duplicates == 1
    assert {code for _, code in res.rejected} == {"IP_NOT_PUBLIC", "EMPTY_URL"}
    assert res.records[0].detected_on.isoformat() == "2025-08-01"


def test_kisa_api_json():
    raw = '{"page":1,"perPage":2,"data":[{"날짜":"2025.08.01","홈페이지주소":"evil.xyz"},{"x":1}]}'.encode()
    res = load_api_json(raw)
    assert [r.normalized_url for r in res.records] == ["http://evil.xyz/"]


# ─────────────── Safe Browsing ───────────────


async def test_safebrowsing_listed_and_not_listed():
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.params["key"] == "k"
        return httpx.Response(200, json={"matches": [
            {"threatType": "SOCIAL_ENGINEERING", "threat": {"url": "http://bad.example/"}}]})

    c = SafeBrowsingClient("k", transport=httpx.MockTransport(handler), min_interval_s=0)
    reps = await c.lookup(["http://bad.example/", "http://unknown.example/"])
    assert reps[0].result == ReputationResult.LISTED and reps[0].threats == ["SOCIAL_ENGINEERING"]
    assert reps[1].result == ReputationResult.NOT_LISTED


async def test_safebrowsing_error_and_skip():
    c = SafeBrowsingClient("k", transport=httpx.MockTransport(lambda r: httpx.Response(429)), min_interval_s=0)
    assert (await c.lookup(["http://a/"]))[0].result == ReputationResult.ERROR
    assert (await SafeBrowsingClient("").lookup(["http://a/"]))[0].result == ReputationResult.SKIPPED
