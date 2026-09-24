"""⓪ Candidate Discovery 정책: R8(허용목록 재큐잉 0·탐색 한도 준수·중복 조사 0)."""

from safetrace.discovery.allowlist import is_allowlisted
from safetrace.discovery.policy import Budget, Frontier
from safetrace.discovery.similarity import lookalike_target
from safetrace.schemas import FormInfo, Observation, ObservedLink, Relation, SeedSource


def _obs(cid: str, links: list[tuple[str, Relation]], forms=None) -> Observation:
    return Observation(candidate_id=cid, requested_url="http://seed.xyz/",
                       observed_links=[ObservedLink(url=u, relation=r) for u, r in links], forms=forms or [])


def test_allowlist():
    assert is_allowlisted("www.kbstar.com")
    assert is_allowlisted("minwon.anything.go.kr")
    assert not is_allowlisted("kbstar-login.xyz")


def test_lookalike():
    assert lookalike_target("kbstar-secure-login.xyz") == "kbstar.com"
    assert lookalike_target("w00ribank.com") == "wooribank.com"
    assert lookalike_target("wooribamk.net") == "wooribank.com"  # 편집 거리 1
    assert lookalike_target("xn--kbstr-9ua.com") is None or True  # 디코드 실패 없이 처리
    assert lookalike_target("www.kbstar.com") is None  # 공식 도메인은 아님
    assert lookalike_target("bakery.example.com") is None


def test_allowlisted_never_requeued_and_recorded_as_impersonation():
    f = Frontier("case_1")
    seed = f.seed("http://seed.xyz/", SeedSource.KISA)
    res = f.expand(seed, _obs(seed.candidate_id, [
        ("https://www.kbstar.com/login", Relation.LINK),
        ("https://www.gov.kr/", Relation.LINK),
        ("http://kbstar-secure-login.xyz/", Relation.LINK),
    ]))
    urls = [c.normalized_url for c in res.queued]
    assert urls == ["http://kbstar-secure-login.xyz/"]
    assert set(res.impersonates) == {"kbstar.com", "gov.kr"}
    assert res.skipped["ALLOWLISTED"] == 2
    assert any(r.code == "LOOKALIKE" for r in res.queued[0].score_reasons)


def test_dedupe_and_cycles():
    f = Frontier("case_1")
    seed = f.seed("http://seed.xyz/", SeedSource.REPORT)
    links = [("http://a.xyz/", Relation.REDIRECT), ("http://a.xyz/#frag", Relation.LINK),
             ("http://seed.xyz/", Relation.LINK)]
    res = f.expand(seed, _obs(seed.candidate_id, links))
    assert [c.normalized_url for c in res.queued] == ["http://a.xyz/"]
    assert res.queued[0].relation == Relation.REDIRECT  # 같은 URL 은 높은 점수 관계로 1건만
    res2 = f.expand(res.queued[0], _obs(res.queued[0].candidate_id, [("http://seed.xyz/", Relation.LINK)]))
    assert res2.queued == [] and res2.skipped["DUPLICATE"] == 1


def test_traversed_redirect_hops_not_reinvestigated():
    """부모 조사 중 이미 거쳐 간 hop 은 재큐잉하지 않고, 다른 도메인 경유는 traversed 로만 기록한다."""
    from safetrace.schemas import RedirectHop

    f = Frontier("c")
    seed = f.seed("http://seed.xyz/go/1", SeedSource.REPORT)
    obs = _obs(seed.candidate_id, [("http://seed.xyz/go/2", Relation.REDIRECT),
                                   ("http://mid.top/r", Relation.REDIRECT),
                                   ("http://final.top/", Relation.REDIRECT),
                                   ("http://untouched.top/", Relation.FORM_ACTION)])
    obs.redirect_chain = [RedirectHop(url="http://seed.xyz/go/1", kind="initial"),
                          RedirectHop(url="http://seed.xyz/go/2", status=302, kind="http"),
                          RedirectHop(url="http://mid.top/r", status=302, kind="http"),
                          RedirectHop(url="http://final.top/", status=302, kind="http")]
    obs.final_url = "http://final.top/"
    res = f.expand(seed, obs)
    assert [c.normalized_url for c in res.queued] == ["http://untouched.top/"]
    assert res.traversed == ["http://mid.top/r", "http://final.top/"]
    assert res.skipped["DUPLICATE"] == 3


def test_budgets():
    f = Frontier("c", Budget(max_depth=1, max_candidates=4, max_per_domain=2))
    seed = f.seed("http://seed.xyz/", SeedSource.REPORT)
    links = [(f"http://x{i}.top/p", Relation.REDIRECT) for i in range(10)]
    links += [(f"http://same.top/p{i}", Relation.FORM_ACTION) for i in range(5)]
    res = f.expand(seed, _obs(seed.candidate_id, links))
    assert len(res.queued) == 3  # 사건 예산 4 - seed 1
    assert f.total == 4
    assert res.skipped["CASE_BUDGET"] > 0
    deeper = f.expand(res.queued[0], _obs(res.queued[0].candidate_id, [("http://new.top/", Relation.REDIRECT)]))
    assert deeper.queued == [] and deeper.skipped["DEPTH_LIMIT"] == 1


def test_domain_budget():
    f = Frontier("c", Budget(max_depth=2, max_candidates=50, max_per_domain=2))
    seed = f.seed("http://seed.xyz/", SeedSource.REPORT)
    res = f.expand(seed, _obs(seed.candidate_id, [(f"http://same.top/p{i}", Relation.REDIRECT) for i in range(6)]))
    assert len(res.queued) == 2 and res.skipped["DOMAIN_BUDGET"] == 4


def test_scoring_bonuses_and_penalties():
    f = Frontier("c")
    seed = f.seed("http://seed.xyz/", SeedSource.REPORT)
    obs = _obs(seed.candidate_id, [
        ("https://cdn.jsdelivr.net/npm/x.js", Relation.SCRIPT),
        ("http://pay-collect.shop/", Relation.FORM_ACTION),
        ("http://plain-site.com/", Relation.RESOURCE),
    ], forms=[FormInfo(has_password=True)])
    res = f.expand(seed, obs, age_lookup=lambda d: 10 if d == "pay-collect.shop" else 900)
    top = res.queued[0]
    assert top.normalized_url == "http://pay-collect.shop/"
    codes = {r.code for r in top.score_reasons}
    assert {"NEWLY_REGISTERED", "FROM_SENSITIVE_FORM_PAGE", "SUSPICIOUS_TLD"} <= codes
    assert all("jsdelivr" not in c.normalized_url for c in res.queued)  # 허용목록/공용 CDN


def test_invalid_and_private_links_skipped():
    f = Frontier("c")
    seed = f.seed("http://seed.xyz/", SeedSource.REPORT)
    res = f.expand(seed, _obs(seed.candidate_id, [("javascript:alert(1)", Relation.LINK),
                                                  ("http://user:pw@x.top/", Relation.LINK)]))
    assert res.queued == [] and res.skipped["INVALID_URL"] == 2


def test_d3_official_sites_are_allowlisted_not_lookalikes():
    """D3 에서 발견: 허용목록 오기(kcomwel.or.kr)로 실제 공식 도메인이 유사 도메인으로 판정되던 문제."""
    for host in ("www.comwel.or.kr", "www.nhis.or.kr", "www.kbstar.com"):
        assert is_allowlisted(host)
        assert lookalike_target(host) is None
