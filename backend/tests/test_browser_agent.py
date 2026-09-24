"""Browser Agent 통합 시험(실제 Chromium). 로컬 시험 사이트만 allow_hostports 로 허용한다.

통과 기준: 지연 렌더링 포착(R1), 리다이렉트 단계 기록, 사설·예약 IP 로 향하는 리다이렉트 차단(D2),
다운로드·팝업 차단, 스크린샷·녹화 생성, 실시간 프레임 콜백.
"""

import pytest

from safetrace.agent.browser import AgentLimits, BrowserAgent
from safetrace.schemas import EvidenceType
from safetrace.security.url_policy import UrlPolicy

pytestmark = pytest.mark.browser


def _agent(site: str, **kw) -> BrowserAgent:
    limits = AgentLimits(page_timeout_s=10, settle_s=1.2, total_budget_s=40, max_redirects=5)
    return BrowserAgent(UrlPolicy(allow_hostports=frozenset({site})), limits, **kw)


async def test_delayed_rendering_captured_with_evidence(site):
    frames: list[bytes] = []
    steps: list[str] = []

    async def on_frame(b: bytes) -> None:
        frames.append(b)

    async def on_step(s: str, _: dict) -> None:
        steps.append(s)

    res = await _agent(site).investigate("cand_1", f"http://{site}/phish", on_frame=on_frame, on_step=on_step)
    obs = res.observation
    assert obs.reachable and obs.dom_summary.title.startswith("국민건강보험")
    form = next(f for f in obs.forms if f.action.startswith("http://collector"))
    assert form.has_password and form.has_id_number_like and form.external_action  # 800ms 뒤 삽입된 폼
    assert res.artifacts[EvidenceType.SCREENSHOT].startswith(b"\x89PNG")
    assert res.artifacts[EvidenceType.VIDEO][:4] == b"\x1a\x45\xdf\xa3"  # WebM(EBML)
    assert b"collector.example.xyz" in res.artifacts[EvidenceType.HTML]
    assert steps[:1] == ["navigate"] and "collected" in steps
    assert frames and frames[0][:2] == b"\xff\xd8"
    links = {link.url for link in obs.observed_links}
    assert "http://kbstar-secure-login.xyz/" in links


async def test_http_redirect_chain_recorded(site):
    obs = (await _agent(site, record_video=False).investigate("c", f"http://{site}/r1")).observation
    assert [h.kind for h in obs.redirect_chain] == ["initial", "http", "http", "http"]
    assert [h.status for h in obs.redirect_chain[1:]] == [302, 301, 302]
    assert obs.final_url.endswith("/benign")


@pytest.mark.parametrize("path", ["/to-private", "/to-metadata", "/to-loopback"])
async def test_redirect_to_private_ip_blocked(site, path):
    obs = (await _agent(site, record_video=False).investigate("c", f"http://{site}{path}")).observation
    assert "IP_NOT_PUBLIC" in obs.policy_blocks or "URL_PORT_DENIED" in obs.policy_blocks
    assert obs.request_summary.blocked >= 1
    assert "169.254.169.254" not in obs.final_url and "10.255.255.1" not in obs.final_url


async def test_redirect_loop_limited(site):
    obs = (await _agent(site, record_video=False).investigate("c", f"http://{site}/loop")).observation
    assert "REDIRECT_LIMIT" in obs.policy_blocks


async def test_meta_refresh_client_redirect(site):
    obs = (await _agent(site, record_video=False).investigate("c", f"http://{site}/meta")).observation
    assert obs.final_url.endswith("/benign")
    assert any(h.kind == "client" for h in obs.redirect_chain)


async def test_popup_and_download_blocked(site):
    a = _agent(site, record_video=False)
    obs = (await a.investigate("c", f"http://{site}/popup")).observation
    assert obs.popups_blocked == 0  # window.open 이 무력화되어 팝업 자체가 생성되지 않음
    obs = (await a.investigate("c", f"http://{site}/download")).observation
    assert obs.downloads_blocked >= 1 or any(link.url.endswith(".apk") for link in obs.observed_links)


async def test_har_snapshot_replays_offline(site, tmp_path):
    """D1-R 방식: 1회 수집한 HAR 을 재생하면 서버 없이 같은 관찰을 재현한다(위험 사이트 반복 접속 없음)."""
    rec = await _agent(site, record_video=False, record_har=True).investigate("c", f"http://{site}/r1")
    har = tmp_path / "trace.har.json"
    har.write_bytes(rec.artifacts[EvidenceType.HAR])
    replay = BrowserAgent(UrlPolicy(resolve_dns=False), AgentLimits(settle_s=0.5, total_budget_s=30),
                          record_video=False, har_replay=har)
    obs = (await replay.investigate("c", "http://unreachable-host.invalid/")).observation
    assert obs.dom_summary.text_excerpt == ""  # HAR 에 없는 URL 은 abort(외부 접속 없음)
    obs = (await replay.investigate("c", f"http://{site}/benign")).observation
    assert "식빵" in obs.dom_summary.text_excerpt


async def test_direct_private_target_never_navigated():
    res = await BrowserAgent(UrlPolicy(), AgentLimits(total_budget_s=20)).investigate(
        "c", "http://169.254.169.254/latest/meta-data/")
    assert "IP_NOT_PUBLIC" in res.observation.policy_blocks
    assert EvidenceType.SCREENSHOT not in res.artifacts or res.observation.dom_summary.text_excerpt == ""


@pytest.mark.parametrize("path,error,block", [
    ("/proxy-deny", "EGRESS_UPSTREAM_CONNECT_FAILED", None),
    ("/proxy-policy-deny", None, "IP_NOT_PUBLIC"),
])
async def test_egress_proxy_denial_is_unreachable(site, path, error, block):
    """평문 HTTP 목적지의 프록시 거부 응답은 페이지로 수집하지 않는다(D1-R 수집 결함 재발 방지)."""
    from .conftest import DENY_TOKEN

    res = await _agent(site, record_video=False, egress_deny_token=DENY_TOKEN).investigate("c", f"http://{site}{path}")
    obs = res.observation
    assert obs.reachable is False and obs.dom_summary.text_excerpt == ""
    assert (error in obs.errors) if error else (block in obs.policy_blocks)


async def test_forged_deny_header_does_not_evade_analysis(site):
    """사이트가 거부 헤더를 흉내 내도 공유 비밀값이 다르면 정상적으로 수집·분석한다."""
    from .conftest import DENY_TOKEN

    obs = (await _agent(site, record_video=False, egress_deny_token=DENY_TOKEN)
           .investigate("c", f"http://{site}/forged-deny")).observation
    assert obs.reachable is True and "환급금" in obs.dom_summary.text_excerpt
    assert not any(e.startswith("EGRESS_") for e in obs.errors)
