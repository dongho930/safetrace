"""① 자체 Browser Agent: 격리 Chromium 에서 후보 URL 을 렌더링하고 사실만 수집한다.

안전 통제(기획서 2.2 / docs/04 위협 모델):
- 모든 요청을 가로채 URL 정책(정규화·IP 대역)을 적용하고, 문서 요청의 HTTP 리다이렉트는 직접 받아
  Location 을 재검사한 뒤에만 브라우저에 넘긴다(리다이렉트 단계별 재검증).
- 다운로드·Service Worker·팝업·대화상자 자동 차단, 로그인·결제·폼 입력 없음.
- 요청 수·리다이렉트 수·HTML 크기·시간 상한.
- egress 프록시가 설정되면 모든 트래픽은 프록시 한 곳으로만 나간다(연결 시점 IP 재확인은 프록시 담당).
- 렌더링 녹화(VIDEO)와 CDP screencast 프레임(실시간 조사 화면)을 제공한다.
"""

from __future__ import annotations

import asyncio
import base64
import html
import logging
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from playwright.async_api import Browser, BrowserContext, Page, Request, Route, async_playwright
from playwright.async_api import Error as PlaywrightError

from safetrace import __version__
from safetrace.agent.extract import extract
from safetrace.schemas import (
    EvidenceType,
    Observation,
    ObservedLink,
    RedirectHop,
    Relation,
    RequestSummary,
    utcnow,
)
from safetrace.security.url_policy import PolicyViolation, UrlPolicy, normalize_url

log = logging.getLogger(__name__)

FrameCallback = Callable[[bytes], Awaitable[None]]
StepCallback = Callable[[str, dict], Awaitable[None]]

_POPUP_GUARD = "window.open = function () { return null; };"
_BLOCKED_BODY = b"Blocked by SafeTrace policy"
_CHROMIUM_ARGS = [
    "--disable-dev-shm-usage",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-default-apps",
    "--mute-audio",
    "--no-first-run",
    "--disable-features=InterestFeedContentSuggestions,Translate,MediaRouter,PrivateNetworkAccessSendPreflights",
]


@dataclass
class AgentLimits:
    page_timeout_s: float = 20.0
    settle_s: float = 2.5  # 지연 렌더링 대기
    max_requests: int = 300
    max_redirects: int = 10
    max_html_bytes: int = 2_000_000
    total_budget_s: float = 60.0


@dataclass
class AgentResult:
    observation: Observation
    artifacts: dict[EvidenceType, bytes] = field(default_factory=dict)


@dataclass
class _State:
    requests: int = 0
    redirects: int = 0
    domains: set[str] = field(default_factory=set)
    blocked: list[str] = field(default_factory=list)
    policy_blocks: list[str] = field(default_factory=list)
    hops: list[RedirectHop] = field(default_factory=list)
    mediated: set[str] = field(default_factory=set)  # 3xx 를 대신 중계한 URL(클라이언트 이동으로 오기록 방지)
    popups: int = 0
    downloads: int = 0
    errors: list[str] = field(default_factory=list)


class BrowserAgent:
    def __init__(
        self,
        policy: UrlPolicy,
        limits: AgentLimits | None = None,
        proxy: str = "",
        record_video: bool = True,
        record_har: bool = False,
        headless: bool = True,
        chromium_sandbox: bool = False,
        har_replay: Path | None = None,
    ) -> None:
        # har_replay: D1-R 스냅샷 재생 모드. 네트워크 대신 HAR 에서만 응답하고(없으면 abort) 외부에 접속하지 않는다.
        self.har_replay = har_replay
        self.policy = policy
        self.limits = limits or AgentLimits()
        self.proxy = proxy
        self.record_video = record_video
        self.record_har = record_har
        self.headless = headless
        self.chromium_sandbox = chromium_sandbox

    async def investigate(
        self,
        candidate_id: str,
        url: str,
        on_frame: FrameCallback | None = None,
        on_step: StepCallback | None = None,
    ) -> AgentResult:
        try:
            return await asyncio.wait_for(
                self._investigate(candidate_id, url, on_frame, on_step), self.limits.total_budget_s
            )
        except TimeoutError:
            obs = Observation(candidate_id=candidate_id, requested_url=url[:2048], reachable=False,
                              errors=["TIME_BUDGET_EXCEEDED"], finished_at=utcnow(), agent_version=__version__)
            return AgentResult(observation=obs)

    async def _investigate(self, candidate_id: str, url: str, on_frame: FrameCallback | None,
                           on_step: StepCallback | None) -> AgentResult:
        step = on_step or _noop_step
        obs = Observation(candidate_id=candidate_id, requested_url=url[:2048], agent_version=__version__)
        try:
            start = normalize_url(url)
        except PolicyViolation as exc:
            obs.reachable = False
            obs.policy_blocks.append(exc.code)
            obs.finished_at = utcnow()
            return AgentResult(observation=obs)

        st = _State(hops=[RedirectHop(url=start.url, kind="initial")])
        artifacts: dict[EvidenceType, bytes] = {}
        with tempfile.TemporaryDirectory(prefix="st-agent-") as tmp:
            tmpdir = Path(tmp)
            async with async_playwright() as pw:
                launch_kwargs: dict = {
                    "headless": self.headless,
                    "args": _CHROMIUM_ARGS,
                    "chromium_sandbox": self.chromium_sandbox,
                }
                if self.proxy and self.har_replay is None:
                    launch_kwargs["proxy"] = {"server": self.proxy}
                browser: Browser = await pw.chromium.launch(**launch_kwargs)
                try:
                    context = await self._new_context(browser, tmpdir)
                    if self.har_replay is not None:
                        await context.route_from_har(self.har_replay, not_found="abort")
                    else:
                        await context.route("**/*", lambda r: self._route(r, st))
                    context.on("page", lambda p: asyncio.ensure_future(self._on_extra_page(p, st)))
                    page = await context.new_page()
                    page.on("dialog", lambda d: asyncio.ensure_future(d.dismiss()))
                    page.on("download", lambda d: self._on_download(d, st))
                    page.on("request", lambda r: self._on_request(r, st))
                    page.on("framenavigated", lambda f: self._on_nav(page, f, st))
                    screencast = await self._start_screencast(context, page, on_frame)

                    await step("navigate", {"url": start.url})
                    t0 = time.monotonic()
                    try:
                        await page.goto(start.url, wait_until="domcontentloaded",
                                        timeout=self.limits.page_timeout_s * 1000)
                        try:
                            await page.wait_for_load_state("networkidle", timeout=8000)
                        except PlaywrightError:
                            pass
                        await asyncio.sleep(self.limits.settle_s)
                    except PlaywrightError as exc:
                        msg = str(exc).split("\n", 1)[0]
                        code = _net_error_code(msg)
                        st.errors.append(code)
                        if code in ("ERR_NAME_NOT_RESOLVED", "ERR_CONNECTION_REFUSED",
                                    "ERR_CONNECTION_TIMED_OUT", "ERR_ADDRESS_UNREACHABLE", "TIMEOUT",
                                    "ERR_TUNNEL_CONNECTION_FAILED"):
                            obs.reachable = False
                    await step("rendered", {"elapsed_ms": int((time.monotonic() - t0) * 1000)})

                    if obs.reachable:
                        await self._collect(page, obs, st, artifacts)
                        await step("collected", {"final_url": obs.final_url})
                    if screencast is not None:
                        await _safe(screencast.send("Page.stopScreencast"))
                    video = page.video
                    await context.close()
                    if video is not None and self.record_video:
                        try:
                            artifacts[EvidenceType.VIDEO] = await asyncio.to_thread(Path(await video.path()).read_bytes)
                        except (PlaywrightError, OSError):
                            st.errors.append("VIDEO_UNAVAILABLE")
                    har_path = tmpdir / "trace.har"
                    if self.record_har and har_path.exists():
                        artifacts[EvidenceType.HAR] = har_path.read_bytes()
                finally:
                    await browser.close()

        obs.redirect_chain = st.hops[: self.limits.max_redirects + 2]
        start_host = start.host
        obs.request_summary = RequestSummary(
            total=st.requests,
            blocked=len(st.blocked),
            domains=sorted(st.domains)[:200],
            third_party_domains=sorted(d for d in st.domains if d != start_host)[:200],
            blocked_samples=st.blocked[:20],
        )
        obs.popups_blocked = st.popups
        obs.downloads_blocked = st.downloads
        obs.policy_blocks = sorted(set(obs.policy_blocks) | set(st.policy_blocks))[:50]
        obs.errors = st.errors[:20]
        for hop in obs.redirect_chain[1:]:
            if len(obs.observed_links) < 350:
                obs.observed_links.append(ObservedLink(url=hop.url, relation=Relation.REDIRECT))
        obs.finished_at = utcnow()
        artifacts[EvidenceType.OBSERVATION] = obs.model_dump_json(indent=2).encode()
        return AgentResult(observation=obs, artifacts=artifacts)

    async def _new_context(self, browser: Browser, tmpdir: Path) -> BrowserContext:
        kwargs: dict = {
            "accept_downloads": False,
            "service_workers": "block",
            "viewport": {"width": 1280, "height": 800},
            "locale": "ko-KR",
            "timezone_id": "Asia/Seoul",
            "ignore_https_errors": True,  # 인증서 오류 자체가 관찰 대상이므로 렌더링은 진행
            "java_script_enabled": True,
            "bypass_csp": False,
            "permissions": [],
        }
        if self.record_video:
            kwargs["record_video_dir"] = str(tmpdir / "video")
            kwargs["record_video_size"] = {"width": 1280, "height": 800}
        if self.record_har:
            kwargs["record_har_path"] = str(tmpdir / "trace.har")
            kwargs["record_har_content"] = "embed"
        context = await browser.new_context(**kwargs)
        await context.add_init_script(_POPUP_GUARD)
        context.set_default_timeout(self.limits.page_timeout_s * 1000)
        return context

    async def _check(self, raw: str, st: _State) -> str | None:
        """정책 위반 코드 또는 None. 시험 허용 host:port 가 아니면 IP 리터럴·DNS 결과를 검사한다."""
        try:
            await self.policy.check_url(raw)
            return None
        except PolicyViolation as exc:
            st.policy_blocks.append(exc.code)
            return exc.code

    async def _route(self, route: Route, st: _State) -> None:
        req = route.request
        st.requests += 1
        if st.requests > self.limits.max_requests:
            st.blocked.append(req.url[:300])
            st.policy_blocks.append("REQUEST_LIMIT")
            await _safe(route.abort("blockedbyclient"))
            return
        scheme = urlsplit(req.url).scheme
        if scheme in ("data", "blob", "about"):
            await _safe(route.continue_())
            return
        code = await self._check(req.url, st)
        if code is not None:
            st.blocked.append(req.url[:300])
            await _safe(route.abort("blockedbyclient"))
            return
        if req.resource_type != "document":
            # 하위 리소스의 후속 리다이렉트 hop 은 브라우저가 내부에서 따라가므로 2차 방어(egress 프록시)가 차단한다.
            await _safe(route.continue_())
            return
        await self._route_document(route, req, st)

    async def _route_document(self, route: Route, req: Request, st: _State) -> None:
        """문서 요청은 직접 받아 3xx 를 브라우저에 넘기지 않는다.

        Chromium 은 넘겨받은 3xx 의 후속 hop 을 route 를 거치지 않고 내부에서 따라가므로, Location 을 검사한 뒤
        meta refresh 로 '새 탐색'을 일으켜 다음 hop 도 이 핸들러를 다시 거치게 한다(hop 마다 재검증).
        """
        try:
            resp = await route.fetch(max_redirects=0, timeout=self.limits.page_timeout_s * 1000)
        except PlaywrightError as exc:
            st.errors.append(_net_error_code(str(exc)))
            await _safe(route.abort("failed"))
            return
        if 300 <= resp.status < 400 and "location" in resp.headers:
            target = urljoin(req.url, resp.headers["location"])
            st.redirects += 1
            if req.frame.parent_frame is None:
                st.hops.append(RedirectHop(url=target[:2048], status=resp.status, kind="http"))
            if st.redirects > self.limits.max_redirects:
                st.policy_blocks.append("REDIRECT_LIMIT")
                st.blocked.append(target[:300])
                await _safe(route.fulfill(status=200, body=_BLOCKED_BODY, content_type="text/plain"))
                return
            code = await self._check(target, st)
            if code is not None:
                st.blocked.append(target[:300])
                await _safe(route.fulfill(status=200, body=_BLOCKED_BODY, content_type="text/plain"))
                return
            st.mediated.add(req.url)
            body = f'<meta http-equiv="refresh" content="0;url={html.escape(target, quote=True)}">'
            await _safe(route.fulfill(status=200, body=body, content_type="text/html"))
            return
        body = await resp.body()
        if len(body) > self.limits.max_html_bytes:
            st.policy_blocks.append("HTML_TRUNCATED")
            await _safe(route.fulfill(response=resp, body=body[: self.limits.max_html_bytes]))
            return
        await _safe(route.fulfill(response=resp, body=body))

    def _on_request(self, req: Request, st: _State) -> None:
        host = urlsplit(req.url).hostname
        if host and len(st.domains) < 500:
            st.domains.add(host)

    def _on_nav(self, page: Page, frame, st: _State) -> None:
        if frame != page.main_frame:
            return
        url = frame.url
        if not url or url.startswith(("about:", "chrome-error:")):
            return
        if url in st.mediated or any(h.url.rstrip("/") == url.rstrip("/") for h in st.hops[-3:]):
            return
        # HTTP 3xx 로 이미 기록된 목적지가 아니면 클라이언트 측 이동(meta refresh·JS)으로 기록
        st.hops.append(RedirectHop(url=url[:2048], kind="client"))

    async def _on_extra_page(self, page: Page, st: _State) -> None:
        if await page.opener() is None:  # 조사 대상 페이지 자신은 제외
            return
        st.popups += 1
        await _safe(page.close())

    def _on_download(self, download, st: _State) -> None:
        st.downloads += 1
        asyncio.ensure_future(_safe(download.cancel()))

    async def _start_screencast(self, context: BrowserContext, page: Page, on_frame: FrameCallback | None):
        if on_frame is None:
            return None
        cdp = await context.new_cdp_session(page)
        last = 0.0

        async def handle(params: dict) -> None:
            nonlocal last
            await _safe(cdp.send("Page.screencastFrameAck", {"sessionId": params["sessionId"]}))
            now = time.monotonic()
            if now - last < 0.5:  # 2fps 로 제한
                return
            last = now
            try:
                await on_frame(base64.b64decode(params["data"]))
            except Exception:  # noqa: BLE001 - UI 전송 실패가 조사를 중단시키지 않도록
                log.debug("frame callback failed", exc_info=True)

        cdp.on("Page.screencastFrame", lambda p: asyncio.ensure_future(handle(p)))
        await cdp.send("Page.startScreencast",
                       {"format": "jpeg", "quality": 55, "maxWidth": 640, "maxHeight": 400, "everyNthFrame": 2})
        return cdp

    async def _collect(self, page: Page, obs: Observation, st: _State,
                       artifacts: dict[EvidenceType, bytes]) -> None:
        obs.final_url = page.url[:2048]
        try:
            html = await page.content()
        except PlaywrightError:
            html = ""
            st.errors.append("CONTENT_UNAVAILABLE")
        html = html[: self.limits.max_html_bytes]
        summary, forms, links, _ = extract(html, obs.final_url or obs.requested_url)
        obs.dom_summary = summary
        obs.forms = forms[:30]
        obs.observed_links = links
        artifacts[EvidenceType.HTML] = html.encode("utf-8", "replace")
        try:
            artifacts[EvidenceType.SCREENSHOT] = await page.screenshot(type="png", full_page=False,
                                                                     animations="disabled")
        except PlaywrightError:
            st.errors.append("SCREENSHOT_FAILED")


async def _noop_step(_: str, __: dict) -> None:
    return None


async def _safe(aw) -> None:
    try:
        await aw
    except PlaywrightError:
        pass


def _net_error_code(msg: str) -> str:
    for token in msg.replace(";", " ").split():
        if token.startswith("net::"):
            return token.removeprefix("net::")[:64]
    if "Timeout" in msg:
        return "TIMEOUT"
    return "NAVIGATION_FAILED"
