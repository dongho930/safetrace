"""2차 SSRF 방어: egress 프록시가 연결 시점에 목적지 IP 를 재확인하고 검증한 IP 로만 연결하는지."""

import asyncio

import pytest

from safetrace.proxy.egress import EgressProxy, serve
from safetrace.security.url_policy import UrlPolicy


async def _proxy(policy: UrlPolicy | None = None):
    p = EgressProxy(policy)
    server = await serve("127.0.0.1", 0, p)
    return p, server, server.sockets[0].getsockname()[1]


async def _raw(port: int, payload: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(payload)
    await w.drain()
    data = await asyncio.wait_for(r.read(65536), 10)
    w.close()
    return data


@pytest.mark.parametrize("req,reason", [
    (b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: x\r\n\r\n", b"IP_NOT_PUBLIC"),
    (b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n", b"IP_NOT_PUBLIC"),
    (b"GET http://10.0.0.1/ HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n", b"IP_NOT_PUBLIC"),
    (b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\n\r\n", b"IP_NOT_PUBLIC"),
    (b"GET http://localhost/ HTTP/1.1\r\n\r\n", b"IP_NOT_PUBLIC"),
    (b"GET http://[::1]/ HTTP/1.1\r\n\r\n", b"IP_NOT_PUBLIC"),
    (b"CONNECT example.com:6379 HTTP/1.1\r\n\r\n", b"URL_PORT_DENIED"),
    (b"GET /relative HTTP/1.1\r\n\r\n", b"UNSUPPORTED_TARGET"),
    (b"GET ftp://example.com/ HTTP/1.1\r\n\r\n", b"UNSUPPORTED_TARGET"),
])
async def test_denied_targets(req, reason):
    p, server, port = await _proxy()
    async with server:
        resp = await _raw(port, req)
    assert resp.split(b"\r\n", 1)[0].split(b" ")[1] in (b"403", b"400")
    assert b"X-SafeTrace-Deny: " + reason in resp
    assert p.stats.denied == 1 and p.stats.allowed == 0


async def test_dns_rebinding_pins_validated_ip(monkeypatch, site):
    """검사 시 공개 IP 로 해석된 도메인이 연결 직전 사설 IP 로 바뀌어도, 프록시는 검증한 IP 로만 연결한다."""
    from safetrace.security import url_policy

    policy = UrlPolicy()
    calls = {"n": 0}
    real_check = url_policy.check_ip

    async def resolve(h, p):
        calls["n"] += 1
        return ["203.0.113.10"]  # 검증 시점의 '공개' 주소(시험용으로 이 주소만 공개 취급)

    def check(ip):
        if str(ip) != "203.0.113.10":
            real_check(ip)

    monkeypatch.setattr(policy, "resolve", resolve)
    monkeypatch.setattr(url_policy, "check_ip", check)
    connected: list[str] = []
    real_open = asyncio.open_connection

    async def spy_open(h, p, **kw):
        connected.append(h)
        raise OSError("stub: no upstream")

    monkeypatch.setattr(asyncio, "open_connection", spy_open)
    proxy, server, pport = await _proxy(policy)
    async with server:
        # 클라이언트 연결(spy 에도 기록됨) 이후의 업스트림 연결 대상만 본다.
        r, w = await real_open("127.0.0.1", pport)
        w.write(b"GET http://rebind.test/ HTTP/1.1\r\nHost: rebind.test\r\n\r\n")
        await w.drain()
        data = await asyncio.wait_for(r.read(65536), 15)
        w.close()
    assert calls["n"] == 1
    assert connected == ["203.0.113.10"]  # 로컬 사설 주소로 재해석해 연결하지 않음
    assert b"UPSTREAM_CONNECT_FAILED" in data or b"502" in data


async def test_allowed_http_passthrough_with_connection_close(site):
    """허용된 목적지는 정상 중계되고, 요청마다 Connection: close 로 연결을 끊는다."""
    _, server, port = await _proxy(UrlPolicy(allow_hostports=frozenset({site})))
    async with server:
        resp = await _raw(port, f"GET http://{site}/benign HTTP/1.1\r\nHost: {site}\r\n"
                                f"Proxy-Connection: keep-alive\r\n\r\n".encode())
    assert resp.startswith(b"HTTP/1.0 200") or resp.startswith(b"HTTP/1.1 200")
