"""D2 SSRF/URL 조작 시나리오 — 1차 방어(접근 전 검사)."""

import pytest

from safetrace.security.url_policy import PolicyViolation, UrlPolicy, check_ip, normalize_url, registrable_domain


def test_normalize_basic():
    n = normalize_url("HTTP://Example.COM:80/a?b=1#frag")
    assert n.url == "http://example.com/a?b=1"
    assert n.registrable_domain == "example.com"
    assert n.idempotency_key == normalize_url("http://example.com/a?b=1").idempotency_key


def test_normalize_idn_to_punycode():
    n = normalize_url("https://국민은행.com/")
    assert n.host.startswith("xn--")
    assert n.unicode_host == "국민은행.com"


@pytest.mark.parametrize("raw,code", [
    ("javascript:alert(1)", "URL_SCHEME_DENIED"),
    ("file:///etc/passwd", "URL_SCHEME_DENIED"),
    ("gopher://x/", "URL_SCHEME_DENIED"),
    ("http://user:pw@example.com/", "URL_USERINFO_DENIED"),
    ("http://example.com:6379/", "URL_PORT_DENIED"),
    ("http://example.com:22/", "URL_PORT_DENIED"),
    ("http:///nohost", "URL_NO_HOST"),
    ("http://exa mple.com/", "URL_BAD_HOST"),
    ("http://example.com\\@evil.com/", "URL_BAD_CHARS"),
    ("http://" + "a" * 2100 + ".com", "URL_TOO_LONG"),
])
def test_normalize_rejects(raw, code):
    with pytest.raises(PolicyViolation) as e:
        normalize_url(raw)
    assert e.value.code == code


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.0.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",  # noqa: S104
    "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
    "64:ff9b::a9fe:a9fe", "2002:7f00:1::",  # NAT64(169.254.169.254) / 6to4(127.0.0.1)
])
def test_private_and_reserved_blocked(ip):
    with pytest.raises(PolicyViolation):
        check_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_allowed(ip):
    check_ip(ip)


@pytest.mark.parametrize("raw", [
    "http://2130706433/",  # 10진 127.0.0.1
    "http://0177.0.0.1/",  # 8진
    "http://0x7f.1/",  # 16진 축약
    "http://127.1/",
    "http://[::ffff:169.254.169.254]/",
    "http://0xa9fea9fe/",  # 169.254.169.254
])
async def test_obfuscated_ip_literals_blocked(raw):
    with pytest.raises(PolicyViolation) as e:
        await UrlPolicy().check_url(raw)
    assert e.value.code == "IP_NOT_PUBLIC"


async def test_dns_to_loopback_blocked():
    with pytest.raises(PolicyViolation) as e:
        await UrlPolicy().check_url("http://localhost/")
    assert e.value.code == "IP_NOT_PUBLIC"


async def test_mixed_dns_answers_blocked(monkeypatch):
    """DNS 응답에 공개·사설 주소가 섞이면(rebinding 준비) 전체 차단."""
    policy = UrlPolicy()

    async def fake_resolve(host, port):
        return ["93.184.216.34", "10.0.0.5"]

    monkeypatch.setattr(policy, "resolve", fake_resolve)
    with pytest.raises(PolicyViolation):
        await policy.check_url("http://rebind.example/")


async def test_worker_mode_skips_dns_but_checks_literals():
    policy = UrlPolicy(resolve_dns=False)
    n, ips = await policy.check_url("http://example.invalid/")
    assert ips == []
    with pytest.raises(PolicyViolation):
        await policy.check_url("http://169.254.169.254/")


def test_registrable_domain():
    assert registrable_domain("a.b.example.co.kr") == "example.co.kr"
    assert registrable_domain("www.naver.com") == "naver.com"
    assert registrable_domain("x.y.go.kr") == "y.go.kr"
