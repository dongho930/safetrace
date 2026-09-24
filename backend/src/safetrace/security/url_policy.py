"""접근 전 검사(1차 SSRF 방어): URL 정규화 → DNS 확인 → 사설·예약 IP 차단.

2차 방어는 egress 프록시(safetrace.proxy.egress)가 연결 시점에 같은 정책으로 IP 를 다시 확인하고,
검증한 IP 로만 연결(pinning)해 DNS Rebinding 을 막는다. 두 계층은 이 모듈의 `check_ip` 를 공유한다.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit, urlunsplit

import idna

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})

# 내부 서비스에 흔한 포트는 외부 조사 대상이라도 연결하지 않는다.
DENIED_PORTS = frozenset({
    0, 22, 23, 25, 110, 135, 139, 143, 445, 1433, 1521, 2049, 2375, 2376, 2379, 3306, 3389,
    5432, 5601, 5672, 5984, 6379, 6443, 8081, 9000, 9092, 9200, 9300, 10250, 11211, 15672, 27017,
})

# ipaddress.is_global 이 걸러내지 못하거나 명시적으로 막아야 하는 대역.
EXTRA_BLOCKED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",
    "100.64.0.0/10",  # CGNAT
    "169.254.0.0/16",  # 링크로컬·클라우드 메타데이터(169.254.169.254)
    "192.0.0.0/24",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "64:ff9b::/96",  # NAT64: 내장 IPv4 는 별도 검사
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
))

# 등록 가능 도메인 계산용 다단계 공개 접미사(최소 집합). 운영 시 PSL 스냅샷으로 교체한다.
MULTI_LABEL_SUFFIXES = frozenset({
    "co.kr", "go.kr", "or.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "mil.kr", "hs.kr", "ms.kr",
    "es.kr", "sc.kr", "kg.kr", "seoul.kr", "busan.kr", "gyeonggi.kr",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
    "com.cn", "net.cn", "com.hk", "com.tw", "com.sg", "com.br", "co.in", "co.nz", "com.vn", "com.ph",
})

_HOST_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


class PolicyViolation(Exception):
    """정책 위반. code 는 감사로그·UI 에 그대로 쓰이므로 내부 정보를 담지 않는다."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class NormalizedUrl:
    url: str
    scheme: str
    host: str  # IDNA(punycode) 소문자
    port: int
    path: str
    is_ip_literal: bool
    registrable_domain: str
    unicode_host: str

    @property
    def idempotency_key(self) -> str:
        return hashlib.sha256(self.url.encode()).hexdigest()


def _parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """10진·8진·16진·축약 IPv4 표기(예: 2130706433, 0177.0.0.1, 0x7f.1)까지 IP 로 해석한다."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    parts = h.split(".")
    if not 1 <= len(parts) <= 4 or not all(parts):
        return None
    nums: list[int] = []
    for p in parts:
        try:
            if p.lower().startswith("0x"):
                nums.append(int(p, 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                if not p.isdigit():
                    return None
                nums.append(int(p, 10))
        except ValueError:
            return None
    # inet_aton 규칙: 마지막 조각이 남은 바이트를 모두 채운다.
    *head, last = nums
    if any(n > 255 for n in head) or last >= 256 ** (4 - len(head)):
        return None
    value = 0
    for n in head:
        value = value * 256 + n
    value = value * 256 ** (4 - len(head)) + last
    return ipaddress.IPv4Address(value)


def registrable_domain(host: str) -> str:
    if _parse_ip_literal(host) is not None:
        return host
    labels = host.rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _encode_host(raw_host: str) -> tuple[str, str]:
    host = raw_host.rstrip(".").lower()
    if not host:
        raise PolicyViolation("URL_NO_HOST")
    if host.isascii():
        ascii_host = host
    else:
        try:
            ascii_host = idna.encode(host, uts46=True).decode("ascii")
        except idna.IDNAError as exc:
            raise PolicyViolation("URL_BAD_IDN") from exc
    try:
        unicode_host = idna.decode(ascii_host) if "xn--" in ascii_host else ascii_host
    except idna.IDNAError:
        unicode_host = ascii_host
    return ascii_host, unicode_host


def normalize_url(raw: str) -> NormalizedUrl:
    if not isinstance(raw, str) or not raw.strip():
        raise PolicyViolation("URL_EMPTY")
    raw = raw.strip()
    if len(raw) > MAX_URL_LENGTH:
        raise PolicyViolation("URL_TOO_LONG")
    if any(ord(c) < 0x20 or c in "\\" for c in raw):
        raise PolicyViolation("URL_BAD_CHARS")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise PolicyViolation("URL_PARSE_ERROR") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise PolicyViolation("URL_SCHEME_DENIED", scheme[:16])
    if parts.username is not None or parts.password is not None:
        raise PolicyViolation("URL_USERINFO_DENIED")
    if parts.hostname is None:
        raise PolicyViolation("URL_NO_HOST")

    ip = _parse_ip_literal(parts.hostname)
    if ip is not None:
        host = f"[{ip.compressed}]" if ip.version == 6 else str(ip)
        unicode_host = host
    else:
        host, unicode_host = _encode_host(parts.hostname)
        if not all(_HOST_LABEL.match(label) for label in host.split(".")):
            raise PolicyViolation("URL_BAD_HOST")

    default_port = 443 if scheme == "https" else 80
    port = port or default_port
    if port in DENIED_PORTS:
        raise PolicyViolation("URL_PORT_DENIED", str(port))
    netloc = host if port == default_port else f"{host}:{port}"
    path = parts.path or "/"
    url = urlunsplit(SplitResult(scheme, netloc, path, parts.query, ""))
    return NormalizedUrl(
        url=url,
        scheme=scheme,
        host=host.strip("[]") if ip is not None else host,
        port=port,
        path=path,
        is_ip_literal=ip is not None,
        registrable_domain=registrable_domain(host.strip("[]")),
        unicode_host=unicode_host,
    )


def check_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address | str) -> None:
    """사설·예약·링크로컬·루프백·멀티캐스트 등 비공개 대역이면 PolicyViolation."""
    addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = addr.ipv4_mapped or addr.sixtofour or (addr.teredo[1] if addr.teredo else None)
        if embedded is None and addr in ipaddress.ip_network("64:ff9b::/96"):
            embedded = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        if embedded is not None:
            check_ip(embedded)
    if not addr.is_global or any(addr in net for net in EXTRA_BLOCKED_NETWORKS):
        raise PolicyViolation("IP_NOT_PUBLIC", str(addr))


@dataclass
class UrlPolicy:
    """접근 전 검사. 시험용 로컬 서버만 `allow_hostports` 로 명시 허용(운영 기본값은 비어 있음)."""

    allow_hostports: frozenset[str] = field(default_factory=frozenset)
    resolve_timeout_s: float = 5.0
    # False: 격리 Worker 처럼 외부 DNS 가 없는 곳. 도메인 IP 검사는 egress 프록시가 연결 시점에 수행한다.
    resolve_dns: bool = True

    def is_test_allowed(self, n: NormalizedUrl) -> bool:
        return f"{n.host}:{n.port}" in self.allow_hostports

    async def resolve(self, host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), self.resolve_timeout_s
            )
        except (TimeoutError, socket.gaierror) as exc:
            raise PolicyViolation("DNS_RESOLVE_FAILED", host) from exc
        return sorted({str(info[4][0]).split("%")[0] for info in infos})

    async def check_url(self, raw: str) -> tuple[NormalizedUrl, list[str]]:
        """정규화 + DNS 확인. 해석된 주소 중 하나라도 비공개 대역이면 전체를 차단한다."""
        n = normalize_url(raw)
        if self.is_test_allowed(n):
            return n, []
        if n.is_ip_literal:
            check_ip(n.host)
            return n, [n.host]
        if not self.resolve_dns:
            return n, []
        ips = await self.resolve(n.host, n.port)
        if not ips:
            raise PolicyViolation("DNS_NO_ADDRESS", n.host)
        for ip in ips:
            check_ip(ip)
        return n, ips
