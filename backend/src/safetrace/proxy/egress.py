"""egress 전용 프록시(2차 SSRF 방어). 조사 Worker 의 유일한 외부 출구다.

- CONNECT(HTTPS)와 absolute-form HTTP 요청만 허용한다.
- 연결 시점에 DNS 를 직접 해석하고, 해석된 주소가 모두 공개 대역일 때만 **검증한 IP 로** 연결한다.
  검사와 연결 사이에 DNS 응답이 바뀌어도(DNS Rebinding) 검증하지 않은 주소로는 연결되지 않는다.
- 사설·예약·링크로컬(169.254.169.254 포함)·내부 서비스 대역·위험 포트를 차단한다.
- 연결 수·유휴 시간·전송량 상한을 둔다.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from safetrace.security.url_policy import PolicyViolation, UrlPolicy

log = logging.getLogger("safetrace.egress")

MAX_HEAD = 16 * 1024
IDLE_TIMEOUT_S = 30.0
MAX_BYTES_PER_CONN = 50 * 1024 * 1024
HOP_HEADERS = {"proxy-connection", "proxy-authorization", "connection", "keep-alive", "te", "upgrade"}


@dataclass
class ProxyStats:
    allowed: int = 0
    denied: int = 0


class EgressProxy:
    def __init__(self, policy: UrlPolicy | None = None, max_conns: int = 64) -> None:
        self.policy = policy or UrlPolicy()
        self.stats = ProxyStats()
        self._sem = asyncio.Semaphore(max_conns)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._sem:
            try:
                await self._handle(reader, writer)
            except (ConnectionError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    writer.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        if len(head) > MAX_HEAD:
            return await self._deny(writer, 431, "HEAD_TOO_LARGE")
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            return await self._deny(writer, 400, "BAD_REQUEST_LINE")

        if method.upper() == "CONNECT":
            url = f"https://{target}/"
        elif target.lower().startswith("http://"):
            url = target
        else:
            return await self._deny(writer, 400, "UNSUPPORTED_TARGET")

        try:
            n, ips = await self.policy.check_url(url)
        except PolicyViolation as exc:
            return await self._deny(writer, 403, exc.code, url)
        connect_host = ips[0] if ips else n.host  # 검증한 IP 로 고정(pinning)
        try:
            up_reader, up_writer = await asyncio.wait_for(asyncio.open_connection(connect_host, n.port), 10)
        except (OSError, TimeoutError):
            return await self._deny(writer, 502, "UPSTREAM_CONNECT_FAILED", url)

        self.stats.allowed += 1
        log.info("allow %s %s -> %s:%s", method, n.host, connect_host, n.port)
        try:
            if method.upper() == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                up_writer.write(self._rewrite_http_head(lines, method, target, version))
                await up_writer.drain()
            await self._pipe(reader, writer, up_reader, up_writer)
        finally:
            with contextlib.suppress(Exception):
                up_writer.close()

    @staticmethod
    def _rewrite_http_head(lines: list[str], method: str, target: str, version: str) -> bytes:
        parts = urlsplit(target)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        out = [f"{method} {path} {version}"]
        for line in lines[1:]:
            if not line:
                continue
            name = line.split(":", 1)[0].strip().lower()
            if name in HOP_HEADERS:
                continue
            out.append(line)
        # 한 연결에서 다른 호스트로 요청을 이어 보내지 못하도록 요청마다 연결을 닫는다.
        out.append("Connection: close")
        return ("\r\n".join(out) + "\r\n\r\n").encode("latin-1")

    async def _pipe(self, cr, cw, ur, uw) -> None:
        total = 0

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            nonlocal total
            while True:
                chunk = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT_S)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES_PER_CONN:
                    break
                dst.write(chunk)
                await dst.drain()
            with contextlib.suppress(Exception):
                dst.write_eof()

        tasks = [asyncio.create_task(pump(cr, uw)), asyncio.create_task(pump(ur, cw))]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        for t in pending:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(t, IDLE_TIMEOUT_S)
        for t in tasks:
            if not t.done():
                t.cancel()

    async def _deny(self, writer: asyncio.StreamWriter, code: int, reason: str, url: str = "") -> None:
        self.stats.denied += 1
        log.warning("deny %s %s", reason, url[:200])
        body = f"SafeTrace egress denied: {reason}\n".encode()
        writer.write(
            f"HTTP/1.1 {code} Denied\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
            f"X-SafeTrace-Deny: {reason}\r\nConnection: close\r\n\r\n".encode() + body
        )
        with contextlib.suppress(Exception):
            await writer.drain()


async def serve(host: str, port: int, proxy: EgressProxy | None = None) -> asyncio.Server:
    p = proxy or EgressProxy()
    return await asyncio.start_server(p.handle, host, port, limit=MAX_HEAD)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    host = os.environ.get("SAFETRACE_PROXY_HOST", "127.0.0.1")
    port = int(os.environ.get("SAFETRACE_PROXY_PORT", "3128"))

    async def run() -> None:
        server = await serve(host, port)
        log.info("egress proxy listening on %s:%s", host, port)
        async with server:
            await server.serve_forever()

    asyncio.run(run())


if __name__ == "__main__":
    main()
