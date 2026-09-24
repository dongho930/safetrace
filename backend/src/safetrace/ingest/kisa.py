"""공공데이터포털 「한국인터넷진흥원_피싱사이트 URL」 적재(형식 확정본: docs/06_kisa_data_format.md).

지원 형식
- 파일데이터(CSV): 헤더 `날짜,홈페이지주소` (UTF-8/UTF-8-SIG/CP949 자동 판별)
- 오픈 API(JSON): `{"data": [{"날짜": "...", "홈페이지주소": "..."}], ...}`

적재 규칙
- 스킴이 없으면 http:// 를 붙여 정규화한다(원문은 original 에 보존).
- 정규화 실패·금지 대상(IP 사설 대역 리터럴 등)은 거부 사유와 함께 rejected 로 분리한다.
- 파일 내 중복(정규화 URL 기준)은 제거한다.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import date, datetime

from safetrace.security.url_policy import PolicyViolation, check_ip, normalize_url

URL_KEYS = ("홈페이지주소", "URL", "url", "홈페이지 주소", "피싱사이트")
DATE_KEYS = ("날짜", "등록일", "date", "탐지일")
MAX_ROWS = 200_000


@dataclass(frozen=True)
class KisaRecord:
    original: str
    normalized_url: str
    registrable_domain: str
    idempotency_key: str
    detected_on: date | None


@dataclass
class KisaLoadResult:
    records: list[KisaRecord] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)
    duplicates: int = 0


def _decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "cp949"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _parse_date(s: str) -> date | None:
    s = (s or "").strip()
    for fmt in ("%Y-%m-%d", "%Y.%m.%d", "%Y%m%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(s[:10], fmt).date()
        except ValueError:
            continue
    return None


def _pick(row: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        if row.get(k):
            return str(row[k])
    return ""


def _to_record(original: str, detected: str) -> KisaRecord:
    raw = original.strip().strip('"').replace(" ", "")
    if raw and "://" not in raw:
        raw = "http://" + raw
    n = normalize_url(raw)
    if n.is_ip_literal:
        check_ip(ipaddress.ip_address(n.host))
    return KisaRecord(original=original[:2048], normalized_url=n.url, registrable_domain=n.registrable_domain,
                      idempotency_key=n.idempotency_key, detected_on=_parse_date(detected))


def _load_rows(rows) -> KisaLoadResult:
    res = KisaLoadResult()
    seen: set[str] = set()
    for i, row in enumerate(rows):
        if i >= MAX_ROWS:
            res.rejected.append(("", "MAX_ROWS_EXCEEDED"))
            break
        original = _pick(row, URL_KEYS)
        if not original.strip():
            res.rejected.append(("", "EMPTY_URL"))
            continue
        try:
            rec = _to_record(original, _pick(row, DATE_KEYS))
        except PolicyViolation as exc:
            res.rejected.append((original[:200], exc.code))
            continue
        if rec.idempotency_key in seen:
            res.duplicates += 1
            continue
        seen.add(rec.idempotency_key)
        res.records.append(rec)
    return res


def load_csv(raw: bytes) -> KisaLoadResult:
    reader = csv.DictReader(io.StringIO(_decode(raw)))
    if reader.fieldnames:
        reader.fieldnames = [f.strip() for f in reader.fieldnames]
    return _load_rows(reader)


def load_api_json(raw: bytes) -> KisaLoadResult:
    doc = json.loads(_decode(raw))
    rows = doc.get("data", []) if isinstance(doc, dict) else []
    return _load_rows(r for r in rows if isinstance(r, dict))
