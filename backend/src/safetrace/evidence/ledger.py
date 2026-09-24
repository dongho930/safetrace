"""추가 전용 증거 원장: SHA-256 + 해시 체인 + 분리 키 HMAC 서명.

- 증거 파일은 서버가 생성한 이름(evidence_id + 고정 확장자)으로만 저장한다(파일명 불신).
- 레코드 해시는 직전 레코드 해시(prev_hash)를 포함해 중간 레코드 수정·삭제를 드러낸다.
- 레코드 해시에 서명 서비스의 HMAC 을 붙여, 파일+해시를 함께 고쳐도 서명을 재생성할 수 없게 한다.
- 서명 서비스의 high-water mark 와 비교해 끝 레코드 삭제도 탐지한다.
- 조회·패키지 생성 시 verify() 로 해시·체인·서명·파일을 모두 재검증한다.

개발·시험용 저장소는 SQLite(트리거로 UPDATE/DELETE 거부), 운영은 PostgreSQL(infra/db/schema.sql)이다.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from safetrace.evidence.signer_client import SignerClient
from safetrace.schemas import ChainVerification, Evidence, EvidenceType, VerifyIssue, new_id

GENESIS = "0" * 64
EXTENSIONS = {
    EvidenceType.SCREENSHOT: ".png",
    EvidenceType.HTML: ".html.txt",  # 실행되지 않도록 텍스트 확장자로 보관
    EvidenceType.OBSERVATION: ".json",
    EvidenceType.VIDEO: ".webm",
    EvidenceType.HAR: ".har.json",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence (
    seq INTEGER PRIMARY KEY,
    evidence_id TEXT NOT NULL UNIQUE,
    case_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    type TEXT NOT NULL,
    object_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    captured_at TEXT NOT NULL,
    version INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL,
    hmac_sig TEXT NOT NULL,
    key_id TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
CREATE TRIGGER IF NOT EXISTS evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is append-only'); END;
"""

_FIELDS = ("seq", "evidence_id", "case_id", "candidate_id", "type", "object_path", "sha256", "size",
           "captured_at", "version", "prev_hash", "record_hash", "hmac_sig", "key_id")
# 고정 SQL 리터럴(값은 모두 파라미터 바인딩).
_SQL_LAST = ("SELECT seq, evidence_id, case_id, candidate_id, type, object_path, sha256, size, captured_at, "
             "version, prev_hash, record_hash, hmac_sig, key_id FROM evidence ORDER BY seq DESC LIMIT 1")
_SQL_ALL = ("SELECT seq, evidence_id, case_id, candidate_id, type, object_path, sha256, size, captured_at, "
            "version, prev_hash, record_hash, hmac_sig, key_id FROM evidence ORDER BY seq ASC")
_SQL_INSERT = ("INSERT INTO evidence (seq, evidence_id, case_id, candidate_id, type, object_path, sha256, size, "
               "captured_at, version, prev_hash, record_hash, hmac_sig, key_id) "
               "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_record_hash(
    *, seq: int, evidence_id: str, case_id: str, candidate_id: str, type: str, object_path: str,
    sha256: str, size: int, captured_at: str, version: int, prev_hash: str,
) -> str:
    canonical = json.dumps(
        {
            "seq": seq, "evidence_id": evidence_id, "case_id": case_id, "candidate_id": candidate_id,
            "type": type, "object_path": object_path, "sha256": sha256, "size": size,
            "captured_at": captured_at, "version": version, "prev_hash": prev_hash,
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


class EvidenceLedger:
    def __init__(self, root: Path, signer: SignerClient) -> None:
        self.root = root
        self.objects = root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.db_path = root / "ledger.sqlite3"
        self._signer = signer
        self._lock = asyncio.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return conn

    def _object_path(self, case_id: str, evidence_id: str, etype: EvidenceType) -> Path:
        # case_id·evidence_id 는 서버 생성 값만 허용(경로 조작 방지).
        for part in (case_id, evidence_id):
            if not part.replace("_", "").isalnum():
                raise ValueError("invalid id")
        return self.objects / case_id / f"{evidence_id}{EXTENSIONS[etype]}"

    async def append(self, *, case_id: str, candidate_id: str, etype: EvidenceType, data: bytes,
                     captured_at: datetime | None = None) -> Evidence:
        captured = (captured_at or datetime.now(UTC)).astimezone(UTC).isoformat()
        evidence_id = new_id("ev")
        path = self._object_path(case_id, evidence_id, etype)
        rel = path.relative_to(self.root).as_posix()
        digest = sha256_bytes(data)
        async with self._lock:
            await asyncio.to_thread(self._write_object, path, data)
            last = await asyncio.to_thread(self._last_row)
            seq = (last["seq"] + 1) if last else 1
            prev_hash = last["record_hash"] if last else GENESIS
            fields = dict(
                seq=seq, evidence_id=evidence_id, case_id=case_id, candidate_id=candidate_id,
                type=etype.value, object_path=rel, sha256=digest, size=len(data),
                captured_at=captured, version=1, prev_hash=prev_hash,
            )
            record_hash = compute_record_hash(**fields)
            sig, key_id = await self._signer.sign(seq, record_hash)
            row = {**fields, "record_hash": record_hash, "hmac_sig": sig, "key_id": key_id}
            await asyncio.to_thread(self._insert, row)
        return Evidence(**{**row, "type": etype, "captured_at": datetime.fromisoformat(captured)})

    @staticmethod
    def _write_object(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "xb") as f:  # 기존 파일 덮어쓰기 금지
            f.write(data)

    def _last_row(self) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(_SQL_LAST).fetchone()

    def _insert(self, row: dict) -> None:
        with self._connect() as conn:
            conn.execute(_SQL_INSERT, tuple(row[c] for c in _FIELDS))

    def _all_rows(self) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(_SQL_ALL).fetchall()

    async def list_for_candidate(self, candidate_id: str) -> list[Evidence]:
        rows = await asyncio.to_thread(self._all_rows)
        return [self._to_model(r) for r in rows if r["candidate_id"] == candidate_id]

    async def get(self, evidence_id: str) -> Evidence | None:
        rows = await asyncio.to_thread(self._all_rows)
        return next((self._to_model(r) for r in rows if r["evidence_id"] == evidence_id), None)

    def read_object(self, ev: Evidence) -> bytes:
        path = (self.root / ev.object_path).resolve()
        if not path.is_relative_to(self.objects.resolve()):
            raise ValueError("object path escapes store")
        return path.read_bytes()

    @staticmethod
    def _to_model(r: sqlite3.Row) -> Evidence:
        d = dict(r)
        d["type"] = EvidenceType(d["type"])
        d["captured_at"] = datetime.fromisoformat(d["captured_at"])
        return Evidence(**d)

    async def verify(self, candidate_id: str | None = None) -> ChainVerification:
        """전체 체인을 검증한다. candidate_id 를 주면 해당 후보 증거의 이슈만 보고한다."""
        rows = await asyncio.to_thread(self._all_rows)
        issues: list[VerifyIssue] = []
        prev_hash = GENESIS
        expected_seq = 1
        for r in rows:
            d = dict(r)
            eid = d["evidence_id"]
            if d["seq"] != expected_seq:
                issues.append(VerifyIssue(seq=expected_seq, evidence_id=eid, code="RECORD_DELETED",
                                          detail=f"seq {expected_seq}..{d['seq'] - 1} missing"))
            if d["prev_hash"] != prev_hash:
                issues.append(VerifyIssue(seq=d["seq"], evidence_id=eid, code="CHAIN_BROKEN"))
            recomputed = compute_record_hash(**{k: d[k] for k in (
                "seq", "evidence_id", "case_id", "candidate_id", "type", "object_path", "sha256",
                "size", "captured_at", "version", "prev_hash")})
            if recomputed != d["record_hash"]:
                issues.append(VerifyIssue(seq=d["seq"], evidence_id=eid, code="RECORD_MODIFIED"))
            if not await self._signer.verify(d["seq"], d["record_hash"], d["hmac_sig"], d["key_id"]):
                issues.append(VerifyIssue(seq=d["seq"], evidence_id=eid, code="SIGNATURE_INVALID"))
            try:
                data = await asyncio.to_thread(self.read_object, self._to_model(r))
                if sha256_bytes(data) != d["sha256"]:
                    issues.append(VerifyIssue(seq=d["seq"], evidence_id=eid, code="OBJECT_MODIFIED"))
            except (FileNotFoundError, ValueError):
                issues.append(VerifyIssue(seq=d["seq"], evidence_id=eid, code="OBJECT_MISSING"))
            prev_hash = d["record_hash"]
            expected_seq = d["seq"] + 1

        signed_max, signed_head = await self._signer.head()
        last_seq = rows[-1]["seq"] if rows else 0
        if signed_max > last_seq:
            issues.append(VerifyIssue(seq=last_seq + 1, evidence_id="-", code="TAIL_TRUNCATED",
                                      detail=f"signer saw seq {signed_max}, ledger has {last_seq}"))
        elif rows and signed_head != rows[-1]["record_hash"]:
            issues.append(VerifyIssue(seq=last_seq, evidence_id=rows[-1]["evidence_id"], code="HEAD_MISMATCH"))

        if candidate_id is not None:
            ids = {r["evidence_id"] for r in rows if r["candidate_id"] == candidate_id}
            issues = [i for i in issues if i.evidence_id in ids or i.code in {"TAIL_TRUNCATED", "RECORD_DELETED"}]
        return ChainVerification(ok=not issues, checked=len(rows), issues=issues, head_hash=prev_hash)
