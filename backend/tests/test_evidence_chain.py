"""R2 증거 무결성: 파일 단독·파일+해시 동시·레코드 삭제·끝 레코드 삭제 변조를 모두 탐지해야 한다."""

import sqlite3

import pytest

from safetrace.evidence.ledger import EvidenceLedger, compute_record_hash, sha256_bytes
from safetrace.schemas import EvidenceType


async def _fill(ledger: EvidenceLedger, n: int = 4):
    evs = []
    for i in range(n):
        evs.append(await ledger.append(case_id="case_t", candidate_id=f"cand_{i % 2}",
                                       etype=EvidenceType.SCREENSHOT, data=f"img-{i}".encode()))
    return evs


def _insider(ledger: EvidenceLedger) -> sqlite3.Connection:
    """저장소 권한을 가진 내부자: 트리거를 지우고 직접 수정한다."""
    conn = sqlite3.connect(ledger.db_path, isolation_level=None)
    conn.execute("DROP TRIGGER evidence_no_update")
    conn.execute("DROP TRIGGER evidence_no_delete")
    return conn


def _codes(v):
    return {i.code for i in v.issues}


async def test_clean_chain_verifies(ledger):
    evs = await _fill(ledger)
    v = await ledger.verify()
    assert v.ok and v.checked == 4
    assert evs[1].prev_hash == evs[0].record_hash
    assert evs[0].prev_hash == "0" * 64
    assert all(len(e.hmac_sig) == 64 for e in evs)


async def test_append_only_trigger(ledger):
    await _fill(ledger, 1)
    conn = sqlite3.connect(ledger.db_path)
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE evidence SET sha256 = 'x'")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM evidence")


async def test_file_only_tamper(ledger):
    evs = await _fill(ledger)
    (ledger.root / evs[2].object_path).write_bytes(b"forged")
    v = await ledger.verify()
    assert not v.ok and "OBJECT_MODIFIED" in _codes(v)


async def test_file_and_hash_tamper(ledger):
    """파일과 sha256 을 함께 바꾸면 레코드 해시 불일치로 탐지."""
    evs = await _fill(ledger)
    forged = b"forged"
    (ledger.root / evs[1].object_path).write_bytes(forged)
    _insider(ledger).execute("UPDATE evidence SET sha256=? WHERE seq=2", (sha256_bytes(forged),))
    v = await ledger.verify()
    assert "RECORD_MODIFIED" in _codes(v)


async def test_file_hash_and_record_hash_tamper(ledger):
    """레코드 해시까지 다시 계산해도 HMAC 서명(분리 키)과 다음 레코드의 prev_hash 로 탐지."""
    evs = await _fill(ledger)
    forged = b"forged"
    (ledger.root / evs[1].object_path).write_bytes(forged)
    conn = _insider(ledger)
    row = dict(zip([d[0] for d in conn.execute("SELECT * FROM evidence WHERE seq=2").description],
                   conn.execute("SELECT * FROM evidence WHERE seq=2").fetchone(), strict=True))
    row["sha256"] = sha256_bytes(forged)
    new_hash = compute_record_hash(**{k: row[k] for k in (
        "seq", "evidence_id", "case_id", "candidate_id", "type", "object_path", "sha256", "size",
        "captured_at", "version", "prev_hash")})
    conn.execute("UPDATE evidence SET sha256=?, record_hash=? WHERE seq=2", (row["sha256"], new_hash))
    v = await ledger.verify()
    assert {"SIGNATURE_INVALID", "CHAIN_BROKEN"} <= _codes(v)


async def test_full_chain_rewrite_without_key_detected(ledger):
    """내부자가 전 레코드를 재계산해 체인을 재작성해도 서명 키가 없으므로 탐지."""
    evs = await _fill(ledger, 3)
    conn = _insider(ledger)
    prev = "0" * 64
    for e in evs:
        data = b"rewritten-" + e.evidence_id.encode()
        (ledger.root / e.object_path).write_bytes(data)
        fields = dict(seq=e.seq, evidence_id=e.evidence_id, case_id=e.case_id, candidate_id=e.candidate_id,
                      type=e.type.value, object_path=e.object_path, sha256=sha256_bytes(data), size=len(data),
                      captured_at=e.captured_at.isoformat(), version=1, prev_hash=prev)
        rh = compute_record_hash(**fields)
        conn.execute("UPDATE evidence SET sha256=?, size=?, prev_hash=?, record_hash=?, hmac_sig=? WHERE seq=?",
                     (fields["sha256"], fields["size"], prev, rh, "0" * 64, e.seq))
        prev = rh
    v = await ledger.verify()
    assert "SIGNATURE_INVALID" in _codes(v)
    assert "HEAD_MISMATCH" in _codes(v)


async def test_middle_record_deletion(ledger):
    await _fill(ledger)
    _insider(ledger).execute("DELETE FROM evidence WHERE seq=2")
    v = await ledger.verify()
    assert {"RECORD_DELETED", "CHAIN_BROKEN"} <= _codes(v)


async def test_tail_deletion(ledger):
    await _fill(ledger)
    _insider(ledger).execute("DELETE FROM evidence WHERE seq=4")
    v = await ledger.verify()
    assert "TAIL_TRUNCATED" in _codes(v)


async def test_object_deleted(ledger):
    evs = await _fill(ledger)
    (ledger.root / evs[0].object_path).unlink()
    assert "OBJECT_MISSING" in _codes(await ledger.verify())


async def test_candidate_scoped_verify(ledger):
    evs = await _fill(ledger)
    (ledger.root / evs[0].object_path).write_bytes(b"x")  # cand_0
    assert not (await ledger.verify("cand_0")).ok
    assert (await ledger.verify("cand_1")).ok


async def test_signer_refuses_resign(signer_client):
    await signer_client.sign(1, "a" * 64)
    from safetrace.evidence.signer_client import SignerError

    with pytest.raises(SignerError):
        await signer_client.sign(1, "b" * 64)  # 기존 seq 재서명 금지
    with pytest.raises(SignerError):
        await signer_client.sign(5, "b" * 64)  # 건너뛰기 금지


async def test_signer_requires_token(signer_core):
    import httpx

    from safetrace.signer.app import create_app

    app = create_app(signer_core, "t" * 32)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://s") as c:
        r = await c.post("/v1/sign", json={"seq": 1, "record_hash": "a" * 64})
        assert r.status_code == 401
        r = await c.post("/v1/sign", json={"seq": 1, "record_hash": "a" * 64},
                         headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401


def test_object_paths_are_server_generated(ledger):
    with pytest.raises(ValueError):
        ledger._object_path("../etc", "ev_1", EvidenceType.HTML)
