"""D1-R 라벨링: 표본 추출·블라인드·라벨 잠금·합의·kappa·스냅샷 재검증·권한·기능 스위치."""

import csv
import hashlib
import io
import json
from pathlib import Path

import httpx
import pytest

from safetrace.ai.engine import DecisionEngine
from safetrace.api.app import create_app
from safetrace.api.auth import TokenRegistry, token_hash
from safetrace.config import Settings
from safetrace.labeling.store import LabelingError, LabelStore, cohen_kappa, in_sample
from safetrace.pipeline.events import EventBus
from safetrace.pipeline.orchestrator import Orchestrator
from safetrace.reputation.safebrowsing import SafeBrowsingClient
from safetrace.security.url_policy import UrlPolicy

TOKENS = {"viewer-token": "vic:viewer", "a-token": "ann:investigator", "b-token": "ben:reviewer",
          "c-token": "cho:investigator", "bot-token": "bot:automation"}
PNG = b"\x89PNG\r\n\x1a\nfake-screenshot"


def H(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def make_snapshots(root: Path, n: int) -> list[str]:
    ids = []
    for i in range(n):
        sid = f"20260925-{i:012x}"
        d = root / "snapshots" / sid[:8] / sid
        d.mkdir(parents=True)
        (d / "screenshot.png").write_bytes(PNG)
        (d / "observation.json").write_text(json.dumps({
            "final_url": f"https://phish-{i}.example/login", "redirect_chain": [{}, {}],
            "dom_summary": {"title": f"로그인 {i}", "lang": "ko", "text_excerpt": "본인인증"},
            "forms": [{"has_password": True, "external_action": True}]}), encoding="utf-8")
        (d / "meta.json").write_text(json.dumps({
            "snapshot_id": sid, "source": "openphish", "url": f"https://phish-{i}.example/",
            "files": {"screenshot.png": hashlib.sha256(PNG).hexdigest()}}), encoding="utf-8")
        ids.append(sid)
    return ids


@pytest.fixture
async def env(ledger, site, tmp_path):
    ids = make_snapshots(tmp_path / "d1r", 4)
    orch = Orchestrator(ledger=ledger, engine=DecisionEngine(), bus=EventBus(),
                        policy=UrlPolicy(allow_hostports=frozenset({site})), safebrowsing=SafeBrowsingClient(""))
    reg = TokenRegistry({token_hash(t): spec for t, spec in TOKENS.items()})
    settings = Settings(env="test", labeling_enabled=True, d1r_dir=tmp_path / "d1r", labeling_sample_rate=1.0)
    app = create_app(settings, orchestrator=orch, registry=reg, inproc_worker=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api") as c:
            yield c, orch, ids, tmp_path / "d1r"


async def label(c, tok, sid, lab, reason=None):
    return await c.post(f"/api/labeling/items/{sid}/label", json={"label": lab, "exclude_reason": reason},
                        headers=H(tok))


def test_sampling_is_deterministic_and_close_to_rate():
    ids = [f"20260925-{i:012x}" for i in range(4000)]
    picked = [i for i in ids if in_sample(i, 0.5, "salt")]
    assert picked == [i for i in ids if in_sample(i, 0.5, "salt")]
    assert 0.46 < len(picked) / len(ids) < 0.54
    assert set(picked) != {i for i in ids if in_sample(i, 0.5, "other-salt")}


def test_cohen_kappa_known_values():
    assert cohen_kappa([]) is None
    assert cohen_kappa([("A", "A"), ("B", "B")]) == 1.0
    # po=0.7, pe=0.5 → 0.4
    pairs = [("A", "A")] * 4 + [("B", "B")] * 3 + [("A", "B")] * 2 + [("B", "A")]
    assert cohen_kappa(pairs) == pytest.approx(0.4)


async def test_disabled_by_default(ledger, site):
    orch = Orchestrator(ledger=ledger, engine=DecisionEngine(), bus=EventBus(), policy=UrlPolicy(),
                        safebrowsing=SafeBrowsingClient(""))
    reg = TokenRegistry({token_hash(t): spec for t, spec in TOKENS.items()})
    app = create_app(Settings(env="test"), orchestrator=orch, registry=reg, inproc_worker=False)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://api") as c:
            assert (await c.get("/api/labeling/summary", headers=H("a-token"))).status_code == 404


async def test_roles(env):
    c, *_ = env
    assert (await c.get("/api/labeling/summary")).status_code == 401
    assert (await c.get("/api/labeling/summary", headers=H("viewer-token"))).status_code == 403
    assert (await c.get("/api/labeling/summary", headers=H("bot-token"))).status_code == 403
    assert (await c.get("/api/labeling/summary", headers=H("a-token"))).status_code == 200


async def test_item_is_blinded_and_screenshot_verified(env):
    c, _, ids, root = env
    item = (await c.get(f"/api/labeling/items/{ids[0]}", headers=H("a-token"))).json()
    assert "source" not in item and "openphish" not in json.dumps(item)
    assert item["title"].startswith("로그인") and item["forms"][0]["has_password"] is True
    r = await c.get(f"/api/labeling/items/{ids[0]}/screenshot", headers=H("a-token"))
    assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content == PNG
    (root / "snapshots" / ids[0][:8] / ids[0] / "screenshot.png").write_bytes(PNG + b"x")
    r = await c.get(f"/api/labeling/items/{ids[0]}/screenshot", headers=H("a-token"))
    assert r.status_code == 409 and r.json()["error"] == "SNAPSHOT_TAMPERED"


@pytest.mark.parametrize("bad", ["..%2F..%2Fetc", "20260925-zzzzzzzzzzzz", "x" * 30])
async def test_invalid_snapshot_ids_rejected(env, bad):
    c, *_ = env
    r = await c.get(f"/api/labeling/items/{bad}/screenshot", headers=H("a-token"))
    assert r.status_code in (400, 404)


async def test_label_validation(env):
    c, _, ids, _ = env
    assert (await label(c, "a-token", ids[0], "NOPE")).status_code == 422
    assert (await label(c, "a-token", ids[0], "EXCLUDE")).status_code == 422  # 사유 필수
    assert (await label(c, "a-token", ids[0], "PHISHING", "PARKED")).status_code == 422


async def test_agreement_lock_consensus_and_export(env):
    c, orch, ids, _ = env
    s0, s1, s2 = ids[:3]
    # s0: 일치, s1: 불일치 → 합의, s2: 한 명만(대기)
    assert (await label(c, "a-token", s0, "PHISHING")).status_code == 200
    assert (await label(c, "b-token", s0, "PHISHING")).status_code == 200
    assert (await label(c, "a-token", s1, "PHISHING")).status_code == 200
    assert (await label(c, "a-token", s1, "SCAM")).status_code == 200  # 상대가 아직 안 했으면 수정 가능
    assert (await label(c, "b-token", s1, "EXCLUDE", "PARKED")).status_code == 200
    assert (await label(c, "a-token", s2, "BENIGN")).status_code == 200

    # 두 명 완료 후 개별 라벨 잠금, 세 번째 사용자 거부
    r = await label(c, "a-token", s0, "SCAM")
    assert r.status_code == 409 and r.json()["error"] == "LOCKED"
    r = await label(c, "c-token", s2, "BENIGN")
    assert r.status_code == 403 and r.json()["error"] == "NOT_A_LABELER"

    # 블라인드: 대기 중 항목은 상대 라벨이 어디에도 없다
    q = (await c.get("/api/labeling/queue", headers=H("b-token"))).json()
    row = next(x for x in q if x["snapshot_id"] == s2)
    assert row["my_label"] is None and row["locked"] is False and "BENIGN" not in json.dumps(row)
    dis = (await c.get("/api/labeling/disagreements", headers=H("b-token"))).json()
    assert [d["snapshot_id"] for d in dis] == [s1]
    assert {x["label"] for x in dis[0]["labels"]} == {"SCAM", "EXCLUDE"}

    # 합의는 불일치 건만, 근거 필수
    r = await c.post(f"/api/labeling/items/{s0}/consensus", json={"label": "SCAM", "note": "합의 테스트"},
                     headers=H("a-token"))
    assert r.status_code == 409
    r = await c.post(f"/api/labeling/items/{s1}/consensus", json={"label": "SCAM", "note": "x"}, headers=H("a-token"))
    assert r.status_code == 422
    r = await c.post(f"/api/labeling/items/{s1}/consensus", json={"label": "SCAM", "note": "입금 유도 문구 확인"},
                     headers=H("b-token"))
    assert r.status_code == 200

    s = (await c.get("/api/labeling/summary", headers=H("a-token"))).json()
    assert s["labelers"] == ["ann", "ben"] and s["both_labeled"] == 2
    assert s["outcomes"] == {"PENDING": 2, "AGREED": 1, "DISAGREED": 0, "CONSENSUS": 1}
    assert s["percent_agreement"] == 0.5 and s["final_by_label"] == {"PHISHING": 1, "SCAM": 1}

    r = await c.get("/api/labeling/export", headers=H("a-token"))
    rows = {x["snapshot_id"]: x for x in csv.DictReader(io.StringIO(r.text))}
    assert set(rows) == {s0, s1}
    assert rows[s0]["final_label"] == "PHISHING" and rows[s0]["agreement"] == "AGREED"
    assert rows[s1]["final_label"] == "SCAM" and rows[s1]["agreement"] == "CONSENSUS"
    assert rows[s1]["label_b"] == "EXCLUDE:PARKED"
    assert {a.action for a in orch.audit} >= {"labeling.label", "labeling.consensus", "labeling.export"}


def test_exclusion_agreed_is_exported_as_excluded(tmp_path):
    ids = make_snapshots(tmp_path, 1)
    st = LabelStore(tmp_path, 1.0, "s")
    st.add_label(ids[0], "ann", "EXCLUDE", "DOWN_OR_ERROR", "")
    st.add_label(ids[0], "ben", "EXCLUDE", "DOWN_OR_ERROR", "")
    [row] = st.rows()
    assert row["final_label"] == "" and row["excluded_reason"] == "DOWN_OR_ERROR" and row["agreement"] == "AGREED"


def test_fixed_labelers_and_unsampled_hidden(tmp_path):
    ids = make_snapshots(tmp_path, 40)
    st = LabelStore(tmp_path, 0.5, "s", labelers=["ann", "ben"])
    with pytest.raises(LabelingError) as e:
        st.add_label(st.sample_ids()[0], "cho", "BENIGN", None, "")
    assert e.value.code == "NOT_A_LABELER"
    hidden = next(i for i in ids if i not in st.sample_ids())
    with pytest.raises(LabelingError) as e:
        st.blinded_item(hidden)
    assert e.value.code == "NOT_FOUND"


def test_collector_error_snapshots_excluded(tmp_path):
    ids = make_snapshots(tmp_path, 3)
    obs = tmp_path / "snapshots" / ids[0][:8] / ids[0] / "observation.json"
    obs.write_text(json.dumps({"dom_summary": {"text_excerpt": "SafeTrace egress denied: UPSTREAM_CONNECT_FAILED"}}),
                   encoding="utf-8")
    st = LabelStore(tmp_path, 1.0, "s")
    assert ids[0] not in st.sample_ids() and len(st.sample_ids()) == 2
    assert st.summary("ann")["collector_errors"] == 1 and st.summary("ann")["total_snapshots"] == 3
    with pytest.raises(LabelingError):
        st.add_label(ids[0], "ann", "BENIGN", None, "")
