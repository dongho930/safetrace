"""D1-R 라벨 저장소. 동결 스냅샷(data/d1r/snapshots)은 읽기만 하고, 라벨은 labels/events.jsonl 에 추가만 한다.

- 표본: SHA-256(salt + snapshot_id) 기반 결정적 추출. 수집되는 대로 표본이 늘고,
  같은 스냅샷의 포함 여부는 바뀌지 않는다.
- 라벨러: 설정된 2명(비어 있으면 처음 라벨을 남긴 2명). 3번째 사용자는 라벨을 남길 수 없다.
- 독립성: 두 명이 모두 라벨을 남긴 스냅샷의 개별 라벨은 잠긴다(kappa 는 합의 전 독립 라벨로 계산).
  불일치 건은 합의 라벨(CONSENSUS)로만 최종 라벨이 정해진다.
- 블라인드: 라벨 화면에는 피드 출처·AI 판정·상대 라벨을 주지 않는다. 상대 라벨은 불일치 합의 목록에서만 보인다.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import threading
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

SNAPSHOT_ID = re.compile(r"^\d{8}-[0-9a-f]{12}$")
EVENTS_FILE = "events.jsonl"
# 수집기 결함(2026-09-25 수정 전): 평문 HTTP 접속 실패 시 egress 프록시 거부 응답이 페이지로 저장된 스냅샷
EGRESS_ERROR_PREFIX = "SafeTrace egress denied:"
CSV_FIELDS = ["snapshot_id", "label_a", "label_b", "final_label", "excluded_reason", "note", "agreement"]


class Label(StrEnum):
    PHISHING = "PHISHING"
    SCAM = "SCAM"
    ILLEGAL_GAMBLING_SUSPECTED = "ILLEGAL_GAMBLING_SUSPECTED"
    MALWARE = "MALWARE"
    OTHER = "OTHER"
    BENIGN = "BENIGN"
    EXCLUDE = "EXCLUDE"


class ExcludeReason(StrEnum):
    PARKED = "PARKED"  # 주차 도메인
    DOWN_OR_ERROR = "DOWN_OR_ERROR"  # 삭제·오류·빈 페이지
    UNSURE = "UNSURE"  # 판단 불가


class Outcome(StrEnum):
    PENDING = "PENDING"  # 두 명 중 한 명 이하 완료
    AGREED = "AGREED"
    DISAGREED = "DISAGREED"  # 합의 대기
    CONSENSUS = "CONSENSUS"


class LabelingError(Exception):
    def __init__(self, code: str, http_status: int) -> None:
        super().__init__(code)
        self.code, self.http_status = code, http_status


@dataclass(frozen=True)
class Vote:
    label: Label
    exclude_reason: ExcludeReason | None
    note: str
    user: str
    ts: str

    def key(self) -> tuple[Label, ExcludeReason | None]:
        return self.label, self.exclude_reason if self.label == Label.EXCLUDE else None


def in_sample(snapshot_id: str, rate: float, salt: str) -> bool:
    h = hashlib.sha256(f"{salt}:{snapshot_id}".encode()).digest()
    return int.from_bytes(h[:8], "big") / 2**64 < rate


def sample_order(snapshot_id: str, salt: str) -> str:
    """피드·수집 순서와 무관한 제시 순서(출처별로 몰려 나오지 않게)."""
    return hashlib.sha256(f"{salt}:order:{snapshot_id}".encode()).hexdigest()


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    n = len(pairs)
    if n == 0:
        return None
    po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in ca.keys() | cb.keys()) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def _vote_value(v: Vote) -> str:
    return f"EXCLUDE:{v.exclude_reason}" if v.label == Label.EXCLUDE else v.label.value


class LabelStore:
    def __init__(self, root: Path, sample_rate: float, salt: str, labelers: list[str] | None = None) -> None:
        self.root = root
        self.snap_dir = root / "snapshots"
        self.events_path = root / "labels" / EVENTS_FILE
        self.rate, self.salt = sample_rate, salt
        self.fixed_labelers = [u for u in (labelers or []) if u][:2]
        self._lock = threading.Lock()
        self._collector_error: dict[str, bool] = {}  # 동결 스냅샷이라 한 번 읽으면 바뀌지 않는다

    # ───────────── 스냅샷 ─────────────

    def _snap_path(self, snapshot_id: str) -> Path:
        if not SNAPSHOT_ID.fullmatch(snapshot_id):
            raise LabelingError("INVALID_SNAPSHOT_ID", 400)
        return self.snap_dir / snapshot_id[:8] / snapshot_id

    def meta(self, snapshot_id: str) -> dict:
        p = self._snap_path(snapshot_id) / "meta.json"
        if not p.is_file() or not in_sample(snapshot_id, self.rate, self.salt) or self.is_collector_error(snapshot_id):
            raise LabelingError("NOT_FOUND", 404)
        return json.loads(p.read_text(encoding="utf-8"))

    def is_collector_error(self, snapshot_id: str) -> bool:
        if snapshot_id not in self._collector_error:
            p = self._snap_path(snapshot_id) / "observation.json"
            text = ""
            if p.is_file():
                text = (json.loads(p.read_text(encoding="utf-8")).get("dom_summary") or {}).get("text_excerpt") or ""
            self._collector_error[snapshot_id] = text.startswith(EGRESS_ERROR_PREFIX)
        return self._collector_error[snapshot_id]

    def _all_ids(self) -> list[str]:
        return [p.parent.name for p in self.snap_dir.glob("*/*/meta.json") if SNAPSHOT_ID.fullmatch(p.parent.name)]

    def sample_ids(self) -> list[str]:
        ids = (i for i in self._all_ids() if in_sample(i, self.rate, self.salt) and not self.is_collector_error(i))
        return sorted(ids, key=lambda i: sample_order(i, self.salt))

    def total_snapshots(self) -> int:
        return len(self._all_ids())

    def blinded_item(self, snapshot_id: str) -> dict:
        """라벨 화면용. 피드 출처(source)·AI 판정은 넣지 않는다."""
        meta = self.meta(snapshot_id)
        obs_path = self._snap_path(snapshot_id) / "observation.json"
        obs = json.loads(obs_path.read_text(encoding="utf-8")) if obs_path.is_file() else {}
        dom = obs.get("dom_summary") or {}
        forms = obs.get("forms") or []
        return {
            "snapshot_id": snapshot_id,
            "collected_day": snapshot_id[:8],
            "url": meta.get("url", ""),
            "final_url": obs.get("final_url") or meta.get("final_url", ""),
            "title": dom.get("title", ""),
            "lang": dom.get("lang", ""),
            "text_excerpt": (dom.get("text_excerpt") or "")[:600],
            "redirects": len(obs.get("redirect_chain") or []),
            "downloads_blocked": obs.get("downloads_blocked", 0),
            "forms": [{k: bool(f.get(k)) for k in ("has_password", "has_card_like", "has_phone",
                                                    "has_id_number_like", "external_action")} for f in forms[:10]],
            "has_screenshot": "screenshot.png" in (meta.get("files") or {}),
        }

    def screenshot(self, snapshot_id: str) -> bytes:
        meta = self.meta(snapshot_id)
        expected = (meta.get("files") or {}).get("screenshot.png")
        p = self._snap_path(snapshot_id) / "screenshot.png"
        if not expected or not p.is_file():
            raise LabelingError("NOT_FOUND", 404)
        data = p.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:  # 동결 시 기록한 해시로 재검증
            raise LabelingError("SNAPSHOT_TAMPERED", 409)
        return data

    # ───────────── 라벨 이벤트 ─────────────

    def _events(self) -> list[dict]:
        if not self.events_path.is_file():
            return []
        return [json.loads(ln) for ln in self.events_path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def _append(self, event: dict) -> None:
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.events_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _state(self) -> tuple[list[str], dict[str, dict[str, Vote]], dict[str, Vote]]:
        labelers = list(self.fixed_labelers)
        votes: dict[str, dict[str, Vote]] = {}
        consensus: dict[str, Vote] = {}
        for e in self._events():
            v = Vote(Label(e["label"]), ExcludeReason(e["exclude_reason"]) if e.get("exclude_reason") else None,
                     e.get("note", ""), e["user"], e["ts"])
            if e["kind"] == "label":
                if not self.fixed_labelers and e["user"] not in labelers and len(labelers) < 2:
                    labelers.append(e["user"])
                votes.setdefault(e["snapshot_id"], {})[e["user"]] = v
            elif e["kind"] == "consensus":
                consensus[e["snapshot_id"]] = v
        return labelers, votes, consensus

    @staticmethod
    def _outcome(labelers: list[str], mine: dict[str, Vote], cons: Vote | None) -> Outcome:
        both = [mine.get(u) for u in labelers]
        if len(labelers) < 2 or None in both:
            return Outcome.PENDING
        if both[0].key() == both[1].key():  # type: ignore[union-attr]
            return Outcome.AGREED
        return Outcome.CONSENSUS if cons else Outcome.DISAGREED

    def _validate(self, label: str, exclude_reason: str | None) -> tuple[Label, ExcludeReason | None]:
        try:
            lab = Label(label)
            reason = ExcludeReason(exclude_reason) if exclude_reason else None
        except ValueError:
            raise LabelingError("INVALID_LABEL", 422) from None
        if (lab == Label.EXCLUDE) != (reason is not None):
            raise LabelingError("EXCLUDE_REASON_REQUIRED" if lab == Label.EXCLUDE else "UNEXPECTED_REASON", 422)
        return lab, reason

    def add_label(self, snapshot_id: str, user: str, label: str, exclude_reason: str | None, note: str) -> Vote:
        self.meta(snapshot_id)
        lab, reason = self._validate(label, exclude_reason)
        with self._lock:
            labelers, votes, _ = self._state()
            if user not in labelers and len(labelers) >= 2:
                raise LabelingError("NOT_A_LABELER", 403)
            mine = votes.get(snapshot_id, {})
            others = [u for u in labelers if u != user]
            if user in mine and others and others[0] in mine:
                raise LabelingError("LOCKED", 409)  # 두 명 모두 완료 → 합의로만 변경
            ts = datetime.now(UTC).isoformat()
            self._append({"kind": "label", "snapshot_id": snapshot_id, "user": user, "label": lab.value,
                          "exclude_reason": reason.value if reason else None, "note": note, "ts": ts})
        return Vote(lab, reason, note, user, ts)

    def add_consensus(self, snapshot_id: str, user: str, label: str, exclude_reason: str | None, note: str) -> Vote:
        self.meta(snapshot_id)
        lab, reason = self._validate(label, exclude_reason)
        with self._lock:
            labelers, votes, cons = self._state()
            if user not in labelers:
                raise LabelingError("NOT_A_LABELER", 403)
            if self._outcome(labelers, votes.get(snapshot_id, {}), cons.get(snapshot_id)) not in (
                    Outcome.DISAGREED, Outcome.CONSENSUS):
                raise LabelingError("NOT_DISAGREED", 409)
            ts = datetime.now(UTC).isoformat()
            self._append({"kind": "consensus", "snapshot_id": snapshot_id, "user": user, "label": lab.value,
                          "exclude_reason": reason.value if reason else None, "note": note, "ts": ts})
        return Vote(lab, reason, note, user, ts)

    # ───────────── 조회 ─────────────

    def queue(self, user: str) -> list[dict]:
        labelers, votes, cons = self._state()
        out = []
        for sid in self.sample_ids():
            mine = votes.get(sid, {})
            v = mine.get(user)
            out.append({"snapshot_id": sid, "my_label": v.label.value if v else None,
                        "my_exclude_reason": v.exclude_reason.value if v and v.exclude_reason else None,
                        "locked": self._outcome(labelers, mine, cons.get(sid)) != Outcome.PENDING})
        return out

    def disagreements(self, user: str) -> list[dict]:
        labelers, votes, cons = self._state()
        if user not in labelers:
            raise LabelingError("NOT_A_LABELER", 403)
        out = []
        for sid in self.sample_ids():
            mine = votes.get(sid, {})
            outcome = self._outcome(labelers, mine, cons.get(sid))
            if outcome not in (Outcome.DISAGREED, Outcome.CONSENSUS):
                continue
            c = cons.get(sid)
            out.append({
                "snapshot_id": sid, "outcome": outcome.value,
                "labels": [{"user": u, "label": mine[u].label.value,
                            "exclude_reason": mine[u].exclude_reason.value if mine[u].exclude_reason else None,
                            "note": mine[u].note} for u in labelers],
                "consensus": {"label": c.label.value, "exclude_reason": c.exclude_reason.value if c.exclude_reason
                              else None, "note": c.note, "user": c.user} if c else None,
            })
        return out

    def rows(self) -> list[dict]:
        """labels.csv 행. 최종 라벨이 정해진(AGREED·CONSENSUS) 스냅샷만."""
        labelers, votes, cons = self._state()
        rows = []
        for sid in sorted(self.sample_ids()):
            mine = votes.get(sid, {})
            outcome = self._outcome(labelers, mine, cons.get(sid))
            if outcome not in (Outcome.AGREED, Outcome.CONSENSUS):
                continue
            final = cons[sid] if outcome == Outcome.CONSENSUS else mine[labelers[0]]
            excluded = final.label == Label.EXCLUDE
            rows.append({
                "snapshot_id": sid,
                "label_a": _vote_value(mine[labelers[0]]), "label_b": _vote_value(mine[labelers[1]]),
                "final_label": "" if excluded else final.label.value,
                "excluded_reason": final.exclude_reason.value if excluded and final.exclude_reason else "",
                "note": final.note if outcome == Outcome.CONSENSUS else "", "agreement": outcome.value,
            })
        return rows

    def export_csv(self) -> str:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(self.rows())
        return buf.getvalue()

    def summary(self, user: str) -> dict:
        labelers, votes, cons = self._state()
        sample = self.sample_ids()
        outcomes = Counter(self._outcome(labelers, votes.get(s, {}), cons.get(s)).value for s in sample)
        pairs = [(_vote_value(votes[s][labelers[0]]), _vote_value(votes[s][labelers[1]])) for s in sample
                 if len(labelers) == 2 and all(u in votes.get(s, {}) for u in labelers)]
        rows = self.rows()
        kappa = cohen_kappa(pairs)
        return {
            "sample_rate": self.rate, "total_snapshots": self.total_snapshots(), "sample_size": len(sample),
            "collector_errors": sum(1 for i in self._all_ids() if self.is_collector_error(i)),
            "labelers": labelers, "is_labeler": user in labelers or len(labelers) < 2,
            "done_by": {u: sum(1 for s in sample if u in votes.get(s, {})) for u in labelers},
            "outcomes": {o.value: outcomes.get(o.value, 0) for o in Outcome},
            "both_labeled": len(pairs),
            "percent_agreement": round(sum(a == b for a, b in pairs) / len(pairs), 4) if pairs else None,
            "kappa": round(kappa, 4) if kappa is not None else None,
            "final_by_label": dict(Counter(r["final_label"] for r in rows if r["final_label"])),
            "excluded_by_reason": dict(Counter(r["excluded_reason"] for r in rows if r["excluded_reason"])),
        }
