"""D1-R 라벨링 API(/api/labeling/*). 평가용 기능이므로 SAFETRACE_LABELING_ENABLED=1 일 때만 등록한다.

- investigator·reviewer 만 사용. 스냅샷은 스크린샷 PNG(해시 재검증)와 요약 필드만 내보내고 수집 HTML 은 보내지 않는다.
- 라벨·합의는 labels/events.jsonl 에 추가되고 감사 로그에도 남는다.
"""


import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from safetrace.api.auth import Principal, Role, require
from safetrace.labeling.store import LabelingError, LabelStore

LABELERS = (Role.INVESTIGATOR, Role.REVIEWER)


class LabelIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Annotated[str, Field(max_length=40)]
    exclude_reason: Annotated[str | None, Field(max_length=20)] = None
    note: Annotated[str, Field(max_length=500)] = ""


class ConsensusIn(LabelIn):
    note: Annotated[str, Field(min_length=5, max_length=500)]  # 합의 근거는 필수


def labeling_error_response(exc: LabelingError) -> JSONResponse:
    return JSONResponse({"error": exc.code}, status_code=exc.http_status)


def build_router(store: LabelStore) -> APIRouter:
    r = APIRouter(prefix="/api/labeling")
    User = Annotated[Principal, Depends(require(*LABELERS))]

    def audit(request: Request, p: Principal, action: str, target: str, detail: str = "") -> None:
        request.app.state.orch.record_audit(f"{p.role.value}:{p.user_id}", action, target, detail=detail)

    @r.get("/summary")
    async def summary(p: User):
        return await asyncio.to_thread(store.summary, p.user_id)

    @r.get("/queue")
    async def queue(p: User):
        return await asyncio.to_thread(store.queue, p.user_id)

    @r.get("/items/{snapshot_id}")
    async def item(snapshot_id: str, _: User):
        return await asyncio.to_thread(store.blinded_item, snapshot_id)

    @r.get("/items/{snapshot_id}/screenshot")
    async def screenshot(snapshot_id: str, _: User):
        data = await asyncio.to_thread(store.screenshot, snapshot_id)
        return Response(data, media_type="image/png", headers={"Content-Disposition": "inline"})

    @r.post("/items/{snapshot_id}/label")
    async def label(snapshot_id: str, body: LabelIn, request: Request, p: User):
        v = await asyncio.to_thread(store.add_label, snapshot_id, p.user_id, body.label, body.exclude_reason,
                                    body.note)
        audit(request, p, "labeling.label", snapshot_id)
        return {"snapshot_id": snapshot_id, "label": v.label, "exclude_reason": v.exclude_reason}

    @r.get("/disagreements")
    async def disagreements(p: User):
        return await asyncio.to_thread(store.disagreements, p.user_id)

    @r.post("/items/{snapshot_id}/consensus")
    async def consensus(snapshot_id: str, body: ConsensusIn, request: Request, p: User):
        v = await asyncio.to_thread(store.add_consensus, snapshot_id, p.user_id, body.label, body.exclude_reason,
                                    body.note)
        audit(request, p, "labeling.consensus", snapshot_id)
        return {"snapshot_id": snapshot_id, "label": v.label, "exclude_reason": v.exclude_reason}

    @r.get("/export")
    async def export(request: Request, p: User):
        text = await asyncio.to_thread(store.export_csv)
        audit(request, p, "labeling.export", "labels.csv")
        return Response(text, media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="labels.csv"'})

    return r
