"""로컬 다국어 제로샷 분류(선택). 원문을 외부로 보내지 않고, 모델·리비전을 고정한다.

프롬프트 인젝션 대응: 페이지 텍스트는 분류 입력(데이터)으로만 쓰이고, 모델은 고정된 가설 집합에 대한
점수만 낸다. 생성·도구 실행 경로가 없으므로 페이지 문구가 출력 형식이나 권한을 바꿀 수 없다.
"""

from __future__ import annotations

import logging
from typing import Protocol

from safetrace.schemas import ThreatType

log = logging.getLogger(__name__)

DEFAULT_MODEL = "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7"
DEFAULT_REVISION = "b5113eb38ab63efdd7f280f8c144ea8b13f978ce"  # 2026-09-24 검증한 커밋
HYPOTHESES: dict[ThreatType, str] = {
    ThreatType.PHISHING: "이 웹페이지는 기관이나 회사를 사칭해 로그인 정보나 개인정보를 입력하게 한다.",
    ThreatType.SCAM: "이 웹페이지는 고수익 투자, 당첨, 환불 등을 미끼로 돈을 보내게 한다.",
    ThreatType.ILLEGAL_GAMBLING_SUSPECTED: "이 웹페이지는 카지노, 스포츠 베팅 등 온라인 도박 사이트다.",
    ThreatType.MALWARE: "이 웹페이지는 앱이나 프로그램을 설치하거나 파일을 내려받게 한다.",
}
MAX_CHARS = 1500


class TextClassifier(Protocol):
    name: str
    revision: str

    def classify(self, text: str) -> dict[ThreatType, float]: ...


class HFZeroShot:
    """transformers zero-shot-classification 파이프라인. 모델 파일은 로컬 캐시에서 로드한다."""

    def __init__(self, model: str = DEFAULT_MODEL, revision: str = DEFAULT_REVISION, device: int = -1) -> None:
        from transformers import pipeline  # 선택 의존성

        self.name = model
        self.revision = revision
        self._pipe = pipeline("zero-shot-classification", model=model, revision=revision, device=device)

    def classify(self, text: str) -> dict[ThreatType, float]:
        text = text[:MAX_CHARS].strip()
        if not text:
            return {}
        labels = list(HYPOTHESES.values())
        out = self._pipe(text, candidate_labels=labels, hypothesis_template="{}", multi_label=True)
        by_label = dict(zip(out["labels"], out["scores"], strict=True))
        return {t: float(by_label[h]) for t, h in HYPOTHESES.items()}


def load_default() -> TextClassifier | None:
    try:
        return HFZeroShot()
    except Exception as exc:  # noqa: BLE001 - 모델 미설치·다운로드 불가 시 규칙 전용으로 동작
        log.warning("zero-shot model unavailable, rules-only mode: %s", type(exc).__name__)
        return None
