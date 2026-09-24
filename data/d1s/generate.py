"""D1-S 합성 시험 페이지 생성기(docs/08_evaluation_plan.md §D1-S).

가상 피싱·사기·도박 의심 페이지 각 20개 + 정상 대조 30개. 변형:
  plain      정적 렌더링
  delayed    핵심 징후(폼·문구)를 1.5초 뒤 JS 로 삽입(정적 HTML 기준선이 놓치는 경우)
  redirect   2~3단계 HTTP 리다이렉트 후 최종 페이지
  jsredirect meta refresh / location.replace 로 최종 페이지 이동

출력: site/ (정적 파일), routes.json (HTTP 리다이렉트 표), labels.csv (정답·회피 징후)
모든 브랜드·기관명은 가상이거나 일반 명칭이며 실제 서비스의 로고·디자인을 복제하지 않는다.
결정적 생성(seed 고정)이므로 같은 버전은 항상 같은 결과를 낸다.
"""

from __future__ import annotations

import csv
import html
import json
import random
import shutil
from pathlib import Path

OUT = Path(__file__).resolve().parent
SITE = OUT / "site"
VERSION = "d1s-1.0"
rng = random.Random(20261005)

ORGS = ["국민건강보험공단", "국세청 홈택스", "우체국 택배", "정부24", "경찰청 사이버수사", "통신사 유심센터",
        "가상은행", "하늘카드", "바다은행", "도시가스공사"]
PHISH_LINES = [
    "환급금 {amt}원이 확인되었습니다. 미확인 시 소멸됩니다.",
    "고객님의 계정이 일시 정지되었습니다. 즉시 본인인증을 진행하세요.",
    "택배 주소 불일치로 배송이 보류되었습니다. 배송비 결제 후 재배송됩니다.",
    "유심 무상 교체 대상입니다. 오늘까지 신청하지 않으면 서비스가 제한됩니다.",
    "과태료 미납 안내: 24시간 내 납부하지 않으면 압류 절차가 진행됩니다.",
]
SCAM_LINES = [
    "원금보장 고수익 투자! 월 수익률 {pct}% 리딩방 무료 입장",
    "이벤트 당첨을 축하합니다. 경품 수령을 위해 배송비 {amt}원을 입금해 주세요.",
    "저금리 대환대출 승인 완료. 보증금 선입금 후 즉시 지급됩니다.",
    "코인 무위험 재테크, 선착순 {n}명 한정 수익 보장",
]
GAMBLE_LINES = [
    "라이브카지노 바카라 슬롯 첫충 {pct}% 매충 10%",
    "스포츠토토 배팅 환전 빠른 사이트, 꽁머니 지급 이벤트",
    "파워볼 홀덤 무제한 롤링, 먹튀 없는 안전 충전",
]
BENIGN = [
    ("동네 빵집", "매일 아침 구운 식빵과 크루아상을 판매합니다. 영업시간은 오전 8시부터입니다."),
    ("시립 도서관 안내", "열람실 이용 시간과 도서 대출 규정을 안내합니다. 대출 기간은 14일입니다."),
    ("등산 동호회", "이번 달 정기 산행은 둘째 주 토요일입니다. 참가 신청은 게시판에 남겨 주세요."),
    ("개발 블로그", "파이썬 비동기 프로그래밍에서 이벤트 루프가 동작하는 방식을 정리했습니다."),
    ("요리 레시피", "된장찌개는 멸치 육수에 된장을 풀고 두부와 애호박을 넣어 끓입니다."),
    ("대학 학과 소식", "2학기 수강신청 일정과 졸업 요건 변경 사항을 공지합니다."),
    ("사진 갤러리", "지난 주말 한강 공원에서 촬영한 야경 사진을 공유합니다."),
    ("카페 메뉴", "시즌 한정 음료로 유자 에이드와 밤 라떼를 준비했습니다."),
    ("쇼핑몰 공지(정상)", "배송은 결제 후 2~3일 소요되며 회원가입 없이 주문 조회가 가능합니다."),
    ("회원 로그인(정상 대조)", "로그인 후 마이페이지에서 주문 내역을 확인할 수 있습니다."),
]


def page(title: str, body: str, *, delayed_html: str = "", head_extra: str = "") -> str:
    delayed = ""
    if delayed_html:
        delayed = ("<div id='late'></div><script>setTimeout(function(){document.getElementById('late').innerHTML="
                   f"{json.dumps(delayed_html)};}},1500);</script>")
    return (f"<!doctype html><html lang='ko'><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
            f"{head_extra}</head><body>{body}{delayed}</body></html>")


def phishing_form(external: bool) -> str:
    action = f"http://collect-{rng.randint(100, 999)}.example.xyz/submit" if external else "/submit"
    fields = rng.sample([
        "<input name='jumin' placeholder='주민등록번호 13자리'>",
        "<input type='password' name='pw' placeholder='비밀번호'>",
        "<input name='cardno' placeholder='카드번호'><input name='cvc' placeholder='CVC'>",
        "<input type='tel' name='phone' placeholder='휴대폰 번호'>",
        "<input name='otp' placeholder='인증번호'>",
    ], k=3)
    return f"<form action='{action}' method='post'>{''.join(fields)}<button>확인</button></form>"


def build() -> None:
    if SITE.exists():
        shutil.rmtree(SITE)
    SITE.mkdir(parents=True)
    routes: dict[str, str] = {}
    labels: list[dict[str, str]] = []
    variants = ["plain", "delayed", "redirect", "jsredirect"]

    def emit(pid: str, label: str, title: str, body: str, key_html: str, variant: str, signals: list[str]) -> None:
        if variant == "delayed":
            content = page(title, body, delayed_html=key_html)
            signals = signals + ["DELAYED_RENDER"]
        else:
            content = page(title, body + key_html)
        final = f"/p/{pid}.html"
        (SITE / "p").mkdir(exist_ok=True)
        (SITE / "p" / f"{pid}.html").write_text(content, encoding="utf-8")
        entry = final
        if variant == "redirect":
            hops = rng.randint(2, 3)
            prev = final
            for i in range(hops, 0, -1):
                src = f"/go/{pid}/{i}"
                routes[src] = prev
                prev = src
            entry = prev
            signals = signals + [f"HTTP_REDIRECT_{hops}"]
        elif variant == "jsredirect":
            entry = f"/j/{pid}.html"
            (SITE / "j").mkdir(exist_ok=True)
            how = rng.choice(["meta", "js"])
            head = f"<meta http-equiv='refresh' content='1;url={final}'>" if how == "meta" else ""
            body_js = "" if how == "meta" else f"<script>setTimeout(()=>location.replace('{final}'),700)</script>"
            (SITE / "j" / f"{pid}.html").write_text(page("잠시만 기다려 주세요", "<p>이동 중...</p>" + body_js,
                                                         head_extra=head), encoding="utf-8")
            signals = signals + ["CLIENT_REDIRECT"]
        labels.append({"page_id": pid, "label": label, "variant": variant, "entry_path": entry,
                       "final_path": final, "signals": "|".join(signals), "dataset_version": VERSION})

    for i in range(20):
        org = rng.choice(ORGS)
        line = rng.choice(PHISH_LINES).format(amt=f"{rng.randint(3, 90) * 1000:,}")
        external = rng.random() < 0.7
        emit(f"phish-{i:02d}", "PHISHING", f"{org} 안내", f"<h1>{org}</h1><p>{line}</p>",
             phishing_form(external), variants[i % 4],
             ["CREDENTIAL_FORM"] + (["EXTERNAL_FORM_ACTION"] if external else []))
    for i in range(20):
        line = rng.choice(SCAM_LINES).format(amt=f"{rng.randint(2, 30) * 1000:,}", pct=rng.randint(20, 300),
                                             n=rng.randint(10, 100))
        acct = f"<p>입금 계좌: 가상은행 {rng.randint(100, 999)}-{rng.randint(1000, 9999)}-{rng.randint(10, 99)}</p>"
        emit(f"scam-{i:02d}", "SCAM", "특별 혜택 안내", f"<h1>회원 전용 혜택</h1><p>{line}</p>",
             acct + "<form><input type='tel' name='phone' placeholder='연락처'></form>", variants[i % 4],
             ["MONEY_REQUEST"])
    for i in range(20):
        line = rng.choice(GAMBLE_LINES).format(pct=rng.randint(10, 50))
        emit(f"gamble-{i:02d}", "ILLEGAL_GAMBLING_SUSPECTED", "VIP 라운지", f"<h1>VIP 라운지</h1><p>{line}</p>",
             "<form><input name='uid'><input type='password' name='pw'><input name='bank'></form>", variants[i % 4],
             ["GAMBLING_TERMS"])
    for i in range(30):
        title, text = BENIGN[i % len(BENIGN)]
        extra = "<form action='/login' method='post'><input name='id'><input type='password' name='pw'></form>" \
            if "로그인" in title else ""
        emit(f"benign-{i:02d}", "BENIGN", title, f"<h1>{title}</h1><p>{text}</p>", extra,
             variants[i % 4] if i % 3 == 0 else "plain", [])

    items = "".join(f"<li><a href='{row['entry_path']}'>{row['page_id']}</a></li>" for row in labels)
    (SITE / "index.html").write_text(page("D1-S 시험 사이트 목록", f"<h1>D1-S {VERSION}</h1><ul>{items}</ul>"),
                                     encoding="utf-8")
    (OUT / "routes.json").write_text(json.dumps(routes, indent=1, sort_keys=True), encoding="utf-8")
    with open(OUT / "labels.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(labels[0].keys()))
        w.writeheader()
        w.writerows(labels)
    counts: dict[str, int] = {}
    for row in labels:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    print(f"{VERSION}: {len(labels)} pages {counts}, {len(routes)} redirect routes")


if __name__ == "__main__":
    build()
