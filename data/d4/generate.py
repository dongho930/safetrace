"""D4 자율 후보 발굴 시험 사이트군 생성기(docs/08 §D4, R8).

구성: Seed 10개 × 설계된 연관 후보 5개 = 50개(깊이 1: 40, 깊이 2: 10).
연결 유형: LINK / REDIRECT(지연 meta refresh) / FORM_ACTION / SCRIPT 를 섞고, 다음 함정을 넣는다.
  - 허용목록 정상 도메인(사칭 대상) 링크 → 재큐잉 0 이어야 함
  - 공용 CDN 스크립트 → 감점으로 재큐잉되지 않아야 함
  - Seed 로 되돌아가는 순환 링크·같은 URL 중복 링크 → 중복 조사 0
  - 같은 사이트 내부 잡음 링크 다수 → 도메인 예산으로 제한
호스트는 <이름>.test(예약 TLD, 호스트마다 별도 등록 도메인)이며,
평가 하네스는 시험 전용 egress 프록시가 이 이름만 로컬 서버로 연결한다.
출력: site/<host>/index.html, graph.json(정답 키)
"""

from __future__ import annotations

import json
import random
import shutil
from pathlib import Path

OUT = Path(__file__).resolve().parent
SITE = OUT / "site"
VERSION = "d4-1.0"
rng = random.Random(20261005)
BRANDS = ["kbstar", "wooribank", "hometax", "epost", "cjlogistics", "tworld", "kakaobank", "shinhancard",
          "nhis", "coupang"]
OFFICIAL = {"kbstar": "https://www.kbstar.com/", "wooribank": "https://www.wooribank.com/",
            "hometax": "https://www.hometax.go.kr/", "epost": "https://www.epost.go.kr/",
            "cjlogistics": "https://www.cjlogistics.com/", "tworld": "https://www.tworld.co.kr/",
            "kakaobank": "https://www.kakaobank.com/", "shinhancard": "https://www.shinhancard.com/",
            "nhis": "https://www.nhis.or.kr/", "coupang": "https://www.coupang.com/"}


def html(title: str, body: str, head: str = "") -> str:
    return f"<!doctype html><html lang='ko'><head><meta charset='utf-8'><title>{title}</title>{head}</head>" \
           f"<body>{body}</body></html>"


def write(host: str, content: str, path: str = "index.html") -> None:
    d = SITE / host
    d.mkdir(parents=True, exist_ok=True)
    (d / path).write_text(content, encoding="utf-8")


def build() -> None:
    if SITE.exists():
        shutil.rmtree(SITE)
    graph = {"version": VERSION, "seeds": [], "designed": [], "decoys": []}
    for s, brand in enumerate(BRANDS, 1):
        seed = f"{brand}-verify{s:02d}.test"
        graph["seeds"].append(f"http://{seed}/")
        d1 = [f"{brand}-{k}{s:02d}.test" for k in ("pay", "login", "cdn-kit", "otp")]
        d2_parent = d1[0]
        d2 = f"{brand}-collect{s:02d}.test"
        # 깊이 1: LINK·REDIRECT(지연 meta refresh)·FORM_ACTION·SCRIPT, 깊이 2: d1[0] 에서 FORM_ACTION
        rels = ["LINK", "REDIRECT", "FORM_ACTION", "SCRIPT"]
        for host, rel in zip(d1, rels, strict=True):
            graph["designed"].append({"url": f"http://{host}/", "depth": 1, "relation": rel, "from": seed})
        graph["designed"].append({"url": f"http://{d2}/", "depth": 2, "relation": "FORM_ACTION", "from": d2_parent})

        noise = "".join(f"<a href='/notice{i}.html'>공지{i}</a>" for i in range(8))  # 같은 사이트 잡음
        seed_body = (
            f"<h1>{brand.upper()} 본인확인</h1><p>계정 보호를 위해 본인인증이 필요합니다.</p>"
            f"<a href='http://{d1[0]}/'>결제 확인</a>"
            f"<a href='http://{d1[0]}/'>결제 확인(중복)</a>"
            f"<form action='http://{d1[2]}/submit' method='post'><input type='password' name='pw'></form>"
            f"<script src='http://{d1[3]}/kit.js'></script>"
            f"<script src='https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js'></script>"
            f"<a href='{OFFICIAL[brand]}'>공식 홈페이지</a><a href='https://www.gov.kr/'>정부24</a>"
            f"<a href='http://{seed}/'>처음으로(순환)</a>{noise}"
        )
        # 30초 뒤 이동하는 meta refresh: 조사 시간(settle) 안에는 따라가지 않지만 REDIRECT 관계로 관찰된다.
        write(seed, html(f"{brand} 인증", seed_body, head=f"<meta http-equiv='refresh' content='30;url=http://{d1[1]}/'>"))
        for i in range(8):
            write(seed, html("공지", "<p>공지</p>"), f"notice{i}.html")
        write(d1[0], html("결제", f"<p>결제 정보를 입력하세요.</p><form action='http://{d2}/collect' method='post'>"
                                f"<input name='cardno' placeholder='카드번호'><input name='cvc'></form>"
                                f"<a href='http://{seed}/'>되돌아가기(순환)</a>"))
        write(d1[1], html("로그인", "<p>로그인</p><form><input type='password' name='pw'></form>"))
        write(d1[2], html("제출", "<p>처리 중</p>"))
        write(d1[3], "", "kit.js")
        write(d1[3], html("kit", "<p>kit</p>"))
        write(d2, html("수집", "<p>완료</p>"))
        graph["decoys"] += [
            {"url": OFFICIAL[brand], "expect": "IMPERSONATES_NOT_REQUEUED"},
            {"url": "https://www.gov.kr/", "expect": "IMPERSONATES_NOT_REQUEUED"},
            {"url": "https://cdn.jsdelivr.net/npm/jquery@3/dist/jquery.min.js", "expect": "NOT_REQUEUED"},
            {"url": f"http://{seed}/", "expect": "DUPLICATE_NOT_REINVESTIGATED"},
        ]
    assert len(graph["seeds"]) == 10 and len(graph["designed"]) == 50
    graph["pass_criteria"] = {"designed_found_min": 40, "allowlisted_requeued": 0, "budget_exceeded": 0,
                              "duplicate_investigations": 0}
    (OUT / "graph.json").write_text(json.dumps(graph, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{VERSION}: seeds={len(graph['seeds'])} designed={len(graph['designed'])} decoys={len(graph['decoys'])}")


if __name__ == "__main__":
    build()
