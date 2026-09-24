import { useEffect, useState } from "react";
import { ApiError, downloadJson, evidenceBlobUrl, getJson, postJson } from "../api";
import { STATUS_LABEL, STATUS_TONE, THREAT_LABEL } from "../labels";
import type { Detail, Me } from "../types";

interface Props {
  candidateId: string; role: Me["role"]; tick: number; onClose: () => void; onChanged: () => void;
}

export default function DetailPanel({ candidateId, role, tick, onClose, onChanged }: Props) {
  const [d, setD] = useState<Detail | null>(null);
  const [shot, setShot] = useState<string>("");
  const [video, setVideo] = useState<string>("");
  const [integrity, setIntegrity] = useState<{ ok: boolean; issues: { code: string; seq: number }[] } | null>(null);
  const [focusEv, setFocusEv] = useState<string>("");

  useEffect(() => {
    let alive = true;
    getJson<Detail>(`/api/candidates/${encodeURIComponent(candidateId)}`)
      .then((x) => { if (alive) setD(x); })
      .catch(() => { if (alive) setD(null); });
    return () => { alive = false; };
  }, [candidateId, tick]);

  const shotId = d?.evidence.find((e) => e.type === "SCREENSHOT")?.evidence_id;
  const videoId = d?.evidence.find((e) => e.type === "VIDEO")?.evidence_id;
  useEffect(() => {
    let url = "";
    if (shotId) evidenceBlobUrl(shotId).then((u) => { url = u; setShot(u); }).catch(() => setShot(""));
    return () => { if (url) URL.revokeObjectURL(url); };
  }, [shotId]);

  async function loadVideo() {
    if (videoId) setVideo(await evidenceBlobUrl(videoId));
  }

  async function verify() {
    const pkg = await getJson<{ evidence: { integrity: { ok: boolean; issues: { code: string; seq: number }[] } } }>(
      `/api/candidates/${encodeURIComponent(candidateId)}/package`);
    setIntegrity(pkg.evidence.integrity);
  }

  if (!d) return <aside className="drawer"><button className="ghost close" onClick={onClose}>닫기</button><p>불러오는 중…</p></aside>;
  const c = d.candidate, o = d.observation, a = d.analysis;

  return (
    <aside className="drawer" aria-label="후보 상세">
      <div className="drawer-head">
        <div>
          <span className={`badge tone-${STATUS_TONE[c.status]}`}>{STATUS_LABEL[c.status]}</span>
          <h2 className="url" title={c.normalized_url}>{c.normalized_url}</h2>
          <p className="muted">{c.candidate_id} · 깊이 {c.depth} · 우선순위 {c.priority.toFixed(1)} · {c.relation}
            {c.status_reason && ` · ${c.status_reason}`}</p>
        </div>
        <button className="ghost close" onClick={onClose}>닫기</button>
      </div>

      <div className="drawer-body">
        <section>
          <h3>화면 증거</h3>
          {shot ? <img className="shot" src={shot} alt="수집된 스크린샷" /> : <p className="muted">스크린샷 없음</p>}
          {videoId && !video && <button className="ghost" onClick={() => void loadVideo()}>렌더링 녹화 보기</button>}
          {video && <video className="shot" src={video} controls muted />}
        </section>

        {a && (
          <section>
            <h3>AI 분석 의견 <span className={`badge ${a.state === "UNKNOWN" ? "tone-muted" : "tone-wait"}`}>{a.state}</span></h3>
            <p className="muted small">{a.state_reason}</p>
            {a.threat_types.map((t) => (
              <div key={t.type} className="threat">
                <div className="threat-head">
                  <strong>{THREAT_LABEL[t.type] ?? t.type}</strong>
                  <progress className="bar" max={1} value={t.confidence} aria-label="AI 신뢰도" />
                  <span className="conf">{t.confidence.toFixed(2)}</span>
                </div>
                <ul className="links">
                  {t.evidence_links.map((l, i) => (
                    <li key={i}>
                      <button className="linklike" onClick={() => setFocusEv(l.evidence_id)}>{l.evidence_id.slice(0, 12)}</button>
                      <code>{l.feature}</code> {l.reason}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            <p className="muted small">모델 {a.model_meta.model_version} · 규칙 해시 {a.model_meta.model_hash} · {a.model_meta.backend}</p>
          </section>
        )}

        {o && (
          <section>
            <h3>이동 경로</h3>
            <ol className="chain">
              {o.redirect_chain.map((h, i) => (
                <li key={i}><span className="kind">{h.kind}{h.status ? ` ${h.status}` : ""}</span><span className="url">{h.url}</span></li>
              ))}
            </ol>
            {o.final_url && <p className="small">최종 URL: <span className="url">{o.final_url}</span></p>}
            {o.policy_blocks.length > 0 && <p className="small warn">안전 정책 차단: {o.policy_blocks.join(", ")}</p>}
            <h3>입력 폼</h3>
            {o.forms.length === 0 ? <p className="muted small">관찰된 폼 없음</p> : (
              <ul className="forms">
                {o.forms.map((f, i) => (
                  <li key={i}>
                    <code>{f.method.toUpperCase()}</code> <span className="url">{f.action}</span>
                    <div className="flags">
                      {f.has_password && <span className="flag">비밀번호</span>}
                      {f.has_card_like && <span className="flag">카드</span>}
                      {f.has_id_number_like && <span className="flag">주민번호</span>}
                      {f.external_action && <span className="flag">외부 전송</span>}
                      <span className="muted small">{f.input_types.join(", ")}</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <p className="small">요청 {o.request_summary.total}건 · 차단 {o.request_summary.blocked}건 · 외부 도메인 {o.request_summary.third_party_domains.length}개
              {o.popups_blocked > 0 && ` · 팝업 차단 ${o.popups_blocked}`}{o.downloads_blocked > 0 && ` · 다운로드 차단 ${o.downloads_blocked}`}</p>
            {d.impersonates.length > 0 && <p className="small">사칭 대상으로 연결된 정상 도메인(재큐잉 제외): {d.impersonates.join(", ")}</p>}
          </section>
        )}

        <section>
          <h3>외부 평판</h3>
          {d.reputation.length === 0 ? <p className="muted small">조회 전</p> : (
            <ul className="small">
              {d.reputation.map((r, i) => <li key={i}><code>{r.result}</code> {r.url} {r.threats.join(", ")} <span className="muted">{r.detail}</span></li>)}
            </ul>
          )}
        </section>

        <section>
          <h3>증거 목록 · 무결성</h3>
          <table className="evidence">
            <thead><tr><th>#</th><th>유형</th><th>SHA-256</th><th>크기</th></tr></thead>
            <tbody>
              {d.evidence.map((e) => (
                <tr key={e.evidence_id} className={e.evidence_id === focusEv ? "sel" : ""}>
                  <td className="num">{e.seq}</td><td>{e.type}</td>
                  <td><code title={e.sha256}>{e.sha256.slice(0, 16)}…</code></td>
                  <td className="num">{(e.size / 1024).toFixed(1)}KB</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="row">
            <button className="ghost" onClick={() => void verify()}>해시 체인·서명 재검증</button>
            <button className="ghost" onClick={() => void downloadJson(`/api/candidates/${encodeURIComponent(candidateId)}/package`,
              `safetrace-package-${candidateId}.json`)}>검토 패키지(JSON)</button>
            {integrity && (integrity.ok
              ? <span className="badge tone-done">무결성 확인</span>
              : <span className="badge tone-fail">변조 탐지: {integrity.issues.map((x) => `${x.code}#${x.seq}`).join(", ")}</span>)}
          </div>
        </section>

        <ReviewBox candidateId={candidateId} role={role} detail={d} onDone={onChanged} />
      </div>
    </aside>
  );
}

function ReviewBox({ candidateId, role, detail, onDone }: { candidateId: string; role: Me["role"]; detail: Detail; onDone: () => void }) {
  const [decision, setDecision] = useState("INCONCLUSIVE");
  const [reason, setReason] = useState("");
  const [msg, setMsg] = useState("");

  if (detail.review) {
    return (
      <section className="review">
        <h3>담당자 판정</h3>
        <p><strong>{detail.review.decision}</strong> · {detail.review.reviewer_id} · {new Date(detail.review.decided_at).toLocaleString("ko-KR")}</p>
        <p className="small">{detail.review.reason}</p>
      </section>
    );
  }
  if (detail.candidate.status !== "REVIEW_REQUIRED") return null;
  if (role !== "reviewer") {
    return <section className="review"><h3>담당자 판정</h3><p className="muted small">판정 확정은 reviewer 역할만 할 수 있습니다(자동화 계정·AI 는 판정 권한 없음).</p></section>;
  }
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    try {
      await postJson(`/api/candidates/${encodeURIComponent(candidateId)}/review`, { decision, reason });
      setMsg("판정이 기록되었습니다.");
      onDone();
    } catch (err) {
      setMsg(err instanceof ApiError ? `실패: ${err.code}` : "실패");
    }
  }
  return (
    <section className="review">
      <h3>담당자 판정</h3>
      <form onSubmit={submit}>
        <div className="row">
          {[["THREAT_CONFIRMED", "위협 확인"], ["NOT_THREAT", "위협 아님"], ["INCONCLUSIVE", "판단 보류"]].map(([v, l]) => (
            <label key={v} className="radio"><input type="radio" name="decision" value={v} checked={decision === v}
              onChange={() => setDecision(v)} />{l}</label>
          ))}
        </div>
        <textarea required minLength={5} maxLength={2000} value={reason} onChange={(e) => setReason(e.target.value)}
          placeholder="판정 사유(원본 증거 확인 내용)" rows={3} />
        <button className="primary" disabled={reason.trim().length < 5}>판정 기록</button>
        {msg && <span className="submit-msg">{msg}</span>}
      </form>
    </section>
  );
}
