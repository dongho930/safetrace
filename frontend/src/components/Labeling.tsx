// D1-R 2인 교차 라벨링 화면(docs/10_labeling_guide.md).
// 블라인드: 피드 출처·AI 판정·상대 라벨을 보여주지 않는다. 상대 라벨은 두 명이 모두 판정한 불일치 건의 합의 탭에서만 보인다.
// 수집 HTML 은 렌더링하지 않고, 해시 재검증된 스크린샷과 요약 필드(텍스트)만 표시한다.
import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError, blobUrl, downloadText, getJson, postJson } from "../api";
import { EXCLUDE_OPTIONS, LABEL_OPTIONS, labelText } from "../labels";
import type { Disagreement, ExcludeReason, LabelItem, LabelQueueRow, LabelSummary, LabelValue } from "../types";

type Tab = "label" | "consensus" | "summary";
const enc = encodeURIComponent;

function errText(e: unknown): string {
  if (!(e instanceof ApiError)) return "요청에 실패했습니다.";
  return ({
    LOCKED: "두 명 모두 판정한 건은 개별 수정할 수 없습니다. 불일치면 합의 탭에서 정하세요.",
    NOT_A_LABELER: "라벨러 2명이 이미 정해져 있어 판정할 수 없습니다.",
    NOT_DISAGREED: "불일치 건만 합의할 수 있습니다.",
    SNAPSHOT_TAMPERED: "스냅샷 해시가 동결 시점과 다릅니다(변조 의심).",
  } as Record<string, string>)[e.code] ?? `${e.status} ${e.code}`;
}

export default function Labeling({ me }: { me: string }) {
  const [tab, setTab] = useState<Tab>("label");
  const [summary, setSummary] = useState<LabelSummary | null>(null);
  const refreshSummary = useCallback(() => {
    getJson<LabelSummary>("/api/labeling/summary").then(setSummary).catch(() => setSummary(null));
  }, []);
  useEffect(refreshSummary, [refreshSummary, tab]);

  const pendingConsensus = summary?.outcomes.DISAGREED ?? 0;
  return (
    <section className="panel labeling">
      <div className="panel-head">
        <h2>D1-R 라벨링</h2>
        <nav className="subtabs" aria-label="라벨링 메뉴">
          <button className={tab === "label" ? "on" : ""} onClick={() => setTab("label")}>라벨링</button>
          <button className={tab === "consensus" ? "on" : ""} onClick={() => setTab("consensus")}>
            합의{pendingConsensus > 0 && <span className="count">{pendingConsensus}</span>}
          </button>
          <button className={tab === "summary" ? "on" : ""} onClick={() => setTab("summary")}>현황</button>
        </nav>
        {summary && (
          <span className="muted">
            표본 {summary.sample_size}건 / 수집 {summary.total_snapshots}건 (비율 {Math.round(summary.sample_rate * 100)}%
            {summary.collector_errors > 0 && `, 수집 오류 ${summary.collector_errors}건 제외`})
            · 라벨러 {summary.labelers.length ? summary.labelers.join(", ") : "미정"}
          </span>
        )}
      </div>
      {summary && !summary.is_labeler && (
        <p className="warn small">라벨러 2명({summary.labelers.join(", ")})이 정해져 있어 이 계정({me})은 조회만 할 수 있습니다.</p>
      )}
      {tab === "label" && <Workbench onChanged={refreshSummary} />}
      {tab === "consensus" && <Consensus onChanged={refreshSummary} />}
      {tab === "summary" && summary && <Summary s={summary} />}
    </section>
  );
}

// ───────────── 스냅샷 표시(공용) ─────────────

function Snapshot({ sid }: { sid: string }) {
  const [item, setItem] = useState<LabelItem | null>(null);
  const [shot, setShot] = useState("");
  const [err, setErr] = useState("");
  useEffect(() => {
    let alive = true, url = "";
    setItem(null); setShot(""); setErr("");
    getJson<LabelItem>(`/api/labeling/items/${enc(sid)}`).then((x) => alive && setItem(x)).catch((e) => alive && setErr(errText(e)));
    blobUrl(`/api/labeling/items/${enc(sid)}/screenshot`)
      .then((u) => { url = u; if (alive) setShot(u); else URL.revokeObjectURL(u); })
      .catch((e) => alive && setErr(errText(e)));
    return () => { alive = false; if (url) URL.revokeObjectURL(url); };
  }, [sid]);

  const flags = useMemo(() => {
    const f = item?.forms ?? [];
    const any = (k: keyof LabelItem["forms"][number]) => f.some((x) => x[k]);
    return [
      any("has_password") && "비밀번호 입력", any("has_card_like") && "카드번호 입력", any("has_phone") && "전화번호 입력",
      any("has_id_number_like") && "주민번호 입력", any("external_action") && "외부 도메인으로 전송",
      (item?.downloads_blocked ?? 0) > 0 && `다운로드 시도 ${item?.downloads_blocked}회`,
    ].filter(Boolean) as string[];
  }, [item]);

  return (
    <div className="snap">
      <div className="snap-shot">
        {shot ? <img src={shot} alt="수집 시점 스크린샷" /> : <div className="screen-empty">{err || "스크린샷 불러오는 중…"}</div>}
      </div>
      <dl className="snap-meta">
        <dt>요청 URL</dt><dd className="url">{item?.url}</dd>
        <dt>최종 URL</dt><dd className="url">{item?.final_url}{item && item.redirects > 1 && <span className="muted"> · 이동 {item.redirects - 1}회</span>}</dd>
        <dt>제목</dt><dd>{item?.title || <span className="muted">(없음)</span>}{item?.lang && <span className="muted"> · {item.lang}</span>}</dd>
        <dt>입력 폼</dt>
        <dd>{item && (item.forms.length ? <span className="flags">{item.forms.length}개
          {flags.map((t) => <span key={t} className="flag">{t}</span>)}</span> : <span className="muted">없음</span>)}</dd>
        <dt>본문 일부</dt><dd className="excerpt">{item?.text_excerpt || <span className="muted">(없음)</span>}</dd>
        <dt>스냅샷</dt><dd className="muted small">{sid} · 수집일 {item?.collected_day}</dd>
      </dl>
    </div>
  );
}

// ───────────── 라벨링 ─────────────

function Workbench({ onChanged }: { onChanged: () => void }) {
  const [queue, setQueue] = useState<LabelQueueRow[] | null>(null);
  const [idx, setIdx] = useState(0);
  const [excludeMode, setExcludeMode] = useState(false);
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getJson<LabelQueueRow[]>("/api/labeling/queue").then((q) => {
      setQueue(q);
      const first = q.findIndex((r) => !r.my_label);
      setIdx(first >= 0 ? first : 0);
    }).catch((e) => setMsg(errText(e)));
  }, []);

  const row = queue?.[idx];
  useEffect(() => { setExcludeMode(false); setNote(""); }, [idx]);

  const nextUnlabeled = useCallback((from: number, q: LabelQueueRow[]) => {
    for (let i = 1; i <= q.length; i++) { const j = (from + i) % q.length; if (!q[j].my_label) return j; }
    return Math.min(from + 1, q.length - 1);
  }, []);

  const submit = useCallback(async (label: LabelValue, reason: ExcludeReason | null = null) => {
    if (!queue || !row || busy) return;
    if (row.locked) { setMsg(errText(new ApiError(409, "LOCKED"))); return; }
    setBusy(true); setMsg("");
    try {
      await postJson(`/api/labeling/items/${enc(row.snapshot_id)}/label`, { label, exclude_reason: reason, note });
      const q = queue.map((r, i) => i === idx ? { ...r, my_label: label, my_exclude_reason: reason } : r);
      setQueue(q);
      setIdx(nextUnlabeled(idx, q));
      onChanged();
    } catch (e) {
      setMsg(errText(e));
    } finally {
      setBusy(false);
    }
  }, [queue, row, busy, idx, note, nextUnlabeled, onChanged]);

  useEffect(() => {
    function onKey(ev: KeyboardEvent) {
      const t = ev.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT")) return;
      if (ev.ctrlKey || ev.metaKey || ev.altKey || !queue) return;
      const k = ev.key.toLowerCase();
      if (excludeMode) {
        const o = EXCLUDE_OPTIONS.find((x) => x.key === k);
        if (o) { ev.preventDefault(); void submit("EXCLUDE", o.value); }
        else if (k === "escape") setExcludeMode(false);
        return;
      }
      const o = LABEL_OPTIONS.find((x) => x.key === k);
      if (o) { ev.preventDefault(); void submit(o.value); }
      else if (k === "x") setExcludeMode(true);
      else if (k === "arrowright") setIdx((i) => Math.min(i + 1, queue.length - 1));
      else if (k === "arrowleft") setIdx((i) => Math.max(i - 1, 0));
      else if (k === "n") setIdx((i) => nextUnlabeled(i, queue));
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [queue, excludeMode, submit, nextUnlabeled]);

  if (!queue) return <p className="empty">{msg || "표본 불러오는 중…"}</p>;
  if (queue.length === 0) return <p className="empty">아직 표본이 없습니다. 수집기가 스냅샷을 모으면 자동으로 늘어납니다.</p>;
  const done = queue.filter((r) => r.my_label).length;

  return (
    <div className="workbench">
      <div className="row wb-nav">
        <progress className="bar" max={queue.length} value={done} aria-label="내 진행률" />
        <span className="num small">내 진행 {done} / {queue.length}</span>
        <button className="ghost" onClick={() => setIdx((i) => Math.max(i - 1, 0))} disabled={idx === 0}>← 이전</button>
        <span className="num small">{idx + 1} / {queue.length}</span>
        <button className="ghost" onClick={() => setIdx((i) => Math.min(i + 1, queue.length - 1))} disabled={idx >= queue.length - 1}>다음 →</button>
        <button className="ghost" onClick={() => setIdx((i) => nextUnlabeled(i, queue))}>미라벨로 (N)</button>
      </div>

      {row && <Snapshot sid={row.snapshot_id} />}

      {row && (
        <div className="decide">
          <p className="small">
            내 판정: <strong>{labelText(row.my_label, row.my_exclude_reason)}</strong>
            {row.locked && <span className="badge tone-muted">잠김 · 두 명 모두 완료</span>}
          </p>
          {!excludeMode ? (
            <div className="choices" role="group" aria-label="유형 선택">
              {LABEL_OPTIONS.map((o) => (
                <button key={o.value} className={`choice ${row.my_label === o.value ? "on" : ""}`} title={o.hint}
                  disabled={busy || row.locked} onClick={() => void submit(o.value)}>
                  <kbd>{o.key}</kbd> {o.text}
                </button>
              ))}
              <button className="choice exclude" disabled={busy || row.locked} onClick={() => setExcludeMode(true)}>
                <kbd>X</kbd> 제외…
              </button>
            </div>
          ) : (
            <div className="choices" role="group" aria-label="제외 사유">
              {EXCLUDE_OPTIONS.map((o) => (
                <button key={o.value} className="choice exclude" disabled={busy} onClick={() => void submit("EXCLUDE", o.value)}>
                  <kbd>{o.key}</kbd> {o.text}
                </button>
              ))}
              <button className="ghost" onClick={() => setExcludeMode(false)}><kbd>Esc</kbd> 취소</button>
            </div>
          )}
          <input className="note" placeholder="메모(선택, 500자)" maxLength={500} value={note}
            onChange={(e) => setNote(e.target.value)} disabled={row.locked} />
          {msg && <p className="error small">{msg}</p>}
          <p className="hint">단축키: 1~6 유형 · X 제외(이어서 1~3 사유) · ←/→ 이동 · N 다음 미라벨. 메모 입력 중에는 단축키가 꺼집니다.
            판단 기준은 docs/10_labeling_guide.md 를 따릅니다.</p>
        </div>
      )}
    </div>
  );
}

// ───────────── 합의 ─────────────

function Consensus({ onChanged }: { onChanged: () => void }) {
  const [list, setList] = useState<Disagreement[] | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [label, setLabel] = useState<LabelValue | "">("");
  const [reason, setReason] = useState<ExcludeReason | "">("");
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState("");

  const load = useCallback(() => {
    getJson<Disagreement[]>("/api/labeling/disagreements").then((x) => {
      setList(x);
      setSel((cur) => cur ?? x.find((d) => d.outcome === "DISAGREED")?.snapshot_id ?? x[0]?.snapshot_id ?? null);
    }).catch((e) => { setList([]); setMsg(errText(e)); });
  }, []);
  useEffect(load, [load]);

  const cur = list?.find((d) => d.snapshot_id === sel);
  useEffect(() => {
    setLabel(cur?.consensus?.label ?? ""); setReason(cur?.consensus?.exclude_reason ?? ""); setNote(cur?.consensus?.note ?? "");
    setMsg("");
  }, [cur]);

  async function save() {
    if (!cur || !label) return;
    try {
      await postJson(`/api/labeling/items/${enc(cur.snapshot_id)}/consensus`,
        { label, exclude_reason: label === "EXCLUDE" ? reason || null : null, note });
      onChanged();
      load();
      setMsg("저장했습니다.");
    } catch (e) {
      setMsg(errText(e));
    }
  }

  if (!list) return <p className="empty">불러오는 중…</p>;
  if (list.length === 0) return <p className="empty">{msg || "불일치 건이 없습니다."}</p>;
  const valid = label && (label !== "EXCLUDE" || reason) && note.trim().length >= 5;

  return (
    <div className="consensus">
      <ul className="dis-list">
        {list.map((d) => (
          <li key={d.snapshot_id}>
            <button className={d.snapshot_id === sel ? "on" : ""} onClick={() => setSel(d.snapshot_id)}>
              <span className={`badge ${d.outcome === "DISAGREED" ? "tone-wait" : "tone-done"}`}>
                {d.outcome === "DISAGREED" ? "합의 대기" : "합의 완료"}</span>
              <span className="small">{d.labels.map((v) => labelText(v.label, v.exclude_reason)).join(" vs ")}</span>
            </button>
          </li>
        ))}
      </ul>
      {cur && (
        <div className="dis-body">
          <Snapshot sid={cur.snapshot_id} />
          <table className="votes">
            <thead><tr><th>라벨러</th><th>독립 판정</th><th>메모</th></tr></thead>
            <tbody>{cur.labels.map((v) => (
              <tr key={v.user}><td>{v.user}</td><td>{labelText(v.label, v.exclude_reason)}</td><td className="small">{v.note}</td></tr>
            ))}</tbody>
          </table>
          <div className="row">
            <select value={label} onChange={(e) => setLabel(e.target.value as LabelValue)} aria-label="합의 라벨">
              <option value="">합의 라벨 선택</option>
              {LABEL_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.text}</option>)}
              <option value="EXCLUDE">제외</option>
            </select>
            {label === "EXCLUDE" && (
              <select value={reason} onChange={(e) => setReason(e.target.value as ExcludeReason)} aria-label="제외 사유">
                <option value="">사유 선택</option>
                {EXCLUDE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.text}</option>)}
              </select>
            )}
          </div>
          <textarea rows={2} placeholder="합의 근거(필수, 5자 이상)" maxLength={500} value={note}
            onChange={(e) => setNote(e.target.value)} />
          <div className="row">
            <button className="primary" disabled={!valid} onClick={() => void save()}>
              {cur.consensus ? "합의 수정" : "합의 저장"}</button>
            {cur.consensus && <span className="muted small">현재 합의: {labelText(cur.consensus.label, cur.consensus.exclude_reason)} ({cur.consensus.user})</span>}
            {msg && <span className="small">{msg}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

// ───────────── 현황 ─────────────

function Summary({ s }: { s: LabelSummary }) {
  const pct = (x: number | null) => (x === null ? "—" : `${(x * 100).toFixed(1)}%`);
  const tiles: [string, string | number][] = [
    ["표본", s.sample_size], ["두 명 완료", s.both_labeled], ["독립 일치", s.outcomes.AGREED],
    ["합의 대기", s.outcomes.DISAGREED], ["합의 완료", s.outcomes.CONSENSUS],
    ["일치율", pct(s.percent_agreement)], ["Cohen's κ", s.kappa === null ? "—" : s.kappa.toFixed(3)],
  ];
  return (
    <div>
      <div className="tiles">
        {tiles.map(([k, v]) => <div key={k} className="tile"><span className="tile-value">{v}</span><span className="tile-label">{k}</span></div>)}
      </div>
      <h3>라벨러별 진행</h3>
      <ul className="small">{Object.entries(s.done_by).map(([u, n]) => <li key={u}>{u}: {n} / {s.sample_size}</li>)}</ul>
      <h3>최종 라벨 분포(일치 + 합의)</h3>
      <ul className="small">
        {Object.entries(s.final_by_label).map(([k, n]) => <li key={k}>{labelText(k)}: {n}</li>)}
        {Object.entries(s.excluded_by_reason).map(([k, n]) => <li key={k}>{labelText("EXCLUDE", k)}: {n}</li>)}
      </ul>
      <p className="hint">κ 와 일치율은 합의 전 두 사람의 독립 판정으로 계산합니다. 보고서에는 최종 정답 수를 "독립 일치 N + 합의 M"으로 나눠 적습니다.</p>
      <button className="ghost" onClick={() => void downloadText("/api/labeling/export", "labels.csv", "text/csv")}>
        labels.csv 내려받기</button>
    </div>
  );
}
