import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError, getJson, getToken, setToken } from "./api";
import { subscribe, type SseState } from "./sse";
import type { CandidateRow, CandidateStatus, Me, PipelineEvent, Stats } from "./types";
import Login from "./components/Login";
import PipelineStrip from "./components/PipelineStrip";
import SubmitBar from "./components/SubmitBar";
import CandidateTable from "./components/CandidateTable";
import LiveView from "./components/LiveView";
import RelationGraph from "./components/RelationGraph";
import EventLog from "./components/EventLog";
import DetailPanel from "./components/DetailPanel";

const EMPTY_STATS: Stats = { discovered: 0, waiting: 0, investigating: 0, review_required: 0, decided: 0,
  failed: 0, skipped: 0, cases: 0 };

export interface Frame { candidateId: string; url: string; src: string; step: string; ts: number }

export default function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [authError, setAuthError] = useState("");
  const [rows, setRows] = useState<Map<string, CandidateRow>>(new Map());
  const [stats, setStats] = useState<Stats>(EMPTY_STATS);
  const [events, setEvents] = useState<PipelineEvent[]>([]);
  const [frame, setFrame] = useState<Frame | null>(null);
  const [sse, setSse] = useState<SseState>("closed");
  const [selected, setSelected] = useState<string | null>(null);
  const [detailTick, setDetailTick] = useState(0);
  const stepRef = useRef<Record<string, string>>({});
  const selectedRef = useRef<string | null>(null);
  useEffect(() => { selectedRef.current = selected; }, [selected]);

  const login = useCallback(async (token: string) => {
    setToken(token);
    try {
      setMe(await getJson<Me>("/api/me"));
      setAuthError("");
    } catch (e) {
      setToken("");
      setMe(null);
      setAuthError(e instanceof ApiError && e.status === 401 ? "토큰이 올바르지 않습니다." : "API 에 연결할 수 없습니다.");
    }
  }, []);

  useEffect(() => { if (getToken()) void login(getToken()); }, [login]);

  const refresh = useCallback(async () => {
    const list = await getJson<CandidateRow[]>("/api/candidates");
    setRows(new Map(list.map((r) => [r.candidate_id, r])));
    setStats(await getJson<Stats>("/api/stats"));
  }, []);

  const onEvent = useCallback((e: PipelineEvent) => {
    if (e.type === "pipeline.stats") { setStats(e.data as unknown as Stats); return; }
    if (e.type === "investigation.frame" && e.candidate_id) {
      const b64 = String(e.data.jpeg_b64 ?? "");
      if (/^[A-Za-z0-9+/=]+$/.test(b64)) {
        const cid = e.candidate_id;
        setFrame((prev) => ({ candidateId: cid, url: prev?.candidateId === cid ? prev.url : "",
          src: `data:image/jpeg;base64,${b64}`, step: stepRef.current[cid] ?? "", ts: Date.now() }));
      }
      return;
    }
    setEvents((prev) => [e, ...prev].slice(0, 300));
    const cid = e.candidate_id;
    if (!cid) return;
    if (e.type === "investigation.step") {
      stepRef.current[cid] = String(e.data.step ?? "");
      if (e.data.url) setFrame((prev) => prev && prev.candidateId === cid ? { ...prev, url: String(e.data.url) } : prev);
    }
    setRows((prev) => {
      const next = new Map(prev);
      const cur = next.get(cid);
      if (e.type === "candidate.discovered" && !cur) {
        next.set(cid, {
          candidate_id: cid, case_id: e.case_id ?? "", url: String(e.data.url ?? ""),
          source: String(e.data.source ?? ""), status: "DISCOVERED", status_reason: "",
          priority: Number(e.data.priority ?? 0), depth: Number(e.data.depth ?? 0),
          discovered_from: (e.data.from as string) ?? null, relation: String(e.data.relation ?? "SEED"),
          created_at: e.ts, ai_state: null, ai_top: null,
        });
      } else if (e.type === "candidate.status" && cur) {
        next.set(cid, { ...cur, status: e.data.to as CandidateStatus, status_reason: String(e.data.reason ?? "") });
      } else if (e.type === "analysis.done" && cur) {
        const top = (e.data.top as { type: string; confidence: number }[] | undefined)?.[0] ?? null;
        next.set(cid, { ...cur, ai_state: String(e.data.state ?? ""), ai_top: top });
      }
      return next;
    });
    if (cid === selectedRef.current) setDetailTick((t) => t + 1);
  }, []);

  useEffect(() => {
    if (!me) return;
    void refresh();
    return subscribe(onEvent, setSse);
  }, [me, refresh, onEvent]);

  const list = useMemo(() => [...rows.values()].sort((a, b) => b.created_at.localeCompare(a.created_at)), [rows]);

  if (!me) return <Login onLogin={login} error={authError} />;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo" aria-hidden>ST</span>
          <div>
            <strong>SafeTrace</strong>
            <span className="brand-sub">위협 의심 사이트 조사·검토 콘솔</span>
          </div>
        </div>
        <div className="topbar-right">
          <span className={`live live-${sse}`}>{sse === "open" ? "실시간 연결" : sse === "connecting" ? "연결 중" : "연결 끊김"}</span>
          <span className="who">{me.user_id} · {me.role}</span>
          <button className="ghost" onClick={() => { setToken(""); setMe(null); }}>로그아웃</button>
        </div>
      </header>

      <PipelineStrip rows={list} stats={stats} />

      {me.role !== "viewer" && <SubmitBar onSubmitted={refresh} />}

      <main className="grid">
        <section className="panel span-2">
          <CandidateTable rows={list} selected={selected} onSelect={setSelected} />
        </section>
        <section className="panel">
          <LiveView frame={frame} rows={rows} />
        </section>
        <section className="panel span-2">
          <RelationGraph rows={list} onSelect={setSelected} selected={selected} />
        </section>
        <section className="panel">
          <EventLog events={events} />
        </section>
      </main>

      {selected && (
        <DetailPanel key={selected} candidateId={selected} role={me.role} tick={detailTick}
          onClose={() => setSelected(null)} onChanged={refresh} />
      )}

      <footer className="foot">
        AI confidence 는 모델의 기술적 신뢰도이며 법적 위법성의 확률이 아닙니다. 외부 평판 DB 미등재는 정상의 근거가 아닙니다.
        최종 판정은 담당자가 합니다.
      </footer>
    </div>
  );
}
