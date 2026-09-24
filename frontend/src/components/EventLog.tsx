import type { PipelineEvent } from "../types";

function describe(e: PipelineEvent): string {
  const d = e.data;
  switch (e.type) {
    case "candidate.discovered": return `후보 발견 (${d.source}, 깊이 ${d.depth}, 우선순위 ${Number(d.priority).toFixed(1)})`;
    case "candidate.status": return `${d.from} → ${d.to}${d.reason ? ` · ${d.reason}` : ""}`;
    case "evidence.stored": return `증거 저장 ${d.type} #${d.seq} (sha256 ${String(d.sha256).slice(0, 10)}…)`;
    case "analysis.done": return `AI 분석 ${d.state}`;
    case "reputation.done": return `Safe Browsing ${(d.results as string[] | undefined)?.join(", ")}`;
    case "discovery.expanded": return `후속 후보 재큐잉 ${d.queued}건`;
    case "investigation.step": return `조사 단계: ${d.step}`;
    default: return e.type;
  }
}

export default function EventLog({ events }: { events: PipelineEvent[] }) {
  return (
    <>
      <div className="panel-head"><h2>이벤트</h2><span className="muted">SSE 실시간</span></div>
      <ol className="events">
        {events.length === 0 && <li className="empty">이벤트 대기 중</li>}
        {events.slice(0, 120).map((e) => (
          <li key={e.event_id}>
            <time>{new Date(e.ts).toLocaleTimeString("ko-KR", { hour12: false })}</time>
            <span className="ev-id">{e.candidate_id?.slice(5, 13) ?? "-"}</span>
            <span className="ev-text">{describe(e)}</span>
          </li>
        ))}
      </ol>
    </>
  );
}
