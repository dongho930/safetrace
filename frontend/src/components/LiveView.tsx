import type { Frame } from "../App";
import type { CandidateRow } from "../types";

const STEP_LABEL: Record<string, string> = { navigate: "접속 중", rendered: "렌더링 완료", collected: "증거 수집 완료" };

export default function LiveView({ frame, rows }: { frame: Frame | null; rows: Map<string, CandidateRow> }) {
  const active = [...rows.values()].filter((r) => r.status === "INVESTIGATING");
  const row = frame ? rows.get(frame.candidateId) : undefined;
  const stale = frame ? Date.now() - frame.ts > 8000 && row?.status !== "INVESTIGATING" : true;
  return (
    <>
      <div className="panel-head">
        <h2>실시간 조사 화면</h2>
        <span className="muted">격리 브라우저 · 조사 중 {active.length}건</span>
      </div>
      <div className={`screen ${stale ? "screen-idle" : ""}`}>
        {frame ? (
          <img src={frame.src} alt="격리 브라우저 화면(읽기 전용 캡처)" draggable={false} />
        ) : (
          <div className="screen-empty">조사가 시작되면 격리 브라우저 화면이 표시됩니다.</div>
        )}
      </div>
      {frame && (
        <dl className="screen-meta">
          <dt>후보</dt><dd className="url">{row?.url ?? frame.candidateId}</dd>
          <dt>단계</dt><dd>{STEP_LABEL[frame.step] ?? (frame.step || "-")}</dd>
        </dl>
      )}
      <p className="hint">화면은 이미지로만 전달됩니다. 콘솔에서 수집 페이지의 HTML·스크립트를 실행하지 않습니다.</p>
    </>
  );
}
