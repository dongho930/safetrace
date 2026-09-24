import { STAGES } from "../labels";
import type { CandidateRow, Stats } from "../types";

export default function PipelineStrip({ rows, stats }: { rows: CandidateRow[]; stats: Stats }) {
  const count = (statuses: string[]) => rows.filter((r) => statuses.includes(r.status)).length;
  const seeds = rows.filter((r) => r.depth === 0).length;

  const tiles = [
    { label: "발견", value: stats.discovered, tone: "info" },
    { label: "대기", value: stats.waiting, tone: "wait" },
    { label: "조사·분석 중", value: stats.investigating, tone: "run" },
    { label: "검토 필요", value: stats.review_required, tone: "warn" },
    { label: "판정 완료", value: stats.decided, tone: "done" },
    { label: "차단·실패", value: stats.failed, tone: "fail" },
  ];

  return (
    <section className="pipeline" aria-label="파이프라인 상태">
      <div className="tiles">
        {tiles.map((t) => (
          <div key={t.label} className={`tile tone-${t.tone}`}>
            <span className="tile-value">{t.value}</span>
            <span className="tile-label">{t.label}</span>
          </div>
        ))}
      </div>
      <ol className="stages">
        {STAGES.map((s, i) => {
          const waiting = s.key === "seed" ? 0 : count(s.waiting);
          const running = count(s.running);
          const failed = count(s.failed);
          const done = s.key === "seed" ? seeds : count(s.done);
          const state = running ? "run" : waiting ? "wait" : failed && !done ? "fail" : done ? "done" : "idle";
          return (
            <li key={s.key} className={`stage stage-${state}`}>
              <span className="stage-no">{i + 1}</span>
              <div className="stage-body">
                <strong>{s.title}</strong>
                <span className="stage-sub">{s.sub}</span>
                <span className="stage-counts">
                  {waiting > 0 && <span className="c-wait">대기 {waiting}</span>}
                  {running > 0 && <span className="c-run">진행 {running}</span>}
                  {done > 0 && <span className="c-done">완료 {done}</span>}
                  {failed > 0 && <span className="c-fail">{s.key === "queue" ? "제외" : "실패"} {failed}</span>}
                </span>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
