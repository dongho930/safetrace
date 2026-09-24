import { SOURCE_LABEL, STATUS_LABEL, STATUS_TONE, THREAT_LABEL } from "../labels";
import type { CandidateRow } from "../types";

interface Props { rows: CandidateRow[]; selected: string | null; onSelect: (id: string) => void }

export default function CandidateTable({ rows, selected, onSelect }: Props) {
  return (
    <>
      <div className="panel-head">
        <h2>후보 목록</h2>
        <span className="muted">{rows.length}건 · 최신순</span>
      </div>
      <div className="table-wrap">
        <table className="cands">
          <thead>
            <tr><th>상태</th><th>URL</th><th>출처</th><th>깊이</th><th>우선순위</th><th>AI 분석 의견</th></tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={6} className="empty">접수된 후보가 없습니다. 위에서 URL 을 접수하세요.</td></tr>
            )}
            {rows.map((r) => (
              <tr key={r.candidate_id} className={r.candidate_id === selected ? "sel" : ""}
                onClick={() => onSelect(r.candidate_id)} tabIndex={0}
                onKeyDown={(e) => { if (e.key === "Enter") onSelect(r.candidate_id); }}>
                <td><span className={`badge tone-${STATUS_TONE[r.status]}`} title={r.status_reason}>
                  {STATUS_LABEL[r.status]}</span></td>
                <td className="url" title={r.url}>{r.url}</td>
                <td>{SOURCE_LABEL[r.source] ?? r.source}{r.relation !== "SEED" && <span className="rel"> · {r.relation}</span>}</td>
                <td className="num">{r.depth}</td>
                <td className="num">{r.priority.toFixed(1)}</td>
                <td>
                  {r.ai_state === "UNKNOWN" && <span className="badge tone-muted">UNKNOWN(보류)</span>}
                  {r.ai_state === "REVIEW_REQUIRED" && r.ai_top && (
                    <span className="ai-top">{THREAT_LABEL[r.ai_top.type] ?? r.ai_top.type}
                      <span className="conf">{r.ai_top.confidence.toFixed(2)}</span></span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
