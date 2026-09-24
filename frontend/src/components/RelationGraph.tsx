import { useMemo } from "react";
import { STATUS_TONE } from "../labels";
import type { CandidateRow } from "../types";

interface Props { rows: CandidateRow[]; selected: string | null; onSelect: (id: string) => void }

const COL_W = 230;
const ROW_H = 30;
const NODE_W = 200;

function label(url: string): string {
  try {
    const u = new URL(url);
    const tail = u.pathname.length > 1 ? u.pathname.split("/").filter(Boolean).slice(-1)[0] : "";
    return tail ? `${u.hostname}/…/${tail}` : u.hostname;
  } catch { return url.slice(0, 40); }
}

/** 깊이별 열 배치의 관계 그래프(발견 경로). 외부 라이브러리 없이 SVG 로 그린다. */
export default function RelationGraph({ rows, selected, onSelect }: Props) {
  const layout = useMemo(() => {
    const byDepth = new Map<number, CandidateRow[]>();
    for (const r of [...rows].sort((a, b) => a.created_at.localeCompare(b.created_at))) {
      const list = byDepth.get(r.depth) ?? [];
      list.push(r);
      byDepth.set(r.depth, list);
    }
    const pos = new Map<string, { x: number; y: number }>();
    let maxRows = 1;
    for (const [d, list] of byDepth) {
      maxRows = Math.max(maxRows, list.length);
      list.slice(0, 60).forEach((r, i) => pos.set(r.candidate_id, { x: 12 + d * COL_W, y: 14 + i * ROW_H }));
    }
    const depths = byDepth.size ? Math.max(...byDepth.keys()) + 1 : 1;
    return { pos, width: 24 + depths * COL_W, height: 28 + Math.min(maxRows, 60) * ROW_H };
  }, [rows]);

  return (
    <>
      <div className="panel-head">
        <h2>후보 관계 그래프</h2>
        <span className="muted">Seed(깊이 0) → 관찰된 링크·리다이렉트로 발견된 후속 후보</span>
      </div>
      {rows.length === 0 ? <div className="empty">표시할 관계가 없습니다.</div> : (
        <div className="graph-wrap">
          <svg width={layout.width} height={layout.height} role="img" aria-label="후보 관계 그래프">
            {rows.map((r) => {
              const to = layout.pos.get(r.candidate_id);
              const from = r.discovered_from ? layout.pos.get(r.discovered_from) : undefined;
              if (!to || !from) return null;
              const x1 = from.x + NODE_W, y1 = from.y + 11, x2 = to.x, y2 = to.y + 11;
              return <path key={`e-${r.candidate_id}`} className={`edge edge-${r.relation}`}
                d={`M${x1},${y1} C${x1 + 20},${y1} ${x2 - 20},${y2} ${x2},${y2}`} />;
            })}
            {rows.map((r) => {
              const p = layout.pos.get(r.candidate_id);
              if (!p) return null;
              return (
                <g key={r.candidate_id} transform={`translate(${p.x},${p.y})`}
                  className={`node tone-${STATUS_TONE[r.status]} ${r.candidate_id === selected ? "node-sel" : ""}`}
                  onClick={() => onSelect(r.candidate_id)}>
                  <rect width={NODE_W} height={22} rx={5} />
                  <text x={8} y={15}>{label(r.url).slice(0, 30)}</text>
                  <title>{`${r.url}\n${r.status} · 우선순위 ${r.priority.toFixed(1)} · ${r.relation}`}</title>
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </>
  );
}
