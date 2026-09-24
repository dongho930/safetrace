import type { CandidateStatus } from "./types";

export const STATUS_LABEL: Record<CandidateStatus, string> = {
  DISCOVERED: "발견", QUEUED: "조사 대기", SCREENING: "접근 전 검사", INVESTIGATING: "격리 조사 중",
  ANALYZING: "AI 분석 중", PACKAGING: "평판·패키지", REVIEW_REQUIRED: "검토 필요", DECIDED: "판정 완료",
  SKIPPED: "제외", BLOCKED: "안전 차단", UNREACHABLE: "접속 불가", FAILED: "실패",
};

export type Tone = "wait" | "run" | "done" | "fail" | "muted";

export const STATUS_TONE: Record<CandidateStatus, Tone> = {
  DISCOVERED: "wait", QUEUED: "wait", SCREENING: "run", INVESTIGATING: "run", ANALYZING: "run",
  PACKAGING: "run", REVIEW_REQUIRED: "wait", DECIDED: "done", SKIPPED: "muted", BLOCKED: "fail",
  UNREACHABLE: "fail", FAILED: "fail",
};

export const THREAT_LABEL: Record<string, string> = {
  PHISHING: "피싱 의심", SCAM: "사기 의심", ILLEGAL_GAMBLING_SUSPECTED: "불법 도박 의심",
  MALWARE: "악성코드 유포 의심", OTHER: "기타",
};

export const SOURCE_LABEL: Record<string, string> = {
  KISA: "KISA 피싱 URL", REPORT: "신고 URL", SEARCH_API: "검색 API", DISCOVERED: "자율 발굴",
};

/** 처리 흐름 8단계(기획서 그림 2)와 각 단계에 속하는 후보 상태 */
export const STAGES: { key: string; title: string; sub: string; waiting: CandidateStatus[];
  running: CandidateStatus[]; done: CandidateStatus[]; failed: CandidateStatus[] }[] = [
  { key: "seed", title: "Seed 수집", sub: "KISA·신고·검색", waiting: [], running: [], done: [], failed: [] },
  { key: "queue", title: "후보 큐", sub: "중복·범위·우선순위", waiting: ["DISCOVERED", "QUEUED"], running: [],
    done: [], failed: ["SKIPPED"] },
  { key: "screen", title: "접근 전 검사", sub: "URL·DNS·IP 재검증", waiting: [], running: ["SCREENING"],
    done: [], failed: ["BLOCKED"] },
  { key: "browser", title: "격리 브라우저", sub: "렌더링·증거·후속 후보", waiting: [], running: ["INVESTIGATING"],
    done: [], failed: ["UNREACHABLE", "FAILED"] },
  { key: "ai", title: "AI 분석", sub: "유형·신뢰도·근거 ID", waiting: [], running: ["ANALYZING"], done: [], failed: [] },
  { key: "sb", title: "Safe Browsing", sub: "평판 조회", waiting: [], running: ["PACKAGING"], done: [], failed: [] },
  { key: "pkg", title: "검토 패키지", sub: "증거·AI 근거·초안", waiting: [], running: [],
    done: ["REVIEW_REQUIRED", "DECIDED"], failed: [] },
  { key: "review", title: "담당자 검토", sub: "최종 확정·감사로그", waiting: ["REVIEW_REQUIRED"], running: [],
    done: ["DECIDED"], failed: [] },
];
