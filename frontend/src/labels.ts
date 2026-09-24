import type { CandidateStatus, ExcludeReason, LabelValue } from "./types";

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

/** D1-R 라벨링 선택지. key 는 단축키(docs/10_labeling_guide.md 와 같은 순서). */
export const LABEL_OPTIONS: { value: LabelValue; key: string; text: string; hint: string }[] = [
  { value: "PHISHING", key: "1", text: "피싱", hint: "기관·기업을 사칭해 로그인·결제·개인정보 입력 유도" },
  { value: "SCAM", key: "2", text: "사기", hint: "투자·환급·쇼핑·입금 유도 등 금전 편취(사칭 로그인 없음)" },
  { value: "ILLEGAL_GAMBLING_SUSPECTED", key: "3", text: "불법도박", hint: "카지노·토토·슬롯 배팅·충전·환전" },
  { value: "MALWARE", key: "4", text: "악성코드", hint: "앱·파일 설치·다운로드 유도, 가짜 업데이트" },
  { value: "OTHER", key: "5", text: "기타 위협", hint: "위협이지만 위 유형에 해당하지 않음" },
  { value: "BENIGN", key: "6", text: "정상", hint: "정상 서비스 화면(위협 징후 없음)" },
];

export const EXCLUDE_OPTIONS: { value: ExcludeReason; key: string; text: string }[] = [
  { value: "PARKED", key: "1", text: "주차 도메인" },
  { value: "DOWN_OR_ERROR", key: "2", text: "삭제·오류·빈 페이지" },
  { value: "UNSURE", key: "3", text: "판단 불가" },
];

export function labelText(value: string | null, reason?: string | null): string {
  if (!value) return "미라벨";
  if (value === "EXCLUDE") return `제외(${EXCLUDE_OPTIONS.find((o) => o.value === reason)?.text ?? reason ?? "?"})`;
  return LABEL_OPTIONS.find((o) => o.value === value)?.text ?? value;
}
