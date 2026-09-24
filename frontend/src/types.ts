// backend/src/safetrace/schemas.py 와 대응하는 화면용 타입(필요한 필드만).

export type CandidateStatus =
  | "DISCOVERED" | "QUEUED" | "SCREENING" | "INVESTIGATING" | "ANALYZING" | "PACKAGING"
  | "REVIEW_REQUIRED" | "DECIDED" | "SKIPPED" | "BLOCKED" | "UNREACHABLE" | "FAILED";

export interface CandidateRow {
  candidate_id: string;
  case_id: string;
  url: string;
  source: string;
  status: CandidateStatus;
  status_reason: string;
  priority: number;
  depth: number;
  discovered_from: string | null;
  relation: string;
  created_at: string;
  ai_state: string | null;
  ai_top: { type: string; confidence: number } | null;
}

export interface Stats {
  discovered: number;
  waiting: number;
  investigating: number;
  review_required: number;
  decided: number;
  failed: number;
  skipped: number;
  cases: number;
}

export interface PipelineEvent {
  event_id: number;
  type: string;
  case_id: string | null;
  candidate_id: string | null;
  stage: string | null;
  status: string | null;
  ts: string;
  data: Record<string, unknown>;
}

export interface EvidenceLink { evidence_id: string; feature: string; reason: string }
export interface ThreatScore { type: string; confidence: number; evidence_links: EvidenceLink[] }

export interface Detail {
  candidate: {
    candidate_id: string; normalized_url: string; status: CandidateStatus; status_reason: string;
    source: string; depth: number; priority: number; relation: string; discovered_from: string | null;
    score_reasons: { code: string; weight: number; detail: string }[];
  };
  observation: null | {
    final_url: string; reachable: boolean;
    redirect_chain: { url: string; status: number | null; kind: string }[];
    dom_summary: { title: string; text_excerpt: string };
    forms: { action: string; method: string; input_types: string[]; has_password: boolean;
             has_card_like: boolean; has_id_number_like: boolean; external_action: boolean }[];
    request_summary: { total: number; blocked: number; third_party_domains: string[]; blocked_samples: string[] };
    policy_blocks: string[]; popups_blocked: number; downloads_blocked: number; errors: string[];
  };
  analysis: null | {
    threat_types: ThreatScore[]; state: string; state_reason: string;
    model_meta: { model_version: string; model_hash: string; backend: string; inferred_at: string };
  };
  reputation: { provider: string; url: string; result: string; threats: string[]; detail: string }[];
  review: null | { reviewer_id: string; decision: string; reason: string; decided_at: string };
  evidence: { evidence_id: string; type: string; sha256: string; size: number; seq: number; captured_at: string }[];
  impersonates: string[];
}

export interface Me { user_id: string; role: "viewer" | "investigator" | "reviewer" | "automation" }

// D1-R 라벨링(backend/src/safetrace/labeling/store.py)
export type LabelValue = "PHISHING" | "SCAM" | "ILLEGAL_GAMBLING_SUSPECTED" | "MALWARE" | "OTHER" | "BENIGN" | "EXCLUDE";
export type ExcludeReason = "PARKED" | "DOWN_OR_ERROR" | "UNSURE";

export interface LabelQueueRow {
  snapshot_id: string; my_label: LabelValue | null; my_exclude_reason: ExcludeReason | null; locked: boolean;
}

export interface LabelItem {
  snapshot_id: string; collected_day: string; url: string; final_url: string; title: string; lang: string;
  text_excerpt: string; redirects: number; downloads_blocked: number; has_screenshot: boolean;
  forms: { has_password: boolean; has_card_like: boolean; has_phone: boolean; has_id_number_like: boolean;
           external_action: boolean }[];
}

export interface LabelVote { user: string; label: LabelValue; exclude_reason: ExcludeReason | null; note: string }

export interface Disagreement {
  snapshot_id: string; outcome: "DISAGREED" | "CONSENSUS"; labels: LabelVote[];
  consensus: (LabelVote & { user: string }) | null;
}

export interface LabelSummary {
  sample_rate: number; total_snapshots: number; sample_size: number; collector_errors: number; labelers: string[]; is_labeler: boolean;
  done_by: Record<string, number>; outcomes: Record<"PENDING" | "AGREED" | "DISAGREED" | "CONSENSUS", number>;
  both_labeled: number; percent_agreement: number | null; kappa: number | null;
  final_by_label: Record<string, number>; excluded_by_reason: Record<string, number>;
}
