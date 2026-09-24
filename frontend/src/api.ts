// API 클라이언트. 토큰은 sessionStorage(탭 종료 시 삭제)에만 두고, 모든 요청에 Authorization 헤더로 보낸다.
// 쿠키를 쓰지 않으므로 CSRF 가 성립하지 않는다.

const TOKEN_KEY = "safetrace.token";

export function getToken(): string {
  try { return sessionStorage.getItem(TOKEN_KEY) ?? ""; } catch { return ""; }
}
export function setToken(t: string): void {
  try { t ? sessionStorage.setItem(TOKEN_KEY, t) : sessionStorage.removeItem(TOKEN_KEY); } catch { /* 저장 불가 환경 */ }
}

export class ApiError extends Error {
  constructor(public status: number, public code: string) { super(`${status} ${code}`); }
}

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${getToken()}`);
  const r = await fetch(path, { ...init, headers, credentials: "omit", cache: "no-store" });
  if (!r.ok) {
    let code = "ERROR";
    try {
      const body = await r.json();
      code = body.error ?? (typeof body.detail === "string" ? body.detail : code);
    } catch { /* 본문 없음 */ }
    throw new ApiError(r.status, String(code));
  }
  return r;
}

export async function getJson<T>(path: string): Promise<T> {
  return (await request(path)).json() as Promise<T>;
}

export async function postJson<T>(path: string, body: unknown): Promise<T> {
  const r = await request(path, { method: "POST", body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" } });
  return r.json() as Promise<T>;
}

export async function postRaw<T>(path: string, body: Blob, contentType: string): Promise<T> {
  const r = await request(path, { method: "POST", body, headers: { "Content-Type": contentType } });
  return r.json() as Promise<T>;
}

/** 증거 파일을 인증 헤더와 함께 받아 blob URL 로 만든다(수집 HTML 은 절대 렌더링하지 않음). */
export async function evidenceBlobUrl(evidenceId: string): Promise<string> {
  const r = await request(`/api/evidence/${encodeURIComponent(evidenceId)}/content`);
  return URL.createObjectURL(await r.blob());
}

export async function downloadJson(path: string, filename: string): Promise<void> {
  const r = await request(path);
  const url = URL.createObjectURL(new Blob([await r.text()], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.rel = "noopener";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** 인증이 필요한 이미지 등을 blob URL 로 받는다. 사용 후 URL.revokeObjectURL 로 해제한다. */
export async function blobUrl(path: string): Promise<string> {
  const r = await request(path);
  return URL.createObjectURL(await r.blob());
}

export async function downloadText(path: string, filename: string, type: string): Promise<void> {
  const r = await request(path);
  const url = URL.createObjectURL(new Blob([await r.text()], { type }));
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.rel = "noopener";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
