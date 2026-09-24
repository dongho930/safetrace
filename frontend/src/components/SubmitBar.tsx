import { useRef, useState } from "react";
import { ApiError, postJson, postRaw } from "../api";

export default function SubmitBar({ onSubmitted }: { onSubmitted: () => void }) {
  const [url, setUrl] = useState("");
  const [source, setSource] = useState("REPORT");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await postJson<{ normalized_url: string }>("/api/cases", { url: url.trim(), source });
      setMsg(`접수: ${r.normalized_url}`);
      setUrl("");
      onSubmitted();
    } catch (err) {
      setMsg(err instanceof ApiError ? `거부됨: ${err.code}` : "전송 실패");
    } finally {
      setBusy(false);
    }
  }

  async function uploadKisa(f: File) {
    if (f.size > 20_000_000) { setMsg("파일이 너무 큽니다(20MB 이하)."); return; }
    setBusy(true);
    try {
      const r = await postRaw<{ loaded: number; rejected: number; duplicates: number; submitted: number }>(
        "/api/seeds/kisa?limit=20", f, "text/csv");
      setMsg(`KISA 적재: 정상 ${r.loaded} · 거부 ${r.rejected} · 중복 ${r.duplicates} · 조사 등록 ${r.submitted}`);
      onSubmitted();
    } catch (err) {
      setMsg(err instanceof ApiError ? `거부됨: ${err.code}` : "업로드 실패");
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  return (
    <form className="submitbar" onSubmit={submit}>
      <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="출처">
        <option value="REPORT">신고 URL</option>
        <option value="KISA">KISA 피싱 URL</option>
      </select>
      <input type="url" required maxLength={2048} value={url} onChange={(e) => setUrl(e.target.value)}
        placeholder="조사할 URL (예: http://localhost:8765/p/phish-01.html)" aria-label="조사 URL" />
      <button className="primary" disabled={busy || !url}>조사 접수</button>
      <button type="button" className="ghost" disabled={busy} onClick={() => fileRef.current?.click()}>
        KISA CSV 적재
      </button>
      <input ref={fileRef} type="file" accept=".csv,text/csv" hidden
        onChange={(e) => { const f = e.target.files?.[0]; if (f) void uploadKisa(f); }} />
      {msg && <span className="submit-msg">{msg}</span>}
    </form>
  );
}
