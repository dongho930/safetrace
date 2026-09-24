// fetch 기반 SSE 리더. EventSource 는 헤더를 못 보내므로 토큰을 URL 에 싣지 않기 위해 직접 파싱한다.
// 연결이 끊기면 Last-Event-ID 로 이어받는다.

import { getToken } from "./api";
import type { PipelineEvent } from "./types";

export type SseState = "connecting" | "open" | "closed";

export function subscribe(onEvent: (e: PipelineEvent) => void, onState: (s: SseState) => void): () => void {
  let lastId = 0;
  let stopped = false;
  let ctrl: AbortController | null = null;

  async function loop(): Promise<void> {
    while (!stopped) {
      onState("connecting");
      ctrl = new AbortController();
      try {
        const r = await fetch("/api/events", {
          headers: { Authorization: `Bearer ${getToken()}`, "Last-Event-ID": String(lastId) },
          signal: ctrl.signal, cache: "no-store", credentials: "omit",
        });
        if (!r.ok || !r.body) throw new Error(`SSE ${r.status}`);
        onState("open");
        const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += value;
          let idx: number;
          while ((idx = buf.indexOf("\n\n")) >= 0) {
            const block = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            let data = "";
            for (const line of block.split("\n")) {
              if (line.startsWith("id: ")) lastId = Number(line.slice(4)) || lastId;
              else if (line.startsWith("data: ")) data += line.slice(6);
            }
            if (!data) continue;
            try { onEvent(JSON.parse(data) as PipelineEvent); } catch { /* 형식 오류 무시 */ }
          }
        }
      } catch {
        if (stopped) break;
      }
      onState("closed");
      if (!stopped) await new Promise((res) => setTimeout(res, 2000));
    }
  }
  void loop();
  return () => { stopped = true; ctrl?.abort(); };
}
