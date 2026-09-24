import { useState } from "react";

export default function Login({ onLogin, error }: { onLogin: (t: string) => void; error: string }) {
  const [token, setToken] = useState("");
  return (
    <div className="login">
      <form className="login-card" onSubmit={(e) => { e.preventDefault(); if (token.trim()) onLogin(token.trim()); }}>
        <div className="brand"><span className="logo" aria-hidden>ST</span><strong>SafeTrace</strong></div>
        <p className="muted">공공기관 검토용 위협 의심 사이트 조사 콘솔</p>
        <label htmlFor="tok">접근 토큰</label>
        <input id="tok" type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)}
          placeholder="scripts/gen_secrets.py 가 출력한 토큰" />
        {error && <p className="error" role="alert">{error}</p>}
        <button type="submit" className="primary">로그인</button>
        <p className="hint">토큰은 이 탭의 세션 저장소에만 보관되며 탭을 닫으면 삭제됩니다.</p>
      </form>
    </div>
  );
}
