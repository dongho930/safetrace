"""D1-S 시험 사이트 서버(127.0.0.1 전용). routes.json 의 HTTP 리다이렉트를 적용하고 site/ 정적 파일을 제공한다.

    python data/d1s/serve.py --port 8765
"""

from __future__ import annotations

import argparse
import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent


class Handler(SimpleHTTPRequestHandler):
    routes: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in self.routes:
            self.send_response(302)
            self.send_header("Location", self.routes[path])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/":
            self.path = "/index.html"
        super().do_GET()

    def log_message(self, *args) -> None:
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    Handler.routes = json.loads((HERE / "routes.json").read_text(encoding="utf-8"))
    server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(Handler, directory=str(HERE / "site")))
    print(f"D1-S site on http://127.0.0.1:{args.port}/")
    server.serve_forever()


if __name__ == "__main__":
    main()
