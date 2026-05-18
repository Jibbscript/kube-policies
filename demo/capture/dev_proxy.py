#!/usr/bin/env python3
"""dev_proxy.py — minimal reverse proxy used by capture_dashboard_shots.

The dashboard SPA expects relative API paths (BASE_URL = "" in
web/src/lib/api.ts). To capture screenshots with populated tiles we need:
  - the built SPA served somewhere    (vite preview on :4173)
  - /api/* routed to policy-manager   (kubectl port-forward on :8091)

`vite preview` has no proxy config; `vite dev` triggers a Svelte 5
mount() lifecycle bug. So we run vite preview AND a tiny reverse proxy
here. Playwright hits this proxy at :PORT (default 8081):
  /api/*  → http://localhost:8091
  rest    → http://localhost:4173

No external Python deps — stdlib only.
"""
from __future__ import annotations

import argparse
import http.server
import urllib.error
import urllib.request


def make_handler(spa_origin: str, api_origin: str):
    class _Proxy(http.server.BaseHTTPRequestHandler):
        # Quieter logging — we don't want stderr spam during capture.
        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def _origin(self) -> str:
            return api_origin if self.path.startswith("/api/") else spa_origin

        def _proxy(self, method: str) -> None:
            target = self._origin() + self.path
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length > 0 else None
            req = urllib.request.Request(
                target,
                data=body,
                method=method,
                headers={
                    k: v
                    for k, v in self.headers.items()
                    if k.lower()
                    not in ("host", "content-length", "connection")
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    self.send_response(r.status)
                    for k, v in r.headers.items():
                        if k.lower() not in (
                            "connection",
                            "transfer-encoding",
                            "content-length",
                        ):
                            self.send_header(k, v)
                    payload = r.read()
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
            except urllib.error.HTTPError as e:
                payload = e.read() or b""
                self.send_response(e.code)
                for k, v in (e.headers or {}).items():
                    if k.lower() not in (
                        "connection",
                        "transfer-encoding",
                        "content-length",
                    ):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except Exception as exc:  # noqa: BLE001
                msg = f"dev_proxy upstream error for {target}: {exc}".encode()
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)

        def do_GET(self) -> None:  # noqa: N802
            self._proxy("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._proxy("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._proxy("PUT")

        def do_DELETE(self) -> None:  # noqa: N802
            self._proxy("DELETE")

    return _Proxy


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--spa", default="http://127.0.0.1:4173")
    p.add_argument("--api", default="http://127.0.0.1:8091")
    args = p.parse_args()

    handler = make_handler(args.spa, args.api)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(
        f"[dev_proxy] listening on http://127.0.0.1:{args.port}/  "
        f"(spa={args.spa}, api={args.api})",
        flush=True,
    )
    srv.serve_forever()


if __name__ == "__main__":
    main()
