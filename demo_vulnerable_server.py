#!/usr/bin/env python3
"""
用于演示的本地弱安全配置 HTTP 服务。

特点：
1. 暴露详细 Server 头
2. 缺少常见安全响应头
3. 真实暴露目录索引
4. 可点击查看伪造的备份、日志和配置文件
"""

from __future__ import annotations

import ssl
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


DEMO_ROOT = Path(__file__).resolve().parent / "demo_site"
CERT_DIR = Path(__file__).resolve().parent / "demo_certs"


class VulnerableHandler(SimpleHTTPRequestHandler):
    server_version = "Apache/2.4.49"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/backup.zip":
            body = """<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8" />
    <title>backup.zip</title>
    <style>
      body { font-family: Georgia, 'Times New Roman', serif; margin: 32px; line-height: 1.6; }
      h1 { margin-bottom: 0.3em; }
      .meta { color: #555; margin-bottom: 1.2em; }
      .box { border: 1px solid #ccc; padding: 16px; max-width: 900px; background: #fafafa; }
      ul { margin-top: 0.8em; }
      code { background: #f1f1f1; padding: 2px 5px; }
    </style>
  </head>
  <body>
    <h1>backup.zip</h1>
    <div class="meta">Archive generated: 2026-05-20 10:12:33 | Size: 24.7 MB | Exposure source: public web root</div>
    <div class="box">
      <p><strong>Warning:</strong> This page simulates an accidentally exposed backup archive.</p>
      <p>The archive package is expected to contain the following high-value files:</p>
      <ul>
        <li><code>db/customer_dump.sql</code></li>
        <li><code>config/prod.env</code></li>
        <li><code>nginx/nginx.conf</code></li>
        <li><code>logs/access-2026-05-19.log</code></li>
      </ul>
      <p>This kind of artifact is highly sensitive because it may leak database structure, credentials, hostnames, and service topology.</p>
      <p><a href="/">Return to parent directory</a></p>
    </div>
  </body>
</html>
""".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        super().do_GET()

    def end_headers(self) -> None:
        # 故意不设置常见安全响应头，用于演示弱配置风险。
        self.send_header("Server", self.server_version)
        super().end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def start_https_server() -> ThreadingHTTPServer | None:
    cert_file = CERT_DIR / "cert.pem"
    key_file = CERT_DIR / "key.pem"
    if not (cert_file.exists() and key_file.exists()):
        print(f"未找到自签名证书 {cert_file}，跳过 HTTPS 演示服务。")
        return None

    handler = partial(VulnerableHandler, directory=str(DEMO_ROOT))
    server = ThreadingHTTPServer(("127.0.0.1", 8443), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("Demo vulnerable server (self-signed HTTPS) running on https://127.0.0.1:8443")
    return server


def main() -> None:
    handler = partial(VulnerableHandler, directory=str(DEMO_ROOT))
    http_server = ThreadingHTTPServer(("127.0.0.1", 8080), handler)
    print("Demo vulnerable server running on http://127.0.0.1:8080")

    https_server = start_https_server()
    if https_server is not None:
        threading.Thread(target=https_server.serve_forever, daemon=True).start()

    http_server.serve_forever()


if __name__ == "__main__":
    main()
