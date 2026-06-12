#!/usr/bin/env python3
"""
本地网络资产与 Web 安全配置风险检测系统

功能：
1. 扫描指定主机的端口开放情况
2. 对 HTTP/HTTPS 服务进行基础安全配置检查
3. 根据规则计算风险分值并输出 JSON / Markdown 报告
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPConnection, HTTPSConnection
from pathlib import Path
from typing import Dict, List, Optional


RISK_PORTS: Dict[int, tuple[str, str, int]] = {
    21: ("FTP", "FTP 明文传输账号口令，存在被嗅探风险。", 20),
    23: ("Telnet", "Telnet 明文传输，远程管理风险较高。", 25),
    80: ("HTTP", "仅暴露 HTTP 可能导致流量明文传输。", 10),
    443: ("HTTPS", "HTTPS 端口正常，但仍需检查证书与安全头。", 0),
    3306: ("MySQL", "数据库端口直接暴露可能带来弱口令和越权访问风险。", 20),
    6379: ("Redis", "Redis 端口若未鉴权直接暴露，风险极高。", 30),
    8080: ("HTTP-Alt", "备用 Web 端口常用于测试服务，配置疏漏概率较高。", 10),
    8443: ("HTTPS-Alt", "备用 HTTPS 端口常用于测试环境，需重点核查证书可信性与协议配置。", 0),
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": 10,
    "Content-Security-Policy": 10,
    "X-Frame-Options": 8,
    "X-Content-Type-Options": 6,
    "Referrer-Policy": 4,
}


@dataclass
class Finding:
    title: str
    severity: str
    score: int
    evidence: str
    recommendation: str


@dataclass
class PortResult:
    port: int
    open: bool
    service: str
    risk_hint: str


def scan_port(host: str, port: int, timeout: float) -> PortResult:
    service, risk_hint, _ = RISK_PORTS.get(port, ("Unknown", "未知服务，请结合实际业务研判。", 5))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        open_flag = sock.connect_ex((host, port)) == 0
    finally:
        sock.close()
    return PortResult(port=port, open=open_flag, service=service, risk_hint=risk_hint)


def request_headers(host: str, port: int, use_https: bool, timeout: float) -> Optional[dict]:
    conn_cls = HTTPSConnection if use_https else HTTPConnection
    context = None
    if use_https:
        context = ssl.create_default_context()
        conn = conn_cls(host, port=port, timeout=timeout, context=context)
    else:
        conn = conn_cls(host, port=port, timeout=timeout)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        headers = {k: v for k, v in resp.getheaders()}
        body = resp.read(512).decode("utf-8", errors="ignore")
        headers["_status"] = str(resp.status)
        headers["_preview"] = body
        return headers
    except Exception:
        return None
    finally:
        conn.close()


def check_http_service(host: str, port: int, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    headers = request_headers(host, port, use_https=False, timeout=timeout)
    if not headers:
        return findings

    server = headers.get("Server", "未返回")
    if server and "/" in server:
        findings.append(
            Finding(
                title="Server 版本信息暴露",
                severity="medium",
                score=8,
                evidence=f"端口 {port} 返回 Server 头: {server}",
                recommendation="隐藏精确版本号，仅保留必要产品标识，降低被针对性攻击概率。",
            )
        )

    for header, score in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(
                Finding(
                    title=f"缺少安全响应头 {header}",
                    severity="medium" if score >= 8 else "low",
                    score=score,
                    evidence=f"端口 {port} 响应中未发现 {header}",
                    recommendation=f"在 Web 服务或反向代理中补充 {header} 配置。",
                )
            )

    preview = headers.get("_preview", "").lower()
    if "index of /" in preview:
        findings.append(
            Finding(
                title="疑似目录索引暴露",
                severity="high",
                score=20,
                evidence=f"端口 {port} 页面内容包含 'Index of /'",
                recommendation="关闭目录浏览功能，避免静态资源、日志或备份文件被遍历获取。",
            )
        )

    return findings


SELF_SIGNED_VERIFY_CODES = {18, 19}


def _classify_cert_verification_error(host: str, port: int, exc: ssl.SSLCertVerificationError) -> Finding:
    code = exc.verify_code
    message = exc.verify_message or str(exc)
    if code in SELF_SIGNED_VERIFY_CODES or "self signed" in message or "self-signed" in message:
        return Finding(
            title="HTTPS 证书为自签名证书",
            severity="medium",
            score=12,
            evidence=f"{host}:{port} 证书校验失败：{message}（verify_code={code}）",
            recommendation="改用受信任 CA 签发的证书；如为内网场景，应部署私有 CA 并将根证书分发至客户端信任库。",
        )
    if "expired" in message:
        return Finding(
            title="HTTPS 证书已过期",
            severity="high",
            score=25,
            evidence=f"{host}:{port} 证书校验失败：{message}（verify_code={code}）",
            recommendation="立即更新证书并检查自动续期机制。",
        )
    return Finding(
        title="HTTPS 证书链校验失败",
        severity="medium",
        score=15,
        evidence=f"{host}:{port} 证书校验失败：{message}（verify_code={code}）",
        recommendation="检查证书链完整性，确认中间证书已正确部署，并核实证书与访问域名是否匹配。",
    )


def check_https_service(host: str, port: int, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    cert: dict = {}
    cipher = None
    version = None

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
                cipher = wrapped.cipher()
                version = wrapped.version()
    except ssl.SSLCertVerificationError as exc:
        # 证书链或主机名校验失败：先记录该问题本身，再使用不校验证书的连接
        # 重新握手，以便继续提取协议版本与密码套件信息。
        findings.append(_classify_cert_verification_error(host, port, exc))
        try:
            insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            insecure_context.check_hostname = False
            insecure_context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with insecure_context.wrap_socket(sock, server_hostname=host) as wrapped:
                    cert = wrapped.getpeercert()
                    cipher = wrapped.cipher()
                    version = wrapped.version()
        except Exception:
            return findings
    except Exception as exc:
        findings.append(
            Finding(
                title="HTTPS 握手失败或证书异常",
                severity="high",
                score=25,
                evidence=f"连接 {host}:{port} 时出现异常: {exc}",
                recommendation="检查 TLS 配置、证书链和服务端监听状态。",
            )
        )
        return findings

    if version in {"TLSv1", "TLSv1.1"}:
        findings.append(
            Finding(
                title="TLS 协议版本过旧",
                severity="high",
                score=20,
                evidence=f"服务端协商出的 TLS 版本为 {version}",
                recommendation="停用 TLS 1.0/1.1，仅保留 TLS 1.2 及以上版本。",
            )
        )

    if cipher:
        cipher_name = cipher[0]
        if "RC4" in cipher_name or "3DES" in cipher_name:
            findings.append(
                Finding(
                    title="加密套件强度不足",
                    severity="high",
                    score=18,
                    evidence=f"当前协商密码套件为 {cipher_name}",
                    recommendation="关闭弱加密套件，启用现代 AEAD 套件。",
                )
            )

    not_after = cert.get("notAfter")
    if not_after:
        expire_at = parsedate_to_datetime(not_after)
        now = datetime.now(timezone.utc)
        days_left = (expire_at - now).days
        if days_left < 0:
            findings.append(
                Finding(
                    title="HTTPS 证书已过期",
                    severity="high",
                    score=25,
                    evidence=f"证书过期时间为 {expire_at.isoformat()}",
                    recommendation="立即更新证书并检查自动续期机制。",
                )
            )
        elif days_left <= 30:
            findings.append(
                Finding(
                    title="HTTPS 证书即将到期",
                    severity="medium",
                    score=10,
                    evidence=f"证书剩余有效期 {days_left} 天",
                    recommendation="提前续签证书，避免服务中断。",
                )
            )

    return findings


def calculate_port_risk(results: List[PortResult]) -> List[Finding]:
    findings: List[Finding] = []
    for result in results:
        if not result.open:
            continue
        _, hint, base_score = RISK_PORTS.get(result.port, ("Unknown", result.risk_hint, 5))
        if base_score > 0:
            severity = "high" if base_score >= 20 else "medium"
            findings.append(
                Finding(
                    title=f"开放端口 {result.port} 暴露风险",
                    severity=severity,
                    score=base_score,
                    evidence=f"{result.port}/{result.service} 处于开放状态。{hint}",
                    recommendation="确认端口是否必须对外开放；若非必要，应关闭或限制访问来源。",
                )
            )
    return findings


def summarize(findings: List[Finding]) -> dict:
    total = sum(item.score for item in findings)
    high = sum(1 for item in findings if item.severity == "high")
    medium = sum(1 for item in findings if item.severity == "medium")
    low = sum(1 for item in findings if item.severity == "low")
    if total >= 80 or high >= 3:
        level = "高风险"
    elif total >= 40 or high >= 1 or medium >= 4:
        level = "中风险"
    else:
        level = "低风险"
    return {
        "total_score": total,
        "risk_level": level,
        "high_count": high,
        "medium_count": medium,
        "low_count": low,
    }


def generate_markdown(host: str, ports: List[PortResult], findings: List[Finding], summary: dict) -> str:
    lines = [
        "# 本地网络资产与 Web 安全配置风险检测报告",
        "",
        f"- 扫描目标：`{host}`",
        f"- 扫描时间：`{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`",
        f"- 风险等级：`{summary['risk_level']}`",
        f"- 综合分值：`{summary['total_score']}`",
        "",
        "## 端口扫描结果",
        "",
        "| 端口 | 状态 | 服务 | 风险提示 |",
        "| --- | --- | --- | --- |",
    ]
    for item in ports:
        lines.append(
            f"| {item.port} | {'open' if item.open else 'closed'} | {item.service} | {item.risk_hint} |"
        )

    lines.extend(["", "## 风险明细", ""])
    if not findings:
        lines.append("未发现显著风险。")
    else:
        for index, item in enumerate(findings, 1):
            lines.extend(
                [
                    f"### {index}. {item.title}",
                    f"- 严重级别：`{item.severity}`",
                    f"- 风险分值：`{item.score}`",
                    f"- 证据：{item.evidence}",
                    f"- 建议：{item.recommendation}",
                    "",
                ]
            )

    lines.extend(
        [
            "## 统计摘要",
            "",
            f"- 高风险：{summary['high_count']} 项",
            f"- 中风险：{summary['medium_count']} 项",
            f"- 低风险：{summary['low_count']} 项",
        ]
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="本地网络资产与 Web 安全配置风险检测系统")
    parser.add_argument("--host", default="127.0.0.1", help="待扫描主机")
    parser.add_argument(
        "--ports",
        default="80,443,8000,8080",
        help="待扫描端口列表，使用英文逗号分隔",
    )
    parser.add_argument("--timeout", type=float, default=1.0, help="连接超时时间")
    parser.add_argument("--output-dir", default="results", help="输出目录")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ports = [int(item.strip()) for item in args.ports.split(",") if item.strip()]
    scan_results = [scan_port(args.host, port, args.timeout) for port in ports]

    findings = calculate_port_risk(scan_results)
    for item in scan_results:
        if item.open and item.port in {80, 8000, 8080}:
            findings.extend(check_http_service(args.host, item.port, args.timeout))
        if item.open and item.port in {443, 8443}:
            findings.extend(check_https_service(args.host, item.port, args.timeout))

    findings.sort(key=lambda x: x.score, reverse=True)
    summary = summarize(findings)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "target": args.host,
        "ports": [asdict(item) for item in scan_results],
        "findings": [asdict(item) for item in findings],
        "summary": summary,
        "generated_at": int(time.time()),
    }
    json_path = output_dir / "scan_result.json"
    md_path = output_dir / "scan_report.md"
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(generate_markdown(args.host, scan_results, findings, summary), encoding="utf-8")

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print(f"\n报告已生成：{md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
