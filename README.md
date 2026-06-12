# WebTLS Risk Inspector

WebTLS Risk Inspector is a lightweight Python project for detecting local Web exposure risks, HTTP security configuration defects, and TLS certificate trust issues. It is designed as a transparent security risk programming project: the scanner does not depend on third-party security products, and the core logic is implemented with the Python standard library.

The project focuses on making common security configuration risks visible, measurable, and explainable. It scans selected ports, identifies basic Web service risks, checks HTTP security headers, detects directory indexing exposure, classifies Server header leakage, verifies HTTPS certificate trust, and generates both JSON and Markdown reports.

## Features

- TCP port exposure detection for selected local or remote hosts
- HTTP security header checks, including HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy
- Directory indexing exposure detection based on response body evidence
- Server version information leakage detection
- HTTPS certificate trust verification for self-signed or untrusted certificates
- Basic TLS protocol and cipher suite observation
- Rule-based risk scoring and severity classification
- Structured JSON output and readable Markdown report generation
- Reproducible local vulnerable HTTP/HTTPS demo environment

## Project Structure

```text
.
├── risk_scanner.py              # Main risk scanning program
├── demo_vulnerable_server.py    # Local vulnerable HTTP/HTTPS demo service
├── demo_site/                   # Demo Web root with intentionally exposed files
├── demo_certs/                  # Local self-signed certificate directory
├── results/                     # Reproducible experiment outputs
│   ├── exp1/
│   ├── exp2/
│   ├── exp3/
│   └── exp4/
├── figures/                     # Figures used by the research report
├── report.tex                   # LaTeX source of the full report
└── report.pdf                   # Compiled research report
```

## Requirements

- Python 3.10 or later
- No third-party Python packages are required
- OpenSSL is only needed if you want to regenerate the self-signed demo certificate
- XeLaTeX or a compatible TeX distribution is only needed if you want to rebuild `report.pdf`

## Quick Start

Generate the local self-signed certificate before starting the HTTPS demo:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout demo_certs/key.pem -out demo_certs/cert.pem \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=NormalTime Lab/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1"
```

Start the intentionally weak demo service:

```bash
python3 demo_vulnerable_server.py
```

The demo service listens on:

- `http://127.0.0.1:8080` for weak HTTP configuration
- `https://127.0.0.1:8443` for self-signed HTTPS certificate testing

In another terminal, run the scanner:

```bash
python3 risk_scanner.py --host 127.0.0.1 --ports 80,443,8080,8443 --output-dir results/exp4
```

After the scan finishes, check the generated report:

```bash
cat results/exp4/scan_report.md
```

## Reproduce the Experiments

Experiment 1 scans the basic local Web exposure scenario. Keep the demo service running and execute:

```bash
python3 risk_scanner.py --host 127.0.0.1 --ports 80,443,8080 --output-dir results/exp1
```

Experiment 2 expands the port range to observe how additional exposed services influence the risk score:

```bash
python3 risk_scanner.py --host 127.0.0.1 --ports 21,22,23,80,443,3306,6379,8080 --output-dir results/exp2
```

Experiment 3 is a baseline scan without the demo service. Stop `demo_vulnerable_server.py` first, then execute:

```bash
python3 risk_scanner.py --host 127.0.0.1 --ports 80,443,8080 --output-dir results/exp3
```

Experiment 4 verifies the HTTPS self-signed certificate detection logic. Start the demo service again and execute:

```bash
python3 risk_scanner.py --host 127.0.0.1 --ports 80,443,8080,8443 --output-dir results/exp4
```

## Experiment Results

Each experiment directory contains:

- `scan_result.json`: complete structured scan result
- `scan_report.md`: human-readable risk report

Current reproduced results:

| Experiment | Scenario | Score | Level |
| --- | --- | ---: | --- |
| `exp1` | Basic scan with weak HTTP demo service | 76 | Medium |
| `exp2` | Expanded port range scan | 81 | High |
| `exp3` | Baseline scan without demo service | 0 | Low |
| `exp4` | HTTP risks plus self-signed HTTPS certificate | 88 | High |

## Regenerate the Demo Certificate

The HTTPS demo requires a local self-signed certificate. Certificate files are intentionally ignored by Git because they include a private key. If you need to regenerate them, run:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout demo_certs/key.pem -out demo_certs/cert.pem \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=NormalTime Lab/CN=127.0.0.1" \
  -addext "subjectAltName=IP:127.0.0.1"
```

## Research Report

The full report is available as:

- `report.pdf`: compiled report
- `report.tex`: LaTeX source

The report explains the system design, code implementation, experiment process, risk scoring model, comparison with mainstream security scanning tools, prevention measures, and appendices for reproducibility.

## Notes

This project is intended for controlled local security experiments and educational risk analysis. Do not scan systems without permission.
