# 🔍 SAST Tool

A language-agnostic **Static Application Security Testing** scanner built in Python. Detects security vulnerabilities in source code across any language using a YAML-based rule engine, with terminal, JSON, and HTML report output.

[![CI](https://github.com/yourusername/sast-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/sast-tool/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED)](https://hub.docker.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Features

- **Language-agnostic** — scans Python, Java, Kotlin, JavaScript/TypeScript, C#, Go, Ruby, PHP, Shell, YAML, Terraform, and more
- **YAML rule engine** — rules are human-readable, version-controlled, and trivially extensible (no code required to add detections)
- **Rule categories**: Injection, Secrets, Cryptography, Authentication, Misconfiguration, Path Traversal
- **Three output formats**: rich terminal output, JSON (for CI/CD integration), HTML report with severity filtering
- **Inline suppression**: annotate false positives with `# sast-ignore` or `# nosec`
- **CI/CD exit codes**: fails builds when findings exceed a configurable severity threshold
- **Docker-first**: zero local dependencies, runs anywhere

---

## Rule Coverage

| Rule ID    | Title                                       | Severity | Category       | CWE       | OWASP             |
|------------|---------------------------------------------|----------|----------------|-----------|-------------------|
| INJ-001    | SQL Injection — String Concatenation        | CRITICAL | Injection      | CWE-89    | A03:2021          |
| INJ-002    | Command Injection — Shell Execution         | CRITICAL | Injection      | CWE-78    | A03:2021          |
| INJ-003    | XSS — Unsafe HTML Rendering                 | HIGH     | Injection      | CWE-79    | A03:2021          |
| INJ-004    | LDAP Injection                              | HIGH     | Injection      | CWE-90    | A03:2021          |
| INJ-005    | Server-Side Template Injection              | CRITICAL | Injection      | CWE-94    | A03:2021          |
| SEC-001    | Hardcoded AWS Access Key                    | CRITICAL | Secrets        | CWE-798   | A07:2021          |
| SEC-002    | Hardcoded Password / Secret                 | HIGH     | Secrets        | CWE-798   | A07:2021          |
| SEC-003    | Private Key Material in Source              | CRITICAL | Secrets        | CWE-321   | A02:2021          |
| SEC-004    | Hardcoded JWT Secret                        | CRITICAL | Secrets        | CWE-798   | A02:2021          |
| SEC-005    | GitHub / Bearer Token Pattern               | HIGH     | Secrets        | CWE-798   | A07:2021          |
| SEC-006    | Database Connection String with Credentials | HIGH     | Secrets        | CWE-798   | A07:2021          |
| CRYPTO-001 | Weak Hashing — MD5                          | HIGH     | Cryptography   | CWE-327   | A02:2021          |
| CRYPTO-002 | Weak Hashing — SHA-1                        | MEDIUM   | Cryptography   | CWE-327   | A02:2021          |
| CRYPTO-003 | Insecure Random Number Generation           | HIGH     | Cryptography   | CWE-338   | A02:2021          |
| CRYPTO-004 | Hardcoded Cryptographic Salt                | HIGH     | Cryptography   | CWE-760   | A02:2021          |
| CRYPTO-005 | ECB Mode Encryption                         | HIGH     | Cryptography   | CWE-327   | A02:2021          |
| CRYPTO-006 | SSL/TLS Certificate Validation Disabled     | CRITICAL | Cryptography   | CWE-295   | A02:2021          |
| AUTHN-001  | JWT Algorithm None Attack Vector            | CRITICAL | Authentication | CWE-347   | A07:2021          |
| AUTHN-002  | Insecure Session Configuration              | HIGH     | Authentication | CWE-614   | A07:2021          |
| AUTHN-003  | Weak Password Policy                        | MEDIUM   | Authentication | CWE-521   | A07:2021          |
| AUTHN-004  | Timing Attack in Auth Comparison            | MEDIUM   | Authentication | CWE-208   | A07:2021          |
| AUTHN-005  | Insecure Direct Object Reference (IDOR)     | HIGH     | Authorization  | CWE-639   | A01:2021          |
| MISC-001   | Path Traversal — Unsanitized File Path      | HIGH     | Path Traversal | CWE-22    | A01:2021          |
| MISC-002   | Debug Mode Enabled                          | HIGH     | Misconfiguration | CWE-489 | A05:2021          |
| MISC-003   | XML External Entity (XXE)                   | HIGH     | Injection      | CWE-611   | A05:2021          |
| MISC-004   | Unrestricted File Upload                    | HIGH     | Misconfiguration | CWE-434 | A04:2021          |
| MISC-005   | CORS Wildcard / Reflected Origin            | MEDIUM   | Misconfiguration | CWE-942 | A05:2021          |
| MISC-006   | Insecure Deserialization                    | CRITICAL | Injection      | CWE-502   | A08:2021          |

---

## Quick Start

### Docker (recommended — zero dependencies)

```bash
# Build
docker build -t sast-tool .

# Scan a project
docker run --rm -v $(pwd):/src sast-tool /src

# HTML report
docker run --rm \
  -v $(pwd):/src \
  -v $(pwd)/reports:/reports \
  sast-tool /src --format html --output /reports/report.html

# JSON + HTML
docker run --rm \
  -v $(pwd):/src \
  -v $(pwd)/reports:/reports \
  sast-tool /src --format all --output /reports/
```

### Local (Python 3.10+)

```bash
git clone https://github.com/yourusername/sast-tool
cd sast-tool
pip install -r requirements.txt

# Scan
python main.py ./myproject

# HTML report
python main.py ./myproject --format html --output report.html

# All formats
python main.py ./myproject --format all --output ./reports/
```

---

## Output Formats

### Terminal
Rich-formatted output with severity-colour-coded findings, file locations, and remediation advice.

```
╭─ 💀 CRITICAL  SQL Injection — String Concatenation  INJ-001 ──────────╮
│ api/users.py:42                                                         │
│ cursor.execute("SELECT * FROM users WHERE id = " + user_id)             │
│                                                                         │
│ User-controlled input is concatenated directly into a SQL query...      │
╰─────────────────────────────────────────────────────────────────────────╯
```

### JSON
Machine-readable output suitable for SIEM ingestion, CI dashboards, or further processing:
```bash
python main.py ./src --format json --output results.json
```

### HTML
Interactive report with severity filtering, CWE/OWASP references, and remediation guidance. Open `report.html` in any browser — no server required.

---

## CI/CD Integration

The tool exits with code `1` when findings meet or exceed the configured severity threshold, failing the pipeline:

```yaml
# GitHub Actions
- name: SAST Scan
  run: |
    docker run --rm -v ${{ github.workspace }}:/src \
      sast-tool /src \
      --format json \
      --output /tmp/sast-results.json \
      --fail-on HIGH
```

Use `--fail-on none` to run in audit mode without failing builds.

---

## Writing Custom Rules

Rules are plain YAML. No code required:

```yaml
# rules/my-rules.yaml
rules:
  - id: CUSTOM-001
    title: Dangerous Function Usage
    description: >
      The eval() function executes arbitrary code and should never be
      used with untrusted input.
    severity: CRITICAL
    category: INJECTION
    cwe: CWE-94
    owasp: A03:2021 - Injection
    languages: ["python", "javascript"]
    remediation: >
      Replace eval() with safer alternatives. For JSON parsing, use
      json.loads(). For math expressions, use ast.literal_eval().
    patterns:
      - regex: '\beval\s*\('
        confidence: HIGH
```

Then run with your custom rules:
```bash
python main.py ./src --rules ./rules/my-rules.yaml
```

---

## Suppressing False Positives

Annotate a line with `# sast-ignore` or `# nosec` to suppress all findings on that line:

```python
token = os.environ.get("API_TOKEN", "dev-token-only")  # sast-ignore
```

---

## Architecture

```
sast-tool/
├── main.py                  # CLI entrypoint (argparse)
├── sast/
│   ├── scanner.py           # Core scan engine, Finding/ScanResult dataclasses
│   ├── rules.py             # YAML rule loader with validation
│   ├── languages.py         # File extension → language detection
│   └── formatters.py        # Terminal (rich), JSON, HTML output
├── rules/
│   ├── injection.yaml       # INJ-*  rules
│   ├── secrets.yaml         # SEC-*  rules
│   ├── cryptography.yaml    # CRYPTO-* rules
│   ├── authentication.yaml  # AUTHN-* rules
│   └── misconfiguration.yaml # MISC-* rules
├── tests/
│   ├── test_scanner.py      # Unit tests (pytest)
│   └── vulnerable_sample.py # Intentionally vulnerable file for demos
├── Dockerfile
└── requirements.txt
```

**Design decisions:**

- **Regex over AST** — AST parsing is language-specific and adds significant complexity. Regex patterns with confidence scoring achieve good coverage while remaining language-agnostic. For a production tool, layering in tree-sitter AST analysis per language would reduce false positives.
- **YAML rules** — Keeping rules data-driven (not code) means security teams can add/modify detections without touching the engine. This mirrors how production tools like Semgrep and Nuclei work.
- **Exit codes for CI** — AppSec tooling is most effective when embedded in pipelines. Configurable severity thresholds let teams adopt the tool incrementally.

---

## Extending the Tool

**Add a new language**: Update `sast/languages.py` extension map and add the language name to relevant rule `languages` fields.

**Add new rule categories**: Create a new YAML file in `rules/` — it's automatically discovered on startup.

**Add AST-based detection**: The `scanner.py` `_scan_file` method can be extended with language-specific AST passes alongside the existing regex engine.

---

## Running Tests

```bash
pip install pytest pytest-cov
pytest tests/ -v --cov=sast
```

---

## License

MIT — see [LICENSE](LICENSE)
