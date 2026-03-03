"""
Unit tests for the SAST scanner engine.
"""

import pytest
import tempfile
import os
from pathlib import Path

from sast.scanner import Scanner
from sast.languages import detect_language


@pytest.fixture
def scanner():
    return Scanner()


@pytest.fixture
def tmp_file():
    """Create a temporary Python file with known vulnerabilities."""
    content = '''
password = "hardcoded_password_123"
import subprocess
subprocess.call("ls " + user_input, shell=True)
import hashlib
h = hashlib.md5(data.encode()).hexdigest()
import pickle
obj = pickle.loads(untrusted_data)
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
import requests
r = requests.get(url, verify=False)
'''
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(content)
        yield f.name
    os.unlink(f.name)


class TestScanner:
    def test_scan_returns_result(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        assert result is not None
        assert result.files_scanned == 1

    def test_detects_hardcoded_password(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        rule_ids = [f.rule_id for f in result.findings]
        assert "SEC-002" in rule_ids

    def test_detects_command_injection(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        rule_ids = [f.rule_id for f in result.findings]
        assert "INJ-002" in rule_ids

    def test_detects_md5(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        rule_ids = [f.rule_id for f in result.findings]
        assert "CRYPTO-001" in rule_ids

    def test_detects_pickle(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        rule_ids = [f.rule_id for f in result.findings]
        assert "MISC-006" in rule_ids

    def test_detects_sql_injection(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        rule_ids = [f.rule_id for f in result.findings]
        assert "INJ-001" in rule_ids

    def test_detects_ssl_disabled(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        rule_ids = [f.rule_id for f in result.findings]
        assert "CRYPTO-006" in rule_ids

    def test_nosec_suppression(self, scanner):
        content = 'password = "secret123"  # sast-ignore\n'
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(content)
        try:
            result = scanner.scan(f.name)
            # Should not flag suppressed line
            assert not any(f.line_number == 1 and f.rule_id == "SEC-002" for f in result.findings)
        finally:
            os.unlink(f.name)

    def test_severity_filter(self, scanner, tmp_file):
        filtered = Scanner(severity_filter=["CRITICAL"])
        result = filtered.scan(tmp_file)
        for finding in result.findings:
            assert finding.severity == "CRITICAL"

    def test_scan_summary(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        summary = result.summary
        assert isinstance(summary, dict)
        assert sum(summary.values()) == len(result.findings)

    def test_findings_sorted_by_severity(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        orders = [severity_order.get(f.severity, 99) for f in result.findings]
        assert orders == sorted(orders)

    def test_clean_file_no_findings(self, scanner):
        content = '''
def add(a, b):
    return a + b

class Calculator:
    def multiply(self, x, y):
        return x * y
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(content)
        try:
            result = scanner.scan(f.name)
            assert len(result.findings) == 0
        finally:
            os.unlink(f.name)

    def test_fingerprint_uniqueness(self, scanner, tmp_file):
        result = scanner.scan(tmp_file)
        fingerprints = [f.fingerprint for f in result.findings]
        assert len(fingerprints) == len(set(fingerprints)), "Duplicate fingerprints found"


class TestLanguageDetection:
    def test_python(self):
        assert detect_language(Path("app.py")) == "python"

    def test_javascript(self):
        assert detect_language(Path("app.js")) == "javascript"

    def test_typescript(self):
        assert detect_language(Path("app.ts")) == "typescript"

    def test_java(self):
        assert detect_language(Path("Main.java")) == "java"

    def test_kotlin(self):
        assert detect_language(Path("Main.kt")) == "kotlin"

    def test_dockerfile(self):
        assert detect_language(Path("Dockerfile")) == "dockerfile"

    def test_dotenv(self):
        assert detect_language(Path(".env")) == "dotenv"

    def test_unknown(self):
        assert detect_language(Path("file.xyz")) == "unknown"
