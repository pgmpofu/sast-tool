"""
Core SAST scanning engine.
Performs AST-aware and regex-based pattern matching across source files.
"""

import os
import re
import ast
import json
import hashlib
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime

from .rules import RuleLoader
from .languages import detect_language


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: str
    category: str
    file_path: str
    line_number: int
    line_content: str
    remediation: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    confidence: str = "MEDIUM"
    fingerprint: str = ""

    def __post_init__(self):
        self.fingerprint = hashlib.md5(
            f"{self.rule_id}:{self.file_path}:{self.line_number}:{self.line_content}".encode()
        ).hexdigest()[:12]


@dataclass
class ScanResult:
    scan_id: str
    target_path: str
    started_at: str
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    scan_duration_seconds: float = 0.0

    @property
    def summary(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        d = asdict(self)
        d["summary"] = self.summary
        d["total_findings"] = len(self.findings)
        return d


class Scanner:
    SKIP_DIRS = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", "target", ".idea", ".vscode", "vendor",
        "coverage", ".nyc_output", "eggs", "*.egg-info"
    }

    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt",
        ".cs", ".go", ".rb", ".php", ".cpp", ".c", ".h",
        ".swift", ".rs", ".scala", ".sh", ".bash", ".yaml",
        ".yml", ".json", ".xml", ".tf", ".hcl", ".env",
        ".properties", ".cfg", ".ini", ".conf", ".toml"
    }

    def __init__(self, rules_path: Optional[str] = None, severity_filter: Optional[list] = None,
                 category_filter: Optional[list] = None, exclude_paths: Optional[list] = None):
        self.rule_loader = RuleLoader(rules_path)
        self.rules = self.rule_loader.load_all()
        self.severity_filter = [s.upper() for s in severity_filter] if severity_filter else None
        self.category_filter = [c.upper() for c in category_filter] if category_filter else None
        self.exclude_paths = [re.compile(p) for p in (exclude_paths or [])]

    def scan(self, target: str) -> ScanResult:
        target_path = Path(target).resolve()
        scan_id = hashlib.md5(f"{target_path}{datetime.now().isoformat()}".encode()).hexdigest()[:8]

        result = ScanResult(
            scan_id=scan_id,
            target_path=str(target_path),
            started_at=datetime.now().isoformat()
        )

        start_time = datetime.now()

        if target_path.is_file():
            files = [target_path]
        else:
            files = list(self._collect_files(target_path))

        for file_path in files:
            findings = self._scan_file(file_path, str(target_path))
            if findings is None:
                result.files_skipped += 1
            else:
                result.files_scanned += 1
                result.findings.extend(findings)

        result.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file_path, f.line_number))
        result.finished_at = datetime.now().isoformat()
        result.scan_duration_seconds = (datetime.now() - start_time).total_seconds()

        return result

    def _collect_files(self, root: Path):
        for item in root.rglob("*"):
            if item.is_file():
                if any(skip in item.parts for skip in self.SKIP_DIRS):
                    continue
                if item.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
                    continue
                if self._is_excluded(str(item)):
                    continue
                yield item

    def _is_excluded(self, path: str) -> bool:
        return any(pattern.search(path) for pattern in self.exclude_paths)

    def _scan_file(self, file_path: Path, base_path: str) -> Optional[list[Finding]]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        language = detect_language(file_path)
        lines = content.splitlines()
        findings = []

        applicable_rules = [
            r for r in self.rules
            if (not r.get("languages") or language in r["languages"] or "*" in r["languages"])
            and (not self.severity_filter or r["severity"] in self.severity_filter)
            and (not self.category_filter or r["category"].upper() in self.category_filter)
        ]

        for rule in applicable_rules:
            for pattern_cfg in rule.get("patterns", []):
                regex = pattern_cfg.get("regex")
                if not regex:
                    continue
                try:
                    compiled = re.compile(regex, re.IGNORECASE | re.MULTILINE)
                except re.error:
                    continue

                for match in compiled.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    # Skip if inline suppression comment present
                    if "sast-ignore" in line_content or "nosec" in line_content:
                        continue

                    rel_path = os.path.relpath(str(file_path), base_path)

                    findings.append(Finding(
                        rule_id=rule["id"],
                        title=rule["title"],
                        description=rule["description"],
                        severity=rule["severity"],
                        category=rule["category"],
                        file_path=rel_path,
                        line_number=line_num,
                        line_content=line_content[:200],
                        remediation=rule.get("remediation", ""),
                        cwe=rule.get("cwe"),
                        owasp=rule.get("owasp"),
                        confidence=pattern_cfg.get("confidence", "MEDIUM"),
                    ))

        return findings
