"""
Rule loader — reads YAML rule definitions from the rules/ directory.
Rules are structured similarly to Semgrep for familiarity.
"""

import os
import yaml
from pathlib import Path
from typing import Optional


DEFAULT_RULES_PATH = Path(__file__).parent.parent / "rules"


class RuleLoader:
    def __init__(self, rules_path: Optional[str] = None):
        self.rules_path = Path(rules_path) if rules_path else DEFAULT_RULES_PATH

    def load_all(self) -> list[dict]:
        rules = []
        if not self.rules_path.exists():
            return rules

        for rule_file in sorted(self.rules_path.rglob("*.yaml")):
            try:
                loaded = self._load_file(rule_file)
                rules.extend(loaded)
            except Exception as e:
                print(f"[WARN] Failed to load rule file {rule_file}: {e}")

        return rules

    def _load_file(self, path: Path) -> list[dict]:
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return []

        validated = []
        for rule in data["rules"]:
            if self._validate(rule, path):
                validated.append(rule)
        return validated

    def _validate(self, rule: dict, source: Path) -> bool:
        required = ["id", "title", "description", "severity", "category", "patterns"]
        for field in required:
            if field not in rule:
                print(f"[WARN] Rule in {source} missing field '{field}', skipping.")
                return False

        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        if rule["severity"] not in valid_severities:
            print(f"[WARN] Rule '{rule['id']}' has invalid severity '{rule['severity']}', skipping.")
            return False

        return True
