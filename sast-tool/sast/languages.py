"""
Language detection based on file extension and content heuristics.
"""

from pathlib import Path

EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".swift": "swift",
    ".rs": "rust",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".tf": "terraform",
    ".hcl": "terraform",
    ".env": "dotenv",
    ".properties": "properties",
    ".cfg": "config",
    ".ini": "config",
    ".conf": "config",
    ".toml": "toml",
    ".sql": "sql",
    ".dockerfile": "dockerfile",
}


def detect_language(file_path: Path) -> str:
    name = file_path.name.lower()
    suffix = file_path.suffix.lower()

    # Special filenames
    if name == "dockerfile":
        return "dockerfile"
    if name in (".env", ".env.local", ".env.production", ".env.development"):
        return "dotenv"
    if name == "makefile":
        return "makefile"

    return EXTENSION_MAP.get(suffix, "unknown")
