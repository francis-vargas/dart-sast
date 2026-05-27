"""
dart_sast/analyzer.py
Core SAST analysis engine — loads rules from YAML files.
"""

import re
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    rule_id:     str
    title:       str
    description: str
    severity:    Severity
    cwe:         str
    owasp:       str
    tags:        List[str]
    file:        str
    line:        int
    column:      int
    snippet:     str
    suggestion:  str


@dataclass
class AnalysisResult:
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)

    @property
    def by_severity(self) -> Dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts


# ──────────────────────────────────────────────────────────────────────────────
#  YAML Rule loader
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_RULES_DIR = Path(__file__).parent.parent / "rules"

_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE":  re.MULTILINE,
    "DOTALL":     re.DOTALL,
}


def _compile_pattern(rule_def: Dict[str, Any]) -> Optional[re.Pattern]:
    pattern_def = rule_def.get("pattern", {})
    if not pattern_def:
        return None
    raw = pattern_def.get("regex", "")
    if not raw:
        return None
    # Normalize multi-line YAML scalars (strip embedded newlines/spaces)
    raw = re.sub(r"\s+", " ", raw).strip()
    flags = 0
    for flag_name in pattern_def.get("flags", "").split(","):
        flag_name = flag_name.strip().upper()
        if flag_name in _FLAG_MAP:
            flags |= _FLAG_MAP[flag_name]
    try:
        return re.compile(raw, flags)
    except re.error as exc:
        import warnings
        warnings.warn(f"Invalid regex in rule {rule_def.get('id', '?')}: {exc}")
        return None


class YamlRule:
    """A rule loaded from a YAML definition."""

    def __init__(self, definition: Dict[str, Any]) -> None:
        meta = definition.get("metadata", {})
        self.rule_id    = definition["id"]
        self.title      = definition["title"]
        self.description= definition.get("message", "")
        self.severity   = Severity(definition.get("severity", "MEDIUM"))
        self.cwe        = meta.get("cwe", "")
        self.owasp      = meta.get("owasp", "")
        self.tags       = meta.get("tags", [])
        self.suggestion = definition.get("suggestion", "").strip()
        self.languages  = definition.get("languages", [])
        self._pattern   = _compile_pattern(definition)

    def check_line(self, line: str, lineno: int, filepath: str) -> Optional[Finding]:
        if self._pattern is None:
            return None
        m = self._pattern.search(line)
        if m:
            return Finding(
                rule_id    = self.rule_id,
                title      = self.title,
                description= self.description.strip(),
                severity   = self.severity,
                cwe        = self.cwe,
                owasp      = self.owasp,
                tags       = self.tags,
                file       = filepath,
                line       = lineno,
                column     = m.start() + 1,
                snippet    = line.rstrip(),
                suggestion = self.suggestion,
            )
        return None


def load_rules_from_dir(rules_dir: Optional[str] = None) -> List[YamlRule]:
    """
    Load all rules from YAML files in `rules_dir`.
    Falls back to the built-in `rules/` directory next to the package.
    """
    if not _YAML_AVAILABLE:
        raise ImportError(
            "PyYAML is required to load rules. Install with: pip install pyyaml"
        )

    directory = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
    if not directory.exists():
        raise FileNotFoundError(f"Rules directory not found: {directory}")

    rules: List[YamlRule] = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        with open(yaml_file, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        for rule_def in data.get("rules", []):
            rules.append(YamlRule(rule_def))
    return rules


def _get_default_rules() -> List[YamlRule]:
    try:
        return load_rules_from_dir()
    except (ImportError, FileNotFoundError):
        return []


# ──────────────────────────────────────────────────────────────────────────────
#  Analysis functions
# ──────────────────────────────────────────────────────────────────────────────

_LANG_EXTENSIONS: Dict[str, List[str]] = {
    "dart": [".dart"],
    "yaml": [".yaml", ".yml"],
}


def _extensions_for_rules(rules: List[YamlRule]) -> set:
    exts = set()
    for rule in rules:
        if not rule.languages:
            exts.update([".dart", ".yaml", ".yml"])
        for lang in rule.languages:
            exts.update(_LANG_EXTENSIONS.get(lang, []))
    return exts or {".dart", ".yaml", ".yml"}


def analyze_file(
    filepath: str,
    rules: Optional[List[YamlRule]] = None,
) -> List[Finding]:
    if rules is None:
        rules = _get_default_rules()
    findings: List[Finding] = []
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                for rule in rules:
                    finding = rule.check_line(line, lineno, filepath)
                    if finding:
                        findings.append(finding)
    except OSError:
        pass
    return findings


def analyze_directory(
    root: str,
    rules: Optional[List[YamlRule]] = None,
    exclude_dirs: Optional[List[str]] = None,
    rules_dir: Optional[str] = None,
) -> AnalysisResult:
    """Recursively scan Dart/YAML files under `root`."""
    if rules is None:
        rules = load_rules_from_dir(rules_dir) if rules_dir else _get_default_rules()

    exclude_dirs = exclude_dirs or [".dart_tool", "build", ".git", ".idea"]
    target_extensions = _extensions_for_rules(rules)
    result = AnalysisResult()

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for filename in filenames:
            if Path(filename).suffix in target_extensions:
                full_path = os.path.join(dirpath, filename)
                result.files_scanned += 1
                result.findings.extend(analyze_file(full_path, rules))

    return result


# Convenience alias so existing code importing ALL_RULES doesn't break
ALL_RULES = _get_default_rules()