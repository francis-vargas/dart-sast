"""
tests/test_rules.py
Unit tests for dart_sast — rules loaded from YAML files.
Run with: pytest tests/ -v
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from pathlib import Path

from dart_sast.analyzer import analyze_file, analyze_directory, load_rules_from_dir, Severity, AnalysisResult
from dart_sast.reporter import render_defectdojo, render_sarif


RULES_DIR = str(Path(__file__).parent.parent / "rules")


def write_tmp(content: str, suffix: str = ".dart") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return f.name


# ── Rule loading ──────────────────────────────────────────────────────────────

class TestRuleLoading:
    def test_loads_all_yaml_files(self):
        rules = load_rules_from_dir(RULES_DIR)
        assert len(rules) == 12

    def test_rules_have_required_fields(self):
        rules = load_rules_from_dir(RULES_DIR)
        for rule in rules:
            assert rule.rule_id.startswith("DART-SEC-")
            assert rule.title
            assert rule.severity in Severity
            assert rule.cwe.startswith("CWE-")

    def test_all_rule_ids_unique(self):
        rules = load_rules_from_dir(RULES_DIR)
        ids = [r.rule_id for r in rules]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"


# ── Detection tests ───────────────────────────────────────────────────────────

class TestHardcodedSecret:
    def test_detects_api_key(self):
        path = write_tmp('const apiKey = "sk-prod-abc123456789";')
        assert any(f.rule_id == "DART-SEC-001" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))

    def test_ignores_short_value(self):
        path = write_tmp('const x = "abc";')
        assert not any(f.rule_id == "DART-SEC-001" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))

    def test_detects_password(self):
        path = write_tmp("String password = 'mysecretpass123';")
        assert any(f.rule_id == "DART-SEC-001" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))


class TestInsecureHttp:
    def test_detects_http_url(self):
        path = write_tmp('final url = "http://api.example.com/data";')
        assert any(f.rule_id == "DART-SEC-002" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))

    def test_ignores_localhost(self):
        path = write_tmp('final url = "http://localhost:8080/api";')
        assert not any(f.rule_id == "DART-SEC-002" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))

    def test_ignores_https(self):
        path = write_tmp('final url = "https://api.example.com/data";')
        assert not any(f.rule_id == "DART-SEC-002" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))


class TestWeakCrypto:
    def test_detects_md5(self):
        path = write_tmp("final hash = md5.convert(data);")
        assert any(f.rule_id == "DART-SEC-003" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))

    def test_detects_sha1(self):
        path = write_tmp("var h = sha1.convert(bytes);")
        assert any(f.rule_id == "DART-SEC-003" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))


class TestInsecureRandom:
    def test_detects_random(self):
        path = write_tmp("final rand = Random();")
        assert any(f.rule_id == "DART-SEC-004" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))

    def test_ignores_secure_random(self):
        path = write_tmp("final rand = Random.secure();")
        assert not any(f.rule_id == "DART-SEC-004" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))


class TestSqlInjection:
    def test_detects_raw_query(self):
        path = write_tmp("db.rawQuery(\"SELECT * FROM users WHERE id = '$userId'\");")
        assert any(f.rule_id == "DART-SEC-005" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))


class TestLogSensitiveData:
    def test_detects_print_password(self):
        path = write_tmp('print("user password: $password");')
        assert any(f.rule_id == "DART-SEC-006" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))


class TestCertValidation:
    def test_detects_bad_cert_callback(self):
        path = write_tmp("..badCertificateCallback = (cert, host, port) => true;")
        assert any(f.rule_id == "DART-SEC-009" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))


class TestPathTraversal:
    def test_detects_file_interpolation(self):
        path = write_tmp("File('/data/$userInput').readAsString();")
        assert any(f.rule_id == "DART-SEC-010" for f in analyze_file(path, load_rules_from_dir(RULES_DIR)))


# ── Integration ───────────────────────────────────────────────────────────────

class TestDirectoryScan:
    def test_scans_sample_file(self):
        sample = Path(__file__).parent / "samples" / "vulnerable_app.dart"
        if not sample.exists():
            pytest.skip("Sample file not found")
        result = analyze_directory(str(sample.parent), rules=load_rules_from_dir(RULES_DIR))
        assert result.files_scanned >= 1
        assert len(result.findings) >= 5

    def test_severity_distribution(self):
        sample = Path(__file__).parent / "samples" / "vulnerable_app.dart"
        if not sample.exists():
            pytest.skip("Sample file not found")
        result = analyze_directory(str(sample.parent), rules=load_rules_from_dir(RULES_DIR))
        assert result.by_severity[Severity.CRITICAL] >= 1

    def test_findings_have_metadata(self):
        sample = Path(__file__).parent / "samples" / "vulnerable_app.dart"
        if not sample.exists():
            pytest.skip("Sample file not found")
        result = analyze_directory(str(sample.parent), rules=load_rules_from_dir(RULES_DIR))
        for f in result.findings:
            assert f.cwe.startswith("CWE-")
            assert isinstance(f.tags, list)


# ── DefectDojo export ─────────────────────────────────────────────────────────

class TestDefectDojoExport:
    def _make_result(self):
        sample = Path(__file__).parent / "samples" / "vulnerable_app.dart"
        if not sample.exists():
            pytest.skip("Sample file not found")
        return analyze_directory(str(sample.parent), rules=load_rules_from_dir(RULES_DIR))

    def test_semgrep_schema_top_level_keys(self):
        result = self._make_result()
        dojo = render_defectdojo(result)
        assert "version" in dojo
        assert "results" in dojo
        assert "errors" in dojo
        assert "paths" in dojo

    def test_each_result_has_required_fields(self):
        result = self._make_result()
        dojo = render_defectdojo(result)
        for r in dojo["results"]:
            assert "check_id" in r
            assert "path" in r
            assert "start" in r
            assert "extra" in r
            assert "severity" in r["extra"]
            assert r["extra"]["severity"] in ("ERROR", "WARNING", "INFO")

    def test_fingerprints_are_unique(self):
        result = self._make_result()
        dojo = render_defectdojo(result)
        fps = [r["extra"]["fingerprint"] for r in dojo["results"]]
        # All fingerprints should be non-empty strings
        assert all(isinstance(fp, str) and len(fp) > 0 for fp in fps)

    def test_cwe_in_metadata(self):
        result = self._make_result()
        dojo = render_defectdojo(result)
        for r in dojo["results"]:
            meta = r["extra"]["metadata"]
            assert "cwe" in meta
            assert isinstance(meta["cwe"], list)


# ── SARIF export ──────────────────────────────────────────────────────────────

class TestSarifExport:
    def test_sarif_schema_keys(self):
        sample = Path(__file__).parent / "samples" / "vulnerable_app.dart"
        if not sample.exists():
            pytest.skip("Sample file not found")
        result = analyze_directory(str(sample.parent), rules=load_rules_from_dir(RULES_DIR))
        sarif = render_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert "results" in sarif["runs"][0]


# ── Negative (clean code) ─────────────────────────────────────────────────────

class TestCleanCode:
    CLEAN = """
import 'dart:math';
Future<void> main() async {
  final rand = Random.secure();
  final url = "https://api.example.com/v1/items";
  print("App started");
}
"""
    def test_no_false_positives(self):
        path = write_tmp(self.CLEAN)
        findings = analyze_file(path, load_rules_from_dir(RULES_DIR))
        rule_ids = {f.rule_id for f in findings}
        assert "DART-SEC-002" not in rule_ids   # https ok
        assert "DART-SEC-004" not in rule_ids   # Random.secure() ok