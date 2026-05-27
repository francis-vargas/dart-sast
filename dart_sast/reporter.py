"""
dart_sast/reporter.py
Renders AnalysisResult into HTML, SARIF, and DefectDojo-compatible formats.

DefectDojo import path:
  Findings → Import → "Semgrep JSON Report" scanner
  (matches Semgrep's --json output schema that DefectDojo already supports)
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict
from .analyzer import AnalysisResult, Severity


# ──────────────────────────────────────────────────────────────────────────────
#  Severity mappings
# ──────────────────────────────────────────────────────────────────────────────

_SEV_COLORS = {
    Severity.CRITICAL: "#ef4444",
    Severity.HIGH:     "#f97316",
    Severity.MEDIUM:   "#eab308",
    Severity.LOW:      "#3b82f6",
    Severity.INFO:     "#6b7280",
}

_SEV_BG = {
    Severity.CRITICAL: "#fef2f2",
    Severity.HIGH:     "#fff7ed",
    Severity.MEDIUM:   "#fefce8",
    Severity.LOW:      "#eff6ff",
    Severity.INFO:     "#f9fafb",
}

# DefectDojo / Semgrep severity string expected by the parser
_SEV_SEMGREP = {
    Severity.CRITICAL: "ERROR",
    Severity.HIGH:     "ERROR",
    Severity.MEDIUM:   "WARNING",
    Severity.LOW:      "INFO",
    Severity.INFO:     "INFO",
}


# ──────────────────────────────────────────────────────────────────────────────
#  DefectDojo — Semgrep JSON format
# ──────────────────────────────────────────────────────────────────────────────

def render_defectdojo(result: AnalysisResult) -> Dict[str, Any]:
    """
    Emit a JSON document that matches Semgrep's --json output schema.
    DefectDojo imports this via: Findings → Import → "Semgrep JSON Report".

    Schema reference:
      https://semgrep.dev/docs/semgrep-ci/findings/#semgrep-json-output
      DefectDojo parser: dojo/tools/semgrep/parser.py
    """
    errors: list = []
    results = []

    for f in result.findings:
        # Build the extra.metadata block — DefectDojo reads cwe/owasp from here
        metadata: Dict[str, Any] = {
            "cwe": [f.cwe] if f.cwe else [],
            "owasp": f.owasp or "",
            "confidence": "HIGH",
            "technology": ["dart", "flutter"],
            "category": "security",
            "subcategory": ["vuln"],
        }
        if hasattr(f, "tags") and f.tags:
            metadata["tags"] = f.tags

        results.append({
            "check_id": f.rule_id,
            "path": f.file,
            "start": {
                "line":   f.line,
                "col":    f.column,
                "offset": 0,
            },
            "end": {
                "line":   f.line,
                "col":    f.column + len(f.snippet.strip()),
                "offset": 0,
            },
            "extra": {
                "severity":    _SEV_SEMGREP[f.severity],
                "message":     f.description.strip(),
                "lines":       f.snippet.strip(),
                "fix":         f.suggestion.strip(),
                "metadata":    metadata,
                "fingerprint": _fingerprint(f),
            },
        })

    return {
        "version":    "1.0.0",
        "results":    results,
        "errors":     errors,
        "paths": {
            "scanned": list({f.file for f in result.findings}),
        },
    }


def _fingerprint(f: Any) -> str:
    """Stable dedup key used by DefectDojo to identify duplicate findings."""
    import hashlib
    raw = f"{f.rule_id}:{f.file}:{f.line}:{f.column}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ──────────────────────────────────────────────────────────────────────────────
#  SARIF 2.1.0
# ──────────────────────────────────────────────────────────────────────────────

def render_sarif(result: AnalysisResult) -> Dict[str, Any]:
    """Emit SARIF 2.1.0 — compatible with GitHub Code Scanning."""
    _sev_sarif = {
        Severity.CRITICAL: "error",
        Severity.HIGH:     "error",
        Severity.MEDIUM:   "warning",
        Severity.LOW:      "note",
        Severity.INFO:     "none",
    }

    # Collect unique rules
    seen_rules: Dict[str, Any] = {}
    for f in result.findings:
        if f.rule_id not in seen_rules:
            seen_rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "helpUri": (
                    f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html"
                    if f.cwe else "https://owasp.org/www-project-mobile-security-testing-guide/"
                ),
                "properties": {
                    "tags":  ["security", "dart"] + (f.tags or []),
                    "precision": "medium",
                    "problem.severity": _sev_sarif[f.severity],
                },
            }

    results_sarif = [
        {
            "ruleId": f.rule_id,
            "level": _sev_sarif[f.severity],
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine":   f.line,
                            "startColumn": f.column,
                            "snippet":     {"text": f.snippet.strip()},
                        },
                    }
                }
            ],
            "fixes": [
                {
                    "description": {"text": f.suggestion},
                }
            ] if f.suggestion else [],
        }
        for f in result.findings
    ]

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dart_sast",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/seu-usuario/dart_sast",
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results_sarif,
            }
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
#  HTML Report
# ──────────────────────────────────────────────────────────────────────────────

def render_html(result: AnalysisResult) -> str:
    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = result.by_severity

    summary_cards = ""
    for sev in Severity:
        c = counts[sev]
        color = _SEV_COLORS[sev]
        summary_cards += f"""
        <div class="sev-card" style="border-left:4px solid {color}">
          <span class="sev-count" style="color:{color}">{c}</span>
          <span class="sev-label">{sev.value}</span>
        </div>"""

    rows = ""
    if not result.findings:
        rows = '<tr><td colspan="6" style="text-align:center;padding:2rem;color:#6b7280">No findings 🎉</td></tr>'
    else:
        for f in sorted(result.findings, key=lambda x: (list(Severity).index(x.severity), x.file)):
            color = _SEV_COLORS[f.severity]
            bg    = _SEV_BG[f.severity]
            tags_html = " ".join(
                f'<span class="tag">{t}</span>' for t in (f.tags or [])
            )
            rows += f"""
            <tr>
              <td><span class="badge" style="background:{bg};color:{color};border:1px solid {color}">{f.severity.value}</span></td>
              <td class="mono small">{f.rule_id}</td>
              <td>
                <strong>{f.title}</strong><br>
                <span class="small muted">{f.description[:120]}…</span><br>
                <div class="tag-row">{tags_html}</div>
              </td>
              <td class="mono small">{f.file}:{f.line}</td>
              <td class="mono small code-snippet">{_esc(f.snippet.strip())}</td>
              <td class="small">
                {f.suggestion[:140]}
                <br><span class="cwe-tag">{f.cwe}</span>
                {f'<span class="owasp-tag">{f.owasp[:30]}</span>' if f.owasp else ""}
              </td>
            </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>dart_sast — Security Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Sora:wght@300;400;600;700&display=swap');
  :root {{
    --bg:#0f0f14;--surface:#16161f;--surface2:#1e1e2a;--border:#2a2a3a;
    --text:#e2e2f0;--muted:#6b6b8a;--accent:#7c6af7;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Sora',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}
  header{{background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);padding:3rem 2rem 2rem;border-bottom:1px solid var(--border);position:relative;overflow:hidden}}
  header::before{{content:'';position:absolute;top:-50%;right:-10%;width:400px;height:400px;background:radial-gradient(circle,rgba(124,106,247,.15),transparent 70%);border-radius:50%}}
  .header-inner{{max-width:1200px;margin:0 auto;position:relative}}
  .logo{{font-family:'JetBrains Mono',monospace;font-size:1.8rem;font-weight:600;color:#fff;letter-spacing:-1px}}
  .logo span{{color:var(--accent)}}
  .subtitle{{color:#8888aa;margin-top:.4rem;font-size:.9rem;font-weight:300}}
  .meta{{margin-top:1.5rem;display:flex;gap:2rem;flex-wrap:wrap}}
  .meta-item{{font-size:.8rem;color:#8888aa}}.meta-item strong{{color:#cccce0}}
  main{{max-width:1200px;margin:2rem auto;padding:0 2rem}}
  .summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:1rem;margin-bottom:2rem}}
  .sev-card{{background:var(--surface);border-radius:10px;padding:1.2rem 1rem;display:flex;flex-direction:column;gap:.3rem;border:1px solid var(--border);transition:transform .2s}}
  .sev-card:hover{{transform:translateY(-2px)}}
  .sev-count{{font-size:2rem;font-weight:700;font-family:'JetBrains Mono',monospace}}
  .sev-label{{font-size:.75rem;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}}
  .section-title{{font-size:1rem;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:2px;margin-bottom:1rem}}
  .table-wrap{{background:var(--surface);border-radius:12px;border:1px solid var(--border);overflow:hidden}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  thead th{{background:var(--surface2);padding:.8rem 1rem;text-align:left;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:1px;color:var(--muted);border-bottom:1px solid var(--border)}}
  tbody tr{{border-bottom:1px solid var(--border);transition:background .15s}}
  tbody tr:last-child{{border-bottom:none}}
  tbody tr:hover{{background:var(--surface2)}}
  td{{padding:.9rem 1rem;vertical-align:top}}
  .badge{{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.7rem;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:.5px}}
  .mono{{font-family:'JetBrains Mono',monospace}}.small{{font-size:.78rem}}.muted{{color:var(--muted);line-height:1.5}}
  .code-snippet{{background:#0d0d12;border-radius:4px;padding:.3rem .5rem!important;color:#a5b4fc;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
  .cwe-tag{{display:inline-block;margin-top:.4rem;background:rgba(124,106,247,.15);color:var(--accent);padding:.1rem .4rem;border-radius:3px;font-size:.7rem;font-family:'JetBrains Mono',monospace}}
  .owasp-tag{{display:inline-block;margin:.2rem 0 0 .3rem;background:rgba(234,179,8,.1);color:#eab308;padding:.1rem .4rem;border-radius:3px;font-size:.68rem}}
  .tag{{display:inline-block;margin:.2rem .15rem 0 0;background:rgba(255,255,255,.06);color:#888;padding:.1rem .35rem;border-radius:3px;font-size:.65rem;font-family:'JetBrains Mono',monospace}}
  .tag-row{{margin-top:.3rem}}
  footer{{text-align:center;padding:2rem;color:var(--muted);font-size:.75rem}}
</style>
</head>
<body>
<header>
  <div class="header-inner">
    <div class="logo">dart<span>_sast</span></div>
    <div class="subtitle">Static Application Security Testing for Dart / Flutter</div>
    <div class="meta">
      <div class="meta-item">Generated <strong>{generated}</strong></div>
      <div class="meta-item">Files scanned <strong>{result.files_scanned}</strong></div>
      <div class="meta-item">Total findings <strong>{len(result.findings)}</strong></div>
    </div>
  </div>
</header>
<main>
  <div class="summary-grid">{summary_cards}</div>
  <div class="section-title">Findings</div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th><th>Rule</th><th>Description</th>
          <th>Location</th><th>Snippet</th><th>Recommendation</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</main>
<footer>dart_sast &mdash; {generated}</footer>
</body>
</html>"""


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")