# Changelog

All notable changes to dart_sast are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2025

### Added
- 22 SAST rules across 5 categories (secrets, cryptography, network, injection, misconfiguration)
- YAML-based rule engine — rules are decoupled from Python code
- CLI with 5 output formats: console, JSON, HTML, SARIF 2.1.0, DefectDojo (Semgrep JSON)
- Docker image published to GitHub Container Registry (`ghcr.io`)
- GitHub Action (`uses: seu-usuario/dart-sast@v1`)
- PyPI package (`pip install dart-sast`)
- 41 unit tests covering all rules, export schemas, and false-positive checks
- `--fail-on` flag for CI/CD exit-code integration
- `--rules-dir` flag for custom rule directories