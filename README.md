# dart_sast

> **Static Application Security Testing (SAST) for Dart / Flutter**
> Ferramenta CLI que analisa código-fonte Dart/Flutter em busca de 22 padrões de vulnerabilidade conhecidos, com saída em console, JSON, HTML, SARIF e DefectDojo.

[![CI](https://github.com/seu-usuario/dart-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/seu-usuario/dart-sast/actions)
[![PyPI](https://img.shields.io/pypi/v/dart-sast)](https://pypi.org/project/dart-sast/)
[![Docker](https://ghcr.io/seu-usuario/dart-sast)](https://github.com/seu-usuario/dart-sast/pkgs/container/dart-sast)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Descrição do Problema

Aplicações Flutter estão presentes em bilhões de dispositivos móveis. Entretanto, a falta de ferramentas SAST nativas para Dart faz com que vulnerabilidades comuns — segredos hardcoded, criptografia fraca, SQL Injection, SSRF, JWT inseguro — passem despercebidas durante o desenvolvimento.

`dart_sast` preenche essa lacuna realizando análise estática diretamente sobre `.dart` e `pubspec.yaml`, sem compilar ou executar o projeto.

## Motivação

- Dart/Flutter carecem de ferramentas SAST maduras comparadas a ecossistemas como Java ou Python.
- Vulnerabilidades em apps móveis têm alto impacto (dados de usuários, chaves de API).
- Regras em YAML permitem extensão sem alterar código Python.
- Saída SARIF integra com GitHub Code Scanning; DefectDojo JSON integra com gestão de vulnerabilidades.

---

## Instalação

### pip (recomendado)

```bash
pip install dart-sast
```

### Docker

```bash
# Escanear projeto atual
docker run --rm -v $(pwd):/src ghcr.io/seu-usuario/dart-sast /src

# Gerar relatório HTML
docker run --rm \
  -v $(pwd):/src \
  -v $(pwd)/reports:/reports \
  ghcr.io/seu-usuario/dart-sast \
  /src --output html --out-file /reports/report.html

# Usar regras customizadas
docker run --rm \
  -v $(pwd):/src \
  -v $(pwd)/my-rules:/rules \
  ghcr.io/seu-usuario/dart-sast \
  /src --rules-dir /rules
```

### GitHub Action

```yaml
# .github/workflows/security.yml
- name: Run dart_sast
  uses: seu-usuario/dart-sast@v1
  with:
    path: .
    output: sarif
    out-file: results.sarif
    fail-on: CRITICAL

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Código-fonte

```bash
git clone https://github.com/seu-usuario/dart-sast.git
cd dart-sast
pip install -e ".[dev]"
```

---

## Uso

```bash
# Escanear diretório Flutter (saída console)
dart-sast ./meu_projeto

# Relatório HTML
dart-sast ./meu_projeto --output html --out-file report.html

# Relatório JSON
dart-sast ./meu_projeto --output json --out-file findings.json

# SARIF para GitHub Code Scanning
dart-sast ./meu_projeto --output sarif --out-file results.sarif

# DefectDojo (importar via "Semgrep JSON Report")
dart-sast ./meu_projeto --output defectdojo --out-file dojo.json

# Filtrar por severidade mínima
dart-sast ./meu_projeto --severity HIGH

# Falhar CI se houver CRITICAL
dart-sast ./meu_projeto --fail-on CRITICAL

# Usar regras customizadas
dart-sast ./meu_projeto --rules-dir ./minhas-regras

# Listar todas as regras carregadas
dart-sast . --list-rules
```

---

## Uso como Biblioteca Python

```python
from dart_sast import analyze_directory, load_rules_from_dir

# Usar regras built-in
result = analyze_directory("./meu_projeto_flutter")

print(f"Arquivos escaneados: {result.files_scanned}")
print(f"Findings: {len(result.findings)}")

for finding in result.findings:
    print(f"[{finding.severity}] {finding.rule_id} — {finding.title}")
    print(f"  {finding.file}:{finding.line}")
    print(f"  {finding.suggestion}")

# Usar regras customizadas
custom_rules = load_rules_from_dir("./minhas-regras")
result = analyze_directory("./projeto", rules=custom_rules)

# Exportar para DefectDojo
from dart_sast.reporter import render_defectdojo
import json
dojo_payload = render_defectdojo(result)
json.dump(dojo_payload, open("dojo.json", "w"), indent=2)
```

---

## Regras (22)

| ID | Sev | CWE | Categoria | Descrição |
|----|-----|-----|-----------|-----------|
| DART-SEC-001 | CRITICAL | CWE-798 | Secrets | Credencial hardcoded |
| DART-SEC-002 | HIGH | CWE-319 | Network | URL HTTP sem TLS |
| DART-SEC-003 | HIGH | CWE-327 | Crypto | Algoritmo fraco (MD5, SHA-1) |
| DART-SEC-004 | HIGH | CWE-338 | Crypto | Random() não seguro |
| DART-SEC-005 | CRITICAL | CWE-89 | Injection | SQL Injection |
| DART-SEC-006 | MEDIUM | CWE-532 | Secrets | Dados sensíveis em logs |
| DART-SEC-007 | MEDIUM | CWE-215 | Misconfig | Debug mode ativo |
| DART-SEC-008 | HIGH | CWE-312 | Secrets | Dados sensíveis em SharedPreferences |
| DART-SEC-009 | CRITICAL | CWE-295 | Network | Validação TLS desabilitada |
| DART-SEC-010 | HIGH | CWE-22 | Injection | Path Traversal |
| DART-SEC-011 | MEDIUM | CWE-926 | Injection | Exposição via MethodChannel |
| DART-SEC-012 | LOW | CWE-1104 | Misconfig | SDK desatualizado |
| DART-SEC-013 | CRITICAL | CWE-78 | Injection | Command Injection (Process.run) |
| DART-SEC-014 | CRITICAL | CWE-918 | Injection | SSRF |
| DART-SEC-015 | HIGH | CWE-327 | Crypto | AES modo ECB |
| DART-SEC-016 | CRITICAL | CWE-347 | Crypto | JWT algoritmo "none" |
| DART-SEC-017 | HIGH | CWE-942 | Network | CORS wildcard |
| DART-SEC-018 | HIGH | CWE-598 | Network | Token/API key na URL |
| DART-SEC-019 | CRITICAL | CWE-287 | Secrets | Backdoor de autenticação |
| DART-SEC-020 | MEDIUM | CWE-209 | Misconfig | Stack trace exposto ao cliente |
| DART-SEC-021 | MEDIUM | CWE-521 | Misconfig | Política de senha fraca |
| DART-SEC-022 | LOW | CWE-1104 | Misconfig | Dependência sem versão fixada |

### Escrevendo regras customizadas

Crie um arquivo `.yaml` em qualquer diretório:

```yaml
rules:
  - id: MY-RULE-001
    title: Minha Regra Customizada
    message: Descrição do problema encontrado.
    severity: HIGH          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    metadata:
      cwe: CWE-XX
      owasp: "A01:2021"
      tags: [minha-tag]
    suggestion: Como corrigir.
    pattern:
      regex: 'padrao_perigoso\(\)'
      flags: IGNORECASE     # opcional
    languages: [dart]       # dart | yaml
```

```bash
dart-sast ./projeto --rules-dir ./minhas-regras
```

---

## Integração com DefectDojo

```bash
# 1. Gerar o relatório
dart-sast ./projeto --output defectdojo --out-file findings.json

# 2. Importar no DefectDojo:
#    Findings → Import → Scanner: "Semgrep JSON Report"
#    Upload: findings.json
```

---

## Dependências

- **Python** ≥ 3.9
- **pyyaml** ≥ 6.0

Sem dependências externas adicionais.

---

## Estrutura do Repositório

```
dart-sast/
├── Dockerfile                       # Imagem Docker
├── action.yml                       # GitHub Action
├── pyproject.toml                   # Configuração PyPI
├── dart_sast/
│   ├── __init__.py
│   ├── __main__.py                  # CLI
│   ├── analyzer.py                  # Engine + loader de regras YAML
│   └── reporter.py                  # HTML / SARIF / DefectDojo / JSON
├── rules/
│   ├── secrets.yaml                 # SEC-001, 006, 008, 019
│   ├── cryptography.yaml            # SEC-003, 004, 015, 016
│   ├── network.yaml                 # SEC-002, 009, 017, 018
│   ├── injection.yaml               # SEC-005, 010, 011, 013, 014
│   └── misconfiguration.yaml        # SEC-007, 012, 020, 021, 022
├── tests/
│   ├── test_rules.py                # 41 testes unitários
│   └── samples/vulnerable_app.dart  # Código vulnerável para demo
└── .github/workflows/
    ├── ci.yml                       # CI: testes + Docker + PyPI
    └── example-usage.yml            # Exemplo de uso em projetos externos
```

---

## Testes

```bash
pytest tests/ -v
pytest tests/ --cov=dart_sast --cov-report=term-missing
```

Resultado esperado: **41 passed**.

---

## Critérios de Avaliação de Artefato Científico

| Critério | Como este artefato atende |
|---|---|
| **Disponibilidade** | Código aberto no GitHub (MIT); imagem no GHCR; pacote no PyPI |
| **Funcionalidade** | 22 regras, 5 formatos de saída, GitHub Action, biblioteca Python, 41 testes |
| **Sustentabilidade** | Regras em YAML extensíveis sem alterar Python; CI automatizado; versionamento semântico |
| **Reprodutibilidade** | `pip install dart-sast` ou `docker run` reproduz resultados; amostra vulnerável inclusa |

---

## Referências

- OWASP Mobile Security Testing Guide: https://owasp.org/www-project-mobile-security-testing-guide/
- CWE/SANS Top 25: https://cwe.mitre.org/top25/
- NIST SP 800-63B (Password Guidelines): https://pages.nist.gov/800-63-3/sp800-63b.html
- SARIF 2.1.0 Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- Semgrep JSON Schema (DefectDojo): https://semgrep.dev/docs/semgrep-ci/findings/
- Flutter Secure Storage: https://pub.dev/packages/flutter_secure_storage

## Licença

MIT © 2025