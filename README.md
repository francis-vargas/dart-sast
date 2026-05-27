# dart_sast

> **Static Application Security Testing (SAST) for Dart / Flutter**
> Ferramenta CLI que analisa código-fonte Dart/Flutter em busca de padrões de vulnerabilidade conhecidos, com saída em console, JSON, HTML e SARIF.

---

## Descrição do Problema

Aplicações Flutter estão presentes em bilhões de dispositivos móveis. Entretanto, a falta de ferramentas SAST nativas para a linguagem Dart faz com que vulnerabilidades comuns — como segredos hardcoded, uso de criptografia fraca, comunicação via HTTP sem TLS e validação incorreta de certificados — passem despercebidas durante o desenvolvimento.

`dart_sast` preenche essa lacuna realizando análise estática diretamente sobre o código-fonte `.dart` e `pubspec.yaml`, sem necessidade de compilar ou executar o projeto.

## Motivação

- Dart/Flutter carecem de ferramentas SAST maduras comparadas a ecossistemas como Java ou Python.
- Vulnerabilidades de segurança em apps móveis têm alto impacto (dados de usuários, chaves de API).
- A análise estática é a forma mais custo-efetiva de detectar problemas ainda na fase de desenvolvimento.
- Atende ao fluxo de CI/CD com saída SARIF compatível com GitHub Code Scanning.

## Regras implementadas

| ID            | Severidade | CWE      | Descrição                                      |
|---------------|------------|----------|------------------------------------------------|
| DART-SEC-001  | CRITICAL   | CWE-798  | Segredo ou credencial hardcoded                |
| DART-SEC-002  | HIGH       | CWE-319  | URL HTTP sem TLS                               |
| DART-SEC-003  | HIGH       | CWE-327  | Primitiva criptográfica fraca (MD5, SHA-1…)    |
| DART-SEC-004  | HIGH       | CWE-338  | Aleatoriedade criptograficamente insegura      |
| DART-SEC-005  | CRITICAL   | CWE-89   | Potencial SQL Injection                        |
| DART-SEC-006  | MEDIUM     | CWE-532  | Dados sensíveis em logs                        |
| DART-SEC-007  | MEDIUM     | CWE-215  | Modo debug habilitado em produção              |
| DART-SEC-008  | HIGH       | CWE-312  | Dados sensíveis em SharedPreferences           |
| DART-SEC-009  | CRITICAL   | CWE-295  | Validação de certificado TLS desabilitada      |
| DART-SEC-010  | HIGH       | CWE-22   | Potencial Path Traversal                       |
| DART-SEC-011  | MEDIUM     | CWE-926  | Exposição de dados via MethodChannel           |
| DART-SEC-012  | LOW        | CWE-1104 | Versão de SDK desatualizada no pubspec.yaml    |

## Dependências

- **Python** ≥ 3.9 (sem dependências externas para execução principal)
- **pytest** ≥ 7.0 (apenas para testes)

## Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/dart_sast.git
cd dart_sast

# (Opcional) Crie um ambiente virtual
python -m venv .venv && source .venv/bin/activate

# Instale em modo desenvolvimento (inclui pytest)
pip install -e ".[dev]"
```

## Execução

```bash
# Escanear um diretório Flutter completo (saída console)
python -m dart_sast ./meu_projeto_flutter

# Escanear um arquivo específico
python -m dart_sast lib/services/auth_service.dart

# Gerar relatório HTML
python -m dart_sast ./meu_projeto_flutter --output html --out-file report.html

# Gerar relatório JSON
python -m dart_sast ./meu_projeto_flutter --output json --out-file findings.json

# Gerar SARIF (compatível com GitHub Code Scanning)
python -m dart_sast ./meu_projeto_flutter --output sarif --out-file results.sarif

# Filtrar por severidade mínima
python -m dart_sast ./meu_projeto_flutter --severity HIGH

# Integração CI: falha com exit code 1 se houver CRITICAL
python -m dart_sast ./meu_projeto_flutter --fail-on CRITICAL

# Listar todas as regras disponíveis
python -m dart_sast --list-rules
```

## Exemplos de Uso

### Saída console
```
[CRITICAL] DART-SEC-001 — Hardcoded Secret or Credential
  📍 lib/config.dart:12:14
  A potential secret, API key, password, or token was found hardcoded...
  Snippet  : const apiKey = "sk-prod-1234567890abcdef";
  Suggest  : Store secrets in environment variables or flutter_dotenv.
  CWE      : CWE-798
```

### Integração com GitHub Actions
```yaml
- name: Run dart_sast
  run: |
    pip install dart_sast
    python -m dart_sast . --output sarif --out-file results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Estrutura do Repositório

```
dart_sast/
├── dart_sast/
│   ├── __init__.py       # Exports públicos da biblioteca
│   ├── __main__.py       # CLI (argparse, formatação de saída)
│   ├── analyzer.py       # Engine de análise e regras SAST
│   └── reporter.py       # Renderizadores HTML e SARIF
├── tests/
│   ├── samples/
│   │   └── vulnerable_app.dart   # Código intencionalmente vulnerável
│   └── test_rules.py     # 17 testes unitários (pytest)
├── pyproject.toml
└── README.md
```

## Testes

```bash
# Executar todos os testes
pytest tests/ -v

# Com cobertura de código
pytest tests/ --cov=dart_sast --cov-report=term-missing
```

Resultado esperado: **17 passed** cobrindo detecção positiva, negativa e integração.

## Critérios de Avaliação de Artefato Científico

| Critério           | Como este artefato atende |
|--------------------|---------------------------|
| **Disponibilidade**     | Código aberto no GitHub sob licença MIT |
| **Funcionalidade**      | Ferramenta executável com CLI, 12 regras, 4 formatos de saída, 17 testes automatizados |
| **Sustentabilidade**    | Sem dependências externas de runtime; Python puro; estrutura de regras extensível via herança |
| **Reprodutibilidade**   | `pip install` + `python -m dart_sast` reproduz resultados; arquivo de amostra vulnerável incluso |

## Referências

- OWASP Mobile Security Testing Guide (MSTG): https://owasp.org/www-project-mobile-security-testing-guide/
- CWE/SANS Top 25: https://cwe.mitre.org/top25/
- Dart Security Guidelines: https://dart.dev/security
- SARIF 2.1.0 Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- Flutter Secure Storage: https://pub.dev/packages/flutter_secure_storage

## Licença

MIT © 2025