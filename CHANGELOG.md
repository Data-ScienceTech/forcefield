# Changelog

All notable changes to ForceField will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.2] - 2026-03-27

### Added

- `forcefield init` -- scaffold `.forcefield/constitution.yaml` for vibe coding governance (default/strict/permissive templates)
- `guard.audit_report()` -- generate structured JSON or Markdown audit reports from scan events
- `guard.eval()` -- run security eval suites (116 built-in attacks or custom YAML)
- Constitution engine -- YAML-driven governance rules for files, commands, tools, and content
- `guard.scan_command()` -- scan terminal commands for 22 dangerous patterns
- `guard.scan_filename()` -- scan filenames for 12 security-sensitive patterns
- `guard.protect_path()` / `guard.is_protected()` -- glob-based protected path management
- CLI commands: `forcefield init`, `forcefield eval`, `forcefield scan-command`, `forcefield scan-filename`
- GitHub Action for CI/CD integration (GitHub Marketplace listed)
- pre-commit hook support
- Homebrew tap (`brew tap datasciencetech/forcefield`)
- npm wrapper (`npx forcefield-ai`)
- VS Code extension with Sentinel Mode
- Open VSX Registry listing
- JetBrains Marketplace plugin

### Changed

- Multi-turn session tracker now detects crescendo and probe-then-inject sequences
- Anti-obfuscation normalizer handles zero-width chars, homoglyphs, leetspeak, and mixed scripts

## [0.6.0] - 2026-03-15

### Added

- ONNX ML model for prompt injection detection (95%+ accuracy, 235KB)
- TF-IDF + Random Forest ensemble scoring
- Endpoint security testing (`forcefield test <url>`)
- Cloud hybrid scoring via ForceField Gateway API
- Output moderation (hate speech, violence, credential leaks)
- Chat template validation (`forcefield validate-template`)
- LangChain callback handler (`langchain-forcefield` package)
- LlamaIndex callback handler (`llama-index-forcefield` package)
- OpenAI drop-in wrapper (`ForceFieldOpenAI`)
- FastAPI middleware (`ForceFieldMiddleware`)

## [0.5.0] - 2026-02-28

### Added

- PII detection for 18 types (SSN, credit card, email, phone, IBAN, JWT, API keys, etc.)
- PII redaction with configurable replacements
- Jinja2 chat template backdoor scanning
- Token smuggling and payload splitting detection
- Source file auditing (`forcefield audit <path>`)
- JSON and Markdown report output formats

## [0.4.0] - 2026-02-15

### Added

- Prompt injection detection across 12 categories with 60+ regex patterns
- Jailbreak and role escalation detection (DAN-style attacks)
- Data exfiltration detection (obfuscated destinations, JSON payloads)
- System prompt extraction detection
- Sensitivity levels (low/medium/high/critical) with configurable thresholds
- CLI selftest with 116 built-in attack prompts
- HTTP proxy mode (`forcefield serve`)

## [0.3.0] - 2026-02-01

### Added

- Initial public release
- Core `Guard` class with `scan()`, `redact()`, `moderate()` methods
- Regex-based detection engine (81% detection rate)
- CLI: `forcefield scan`, `forcefield redact`, `forcefield selftest`
- Python 3.9-3.13 support
- Zero external dependencies for core package
