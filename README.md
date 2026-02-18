[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![CI](https://github.com/luca-bellipanni/Multi-Agent-AI-Security-Pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/luca-bellipanni/Multi-Agent-AI-Security-Pipeline/actions)
[![Semgrep](https://img.shields.io/badge/SAST-Semgrep-orange.svg)](https://semgrep.dev/)
[![smolagents](https://img.shields.io/badge/agents-smolagents-blueviolet.svg)](https://github.com/huggingface/smolagents)
[![LiteLLM](https://img.shields.io/badge/LLM-LiteLLM%20100%2B%20providers-green.svg)](https://github.com/BerriAI/litellm)

# Agentic AppSec Pipeline

A GitHub Action that uses **AI agents** instead of static scanners for PR security analysis and **automated remediation**. Agents read the diff, choose the right Semgrep rulesets, filter noise, and explain findings — while a deterministic gate ensures the final verdict can't be manipulated. When findings need fixing, a Remediation Agent generates fixes on a draft PR, keeping humans in the loop.

```
                          WORKFLOW 1 — Scan (automatic on PR)
                          ─────────────────────────────────────
PR opened
    │
    ▼
┌──────────┐  context   ┌──────────────┐  raw findings   ┌──────────────┐
│  Triage  │──────────► │   AppSec     │──(side channel)─►│    Gate      │
│  Agent   │            │   Agent      │                  │(deterministic)│
│(3 steps) │            │(OODA, 10 st) │  AI report       │              │
└──────────┘            └──────────────┘─────────────────►│  ┌────────┐  │
 reads file metadata      reads diff,                     │  │verdict │  │
 assesses risk            runs Semgrep,                   │  └───┬────┘  │
 routes to specialist     filters findings                └──────┼───────┘
                                                                 │
                                          scan-results.json ◄────┘
                                          + PR comment with findings
                                                                 │
                          ─────────────────────────────────────  │
                          WORKFLOW 2 — Remediation (human-triggered)
                          ─────────────────────────────────────  │
                                                                 ▼
                                            maintainer comments /remediate
                                                                 │
                                                                 ▼
                                                       ┌─────────────────┐
                                                       │  Remediation    │
                                                       │  Agent          │
                                                       │  (OODA, 10 st) │
                                                       └────────┬────────┘
                                                                │
                                                    reads code, generates fix,
                                                    AST-validates, commits
                                                                │
                                                                ▼
                                                         Draft PR
                                                    (human reviews & merges)
```

**Key design choices:**
- **AI advises, code decides** — agents produce analysis, the Gate produces the verdict from raw scanner data via a side channel the agent can't tamper with
- **OODA loop** — agents observe, orient, decide, act, and can escalate with additional scans or fix attempts
- **Human-in-the-loop remediation** — fixes only trigger when a maintainer comments `/remediate`, land on a draft PR, never auto-merge
- **Severity mismatch detection** — if the agent downgrades a HIGH to MEDIUM, the Gate flags it as a warning
- **Works without AI** — no API key? Falls back to deterministic rules

## Quick Start

### Workflow 1 — Scan (runs on every PR)

```yaml
name: Security Scan
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: luca-bellipanni/Multi-Agent-AI-Security-Pipeline@main
        id: appsec
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          command: scan
          mode: shadow
          ai_api_key: ${{ secrets.AI_API_KEY }}
          ai_model: gpt-4o-mini
      - uses: actions/upload-artifact@v4
        with:
          name: scan-results
          path: .appsec/scan-results.json
```

### Workflow 2 — Remediation (triggered by `/remediate` comment)

```yaml
name: Security Remediation
on:
  issue_comment:
    types: [created]

jobs:
  remediate:
    if: |
      github.event.issue.pull_request &&
      startsWith(github.event.comment.body, '/remediate') &&
      contains(fromJson('["MEMBER","OWNER"]'),
        github.event.comment.author_association)
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - uses: dawidd6/action-download-artifact@v6
        with:
          workflow: Security Scan
          name: scan-results
          path: .appsec/
          search_artifacts: true
      - uses: luca-bellipanni/Multi-Agent-AI-Security-Pipeline@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          command: remediate
          ai_api_key: ${{ secrets.AI_API_KEY }}
```

## Configuration

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `github_token` | Yes | — | GitHub token for API access |
| `command` | No | `scan` | `scan` (analysis) or `remediate` (generate fixes) |
| `mode` | No | `shadow` | `shadow` (observe only) or `enforce` (can block PRs) |
| `ai_api_key` | No | — | API key for any LLM provider via [LiteLLM](https://docs.litellm.ai/docs/providers) |
| `ai_model` | No | `gpt-4o-mini` | Any model supported by LiteLLM |

| Output | Description |
|--------|-------------|
| `decision` | `allowed` · `manual_review` · `blocked` |
| `continue_pipeline` | `true` / `false` |
| `findings_count` | Total raw findings from scanner |
| `reason` | Human-readable explanation with AI reasoning |
| `safety_warnings_count` | Safety net warnings (agent vs raw data discrepancies) |

**Enforce mode policy:** CRITICAL → `blocked` · Any findings → `manual_review` · Clean → `allowed` · Tool failure → `manual_review` (fail-closed)

## Security Model

The pipeline defends against prompt injection and AI manipulation at four layers:

1. **System prompt hardening** — agents treat all code/comments as untrusted
2. **Side channel** — raw Semgrep findings bypass the agent entirely; the Gate reads scanner output directly
3. **Safety net** — Gate compares agent claims vs raw data; dismissed HIGH/CRITICAL or severity downgrades trigger warnings
4. **Tool guardrails** — secrets injected via constructor (invisible to LLM), ruleset allowlists, output caps, timeouts

The Remediation Agent adds a fifth layer: **fixes only apply to Gate-confirmed findings** (not raw tool output, not agent opinions), land on a draft PR branch, and require human merge. Every modification is logged in a fix audit trail via a side channel the agent can't alter.

> For a deep dive, see the docs in [`docs/`](docs/).

## Project Structure

```
src/
  main.py                Entry point and GitHub Actions I/O
  github_context.py      GitHub Actions environment parser
  models.py              Data contracts: Finding, Decision, Verdict, Severity
  decision_engine.py     Orchestrator: triage → analyzer → gate + safety net
  agent.py               Triage Agent
  analyzer_agent.py      AppSec Agent (OODA loop)
  remediation_agent.py   Remediation Agent
  remediation_engine.py  Remediation orchestrator
  tools.py               Scan tools: FetchPRFiles, FetchPRDiff, Semgrep
  remediation_tools.py   Fix tools: ReadCode, ApplyFix
  scan_results.py        Structured scan results (gate-validated)
  pr_reporter.py         PR comment formatting and posting
  memory.py              Cross-run memory (false positive patterns)

tests/                   Fully mocked test suite
docs/                    Architecture & design deep dives
```

## Tech Stack

[smolagents](https://github.com/huggingface/smolagents) (HuggingFace agent framework) · [LiteLLM](https://github.com/BerriAI/litellm) (universal LLM adapter) · [Semgrep](https://semgrep.dev/) (SAST engine) · Python 3.12 · Docker

## Roadmap

- [x] Triage Agent + AppSec Agent (OODA)
- [x] Side channel + safety net + severity mismatch detection
- [x] PR reporting + scan-results.json
- [x] Remediation Agent + Draft PR workflow
- [ ] Cross-run memory (false positive patterns, hotspots)
- [ ] Gitleaks integration (secret detection)
- [ ] Trivy integration (SCA / dependency scanning)
- [ ] Pentesting agent (DAST)
- [ ] Threat modeling agent

## License

MIT