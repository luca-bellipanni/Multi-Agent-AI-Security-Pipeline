# Agentic AppSec Pipeline

A GitHub Action that replaces sequential security scanners with a **multi-agent AI system**. AI agents read your code changes, reason about risks, run targeted scans, and propose fixes as Draft PRs — while a deterministic gate ensures no AI manipulation can override the verdict.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Quick Start

```yaml
name: Security Check
on: [pull_request]

jobs:
  appsec:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Agentic AppSec
        id: appsec
        uses: luca-bellipanni/Multi-Agent-AI-Security-Pipeline@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          mode: shadow
          ai_api_key: ${{ secrets.AI_API_KEY }}

      - name: Check result
        if: steps.appsec.outputs.continue_pipeline == 'false'
        run: |
          echo "Security gate: ${{ steps.appsec.outputs.decision }}"
          exit 1
```

No `ai_api_key`? The action still works with deterministic rules. Add AI later.

---

## The Pipeline

A PR goes through four phases: triage, analysis, verdict, and remediation. Three AI agents and one deterministic gate, each with a clear role.

```
PR opened
    │
    ▼
┌──────────────────┐
│  Triage Agent    │  Reads file metadata, assesses risk area
│  (cheap, fast)   │  "3 Python files changed in auth area"
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  AppSec Agent    │  Reads diffs, runs Semgrep iteratively (OODA loop)
│  (smart, deep)   │  Confirms 2 real findings, dismisses 3 noise
└────────┬─────────┘
         │ analysis              │ raw findings
         │ (agent's opinion)     │ (side channel, untouchable by AI)
         ▼                       ▼
┌──────────────────────────────────────────┐
│  Gate (deterministic Python, no AI)      │
│                                          │
│  Reads raw findings, NOT the agent.      │
│  Compares: did the agent hide anything?  │
│  Verdict: ALLOWED / MANUAL_REVIEW /      │
│           BLOCKED                        │
│                                          │
│  Output: PR comment + scan-results.json  │
└────────────────────┬─────────────────────┘
                     │
                     ▼
          Human reviews PR comment
          Handles warnings (Gate vs Agent disagreements)
          Types: /remediate
                     │
                     ▼
┌──────────────────────────────────────────┐
│  Remediation Agent (developer, not       │
│  rule applier)                           │
│                                          │
│  Reads full file context + imports.      │
│  Understands developer intent.           │
│  Generates idiomatic fixes.              │
│  Iterates until AST-valid.              │
│                                          │
│  Output: Draft PR (1 commit per finding) │
└──────────────────────────────────────────┘
```

### Why this design

**Cost scales with risk.** The Triage Agent is cheap (small model, 3 steps, file metadata only) and runs on every PR. The AppSec Agent is expensive (larger model, up to 10 steps, reads diffs, runs Semgrep multiple times) and runs only when needed. A README typo doesn't trigger the expensive agent.

**AI advises, code decides.** The AppSec Agent analyzes findings and provides context. The Gate reads raw scanner data through a side channel the AI cannot manipulate. If a prompt injection in your code tricks the agent into dismissing a finding, the Gate still sees it and raises a warning.

**Remediation is a developer, not a template.** The Remediation Agent reads the full file, understands what the code was trying to do, and writes a fix that maintains functional behavior. If fixing a SQL injection requires switching to parameterized queries with a different cursor API, it does the full refactoring.

**Humans stay in the loop.** The Gate posts a PR comment. The human reviews it, handles disagreements, and explicitly triggers remediation with `/remediate`. The Remediation Agent produces a Draft PR — merge requires human approval.

---

## Two Workflows

The scan and remediation are separate GitHub Actions workflows. No standby, no polling.

| | Workflow 1: Scan | Workflow 2: Remediation |
|---|---|---|
| **Trigger** | `on: pull_request` | `on: issue_comment` (`/remediate`) |
| **Who triggers** | Automatic | Maintainer (manual) |
| **What it does** | Triage → AppSec → Gate → PR comment | Load scan results → Remediation Agent → Draft PR |
| **Output** | `scan-results.json` artifact + PR status check | Draft PR with atomic commits |
| **Permissions** | `contents: read`, `pull-requests: write` | `contents: write`, `pull-requests: write` |

### Human decision flow

The PR comment has three sections. The human only needs to look at **warnings**:

| Section | Meaning | Action |
|---------|---------|--------|
| **Confirmed** | Gate and Agent agree it's real | None — will be fixed |
| **Warnings** | Gate and Agent disagree | `/dismiss {id} reason` or leave active |
| **Dismissed** | LOW/INFO noise filtered by Agent | None — audit only |

When ready: `/remediate` → Draft PR appears with one commit per finding.

---

## Security Model

The system defends against the AI itself at four layers:

| Layer | Defense | Threat |
|-------|---------|--------|
| **Prompt hardening** | Agent prompts mark code as untrusted | Prompt injection via comments |
| **Side channel** | Raw findings bypass the agent entirely | Agent hiding findings |
| **Safety net** | Gate compares agent claims vs raw data | Severity downgrade, dismissed HIGHs |
| **Tool guardrails** | Secrets in constructors, scope locks, timeouts | Excessive agency, data exfiltration |

The Remediation Agent has additional constraints: **write-locked to files in the PR diff** (reads the entire workspace for context), **AST validation** on every fix, and a **fix audit log** recorded by the tool — not the agent — as a second side channel.

---

## Configuration

### Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `github_token` | Yes | — | GitHub token for API access |
| `mode` | No | `shadow` | `shadow` (observe only) or `enforce` (can block PRs) |
| `ai_api_key` | No | — | API key for any LLM provider ([LiteLLM supported](https://docs.litellm.ai/docs/providers)) |
| `ai_model` | No | `gpt-4o-mini` | Model ID |
| `command` | No | `scan` | `scan` or `remediate` |

### Outputs

| Name | Description |
|------|-------------|
| `decision` | `allowed`, `manual_review`, or `blocked` |
| `continue_pipeline` | `true` or `false` |
| `findings_count` | Total raw findings from scanner |
| `reason` | Human-readable explanation with AI reasoning |
| `safety_warnings_count` | Safety net warnings (agent vs gate disagreements) |
| `fix_pr_url` | URL of the Draft PR with fixes (remediation only) |

### Modes

| Mode | Behavior |
|------|----------|
| **Shadow** | Full analysis, never blocks. Use to evaluate and tune. |
| **Enforce** | CRITICAL → `blocked`. Any findings → `manual_review`. Clean → `allowed`. Failures → `manual_review` (fail-closed). |

---

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
```

## Tech Stack

- **Python 3.12** on Docker (GitHub Actions container)
- **[smolagents](https://github.com/huggingface/smolagents)** — HuggingFace agent framework
- **[LiteLLM](https://github.com/BerriAI/litellm)** — universal LLM adapter (100+ providers)
- **[Semgrep](https://semgrep.dev/)** — SAST engine with 2000+ community rulesets

## Roadmap

| Feature | Status |
|---------|--------|
| Triage Agent + AppSec Agent (OODA) | ✅ Done |
| Side channel + safety net + severity mismatch | ✅ Done |
| PR reporting + scan-results.json | ✅ Done |
| Remediation Agent + Draft PR workflow | ✅ Done |
| Cross-run memory (false positive patterns, hotspots) | 🔄 In progress |
| Gitleaks integration (secret detection) | 📋 Planned |
| Trivy integration (SCA / container scanning) | 📋 Planned |
| Pentesting agent (DAST) | 📋 Planned |
| Threat modeling agent | 📋 Planned |

## License

MIT