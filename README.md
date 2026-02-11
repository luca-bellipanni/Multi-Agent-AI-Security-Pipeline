# Agentic AppSec Pipeline

A GitHub Action that replaces traditional sequential security pipelines with a **multi-agent AI system** that dynamically analyzes pull requests, selects the right security tools, and makes informed decisions.

Instead of running every scanner on every PR and flooding analysts with false positives, AI agents examine the changes, decide what's relevant, run only the necessary tools, and explain their reasoning.

## The Problem

Traditional AppSec pipelines work like this:

```
PR opened
  → Run SAST (always)
    → Run SCA (always)
      → Run secret scan (always)
        → Analyst reviews ALL findings
          → Security gate: pass/fail
```

Every tool runs on every PR. A documentation change triggers the same 15-minute security scan as a critical authentication rewrite. Analysts drown in false positives. The security gate becomes a bottleneck.

## The Solution: Multi-Agent Architecture

```
                         ┌─────────────────────────────────────────────┐
                         │            GitHub Pull Request              │
                         └────────────────────┬────────────────────────┘
                                              │
                                              ▼
                    ┌──────────────────────────────────────────────┐
                    │              TRIAGE AGENT (AI)               │
                    │                                              │
                    │  Lightweight model, low cost per call.       │
                    │  Looks at: files changed, repo language,     │
                    │  PR metadata, event type.                    │
                    │                                              │
                    │  Decides: "Run Semgrep + Gitleaks,           │
                    │           skip Trivy — no deps changed."     │
                    └──────────────────────┬───────────────────────┘
                                           │
                              ┌─────────────┼─────────────┐
                              ▼             ▼             ▼
                         ┌─────────┐  ┌─────────┐  ┌──────────┐
                         │ Semgrep │  │Gitleaks │  │  Trivy   │
                         │ (SAST)  │  │(Secrets)│  │  (SCA)   │
                         └────┬────┘  └────┬────┘  └──────────┘
                              │            │         (skipped)
                              ▼            ▼
                    ┌──────────────────────────────────────────────┐
                    │            ANALYZER AGENT (AI)               │
                    │                                              │
                    │  Smart model, deeper reasoning.              │
                    │  Reads tool findings + code context.         │
                    │  Filters false positives, explains risks,    │
                    │  produces structured security report.        │
                    └──────────────────────┬───────────────────────┘
                                           │
                                           ▼
              ┌────────────────────────────────────────────────────────┐
              │                  GATE (Python code)                    │
              │                                                        │
              │  Deterministic rules. NOT an LLM. NOT hackable.        │
              │                                                        │
              │  if CRITICAL finding  → BLOCKED     (always)           │
              │  if HIGH + enforce    → BLOCKED     (always)           │
              │  if MEDIUM + enforce  → MANUAL_REVIEW                  │
              │  if shadow mode       → ALLOWED     (observe only)     │
              │                                                        │
              │  No prompt injection can override these rules.         │
              └────────────────────────────┬───────────────────────────┘
                                           │
                              ┌─────────────┼─────────────┐
                              ▼             ▼             ▼
                         ┌─────────┐  ┌─────────┐  ┌──────────┐
                         │ PR      │  │ GitHub  │  │ JSON     │
                         │ Comment │  │ Check   │  │ Artifact │
                         └─────────┘  └─────────┘  └──────────┘
```

### Why This Architecture Wins

**AI advises, code decides.** The final security gate is Python code with fixed rules — not an LLM that could be manipulated. A developer can't trick the gate into approving a critical vulnerability, no matter what they put in the PR description.

**Prompt injection resistant by design.** The AI agents analyze metadata and tool output. The gate that enforces security decisions runs as deterministic code. Even if an attacker manipulates an agent's reasoning, the hard-coded rules still block critical findings.

**Cost optimized.** The Triage Agent uses a cheap, fast model (e.g., GPT-4o-mini) to decide *what* to scan. The Analyzer Agent uses a smarter model only when there are actual findings to analyze. Documentation-only PRs cost almost nothing.

**Graceful degradation.** No AI API key? The pipeline works with deterministic rules. AI service down? Automatic fallback. You never lose security coverage because of an API outage.

**Provider agnostic.** Uses [LiteLLM](https://github.com/BerriAI/litellm) under the hood — works with OpenAI, Anthropic, Azure, Bedrock, and 100+ LLM providers. Switch models by changing one input parameter.

## Current Status

| Component | Status | Description |
|-----------|--------|-------------|
| Triage Agent | Active | Recommends which security tools to run |
| Analyzer Agent | Planned | Will analyze tool findings (Step 5+) |
| Gate (code) | Active | Deterministic security rules |
| Semgrep tool | Planned | SAST — code vulnerability scanning |
| Gitleaks tool | Planned | Secret detection |
| Trivy tool | Planned | SCA — dependency/container scanning |
| PR Reporting | Planned | Comments, checks, artifacts |

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
        uses: R3DLB/Appsec-Agentic-Pipeline@main
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          mode: shadow
          ai_api_key: ${{ secrets.AI_API_KEY }}    # Optional
          ai_model: gpt-4o-mini                     # Optional

      - name: Show result
        run: |
          echo "Decision: ${{ steps.appsec.outputs.decision }}"
          echo "Continue: ${{ steps.appsec.outputs.continue_pipeline }}"
          echo "Reason: ${{ steps.appsec.outputs.reason }}"
```

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `github_token` | Yes | — | GitHub token for API access |
| `mode` | No | `shadow` | `shadow` (observe only) or `enforce` (can block PRs) |
| `ai_api_key` | No | — | API key for LLM provider (OpenAI, Anthropic, etc.) |
| `ai_model` | No | `gpt-4o-mini` | Model ID for [LiteLLM](https://docs.litellm.ai/docs/providers) (e.g. `anthropic/claude-sonnet-4-5-20250929`) |

## Outputs

| Name | Description |
|------|-------------|
| `decision` | Security verdict: `allowed`, `manual_review`, or `blocked` |
| `continue_pipeline` | `true` if the pipeline should continue, `false` if blocked |
| `reason` | Human-readable explanation of the decision (includes AI reasoning when available) |

## Modes

- **Shadow**: observes and reports, never blocks the pipeline. Use this to evaluate the action and tune the AI before enforcing.
- **Enforce**: can block the pipeline when security issues are found. The gate applies strict rules that no AI can override.

## Without AI (Deterministic Fallback)

If no `ai_api_key` is provided, the action runs with deterministic rules:
- Shadow mode: always allows (observing only)
- Enforce mode: requires manual review (no tool results to evaluate)

This means you can adopt the action immediately, even before configuring an AI provider.

## Tech Stack

- **Python 3.12** on Docker (GitHub Actions container)
- **[smolagents](https://github.com/huggingface/smolagents)** — lightweight agent framework by HuggingFace
- **[LiteLLM](https://github.com/BerriAI/litellm)** — unified LLM interface (100+ providers)
- **Semgrep** — SAST (planned)
- **Gitleaks** — secret detection (planned)
- **Trivy** — SCA/container scanning (planned)

## Project Structure

```
src/
├── main.py              # Orchestrator — reads context, runs engine, writes outputs
├── models.py            # Data contracts — Decision, Verdict, Severity enums
├── github_context.py    # Environment parser — GitHub Actions → clean dataclass
├── decision_engine.py   # Triage AI → Gate (deterministic rules)
└── agent.py             # Triage Agent — smolagents + LiteLLM setup
tests/
├── test_agent.py        # 12 tests — response parsing, task building
└── test_decision_engine.py  # 17 tests — modes, fallback, gate rules, integration
```

## License

MIT
