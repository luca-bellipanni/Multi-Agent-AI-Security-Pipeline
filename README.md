# Agentic AppSec Pipeline

A GitHub Action that replaces traditional sequential security pipelines with an AI agent that dynamically analyzes pull requests, selects the right security tools, and makes informed decisions.

Instead of running every scanner on every PR and flooding analysts with false positives, an AI agent examines the changes, decides what's relevant, runs only the necessary tools, and explains its reasoning.

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

## Outputs

| Name | Description |
|------|-------------|
| `decision` | Security verdict: `allowed`, `manual_review`, or `blocked` |
| `continue_pipeline` | `true` if the pipeline should continue, `false` if blocked |
| `reason` | Human-readable explanation of the decision |

## Modes

- **Shadow**: observes and reports, never blocks the pipeline. Use this to evaluate the action before enforcing.
- **Enforce**: can block the pipeline when security issues are found.

## License

MIT
