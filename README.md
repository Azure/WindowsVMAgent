
# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Release Risk & Compatibility Analysis

Every release of the Windows VM Agent ships a change list and a signed zip
package. The [`Release Risk & Compatibility Analysis`](.github/workflows/release-risk-analysis.yml)
GitHub Actions workflow automatically analyzes each release — both **pre-releases**
and **latest** releases — for risk and compatibility across all supported Azure
Windows VM OS versions.

This pipeline is **fully agent-driven**. There are no bespoke analysis programs
checked into the repository — an LLM agent ([Claude Code](https://docs.anthropic.com/en/docs/claude-code))
loads a reusable **skill**, connects to an off-the-shelf **MCP server**, and
writes and runs whatever evidence-collection scripts it needs on each run.

## What it does

1. **Trigger** — fires on the `release` event (`published`, `released`,
   `prereleased`). It can also be run manually via `workflow_dispatch` with a
   `tag` input to back-fill historical releases.
2. **Acquire artifacts** — downloads the release zip package and the previous
   release's zip (deterministically selected as the diff baseline) and unpacks
   both. This is the only work the workflow does itself.
3. **Agentic analysis** — runs the Claude Code CLI headless. The agent:
   * Loads the [`release-risk-analysis` skill](.claude/skills/release-risk-analysis/SKILL.md),
     which carries all the domain knowledge (fixed project constraints, the
     detection technologies to apply, the workflow, and the output contract).
   * Gets structured file access to the workspace via an off-the-shelf
     filesystem MCP server configured in [`.mcp.json`](.mcp.json).
   * **Generates and runs its own scripts on each run** (PowerShell preferred on
     the Windows runner) to collect deterministic evidence for every
     `.dll` / `.exe` / `.sys` and native/Rust binary: Authenticode / signing
     certificate details (via `Get-AuthenticodeSignature`), PE / .NET metadata
     (target framework, arch, imports, managed-vs-native), OS-compatibility
     signals, Rust fingerprints, the Rust compiler / OS supportability check
     (`rustc` version vs. the agent's OS matrix), the change list, and the diff
     vs. the previous release (including **certificate changes**). Throwaway
     helpers are deleted before the run finishes.
   * Writes `analysis/<tag>.json` (validated against
     [`schema/analysis.schema.json`](schema/analysis.schema.json)) and
     `analysis/<tag>.md`, and regenerates the aggregate
     [`docs/risk-dashboard.md`](docs/risk-dashboard.md). Findings are grouped by
     category (*Change list*, *OS compatibility*, *Signing/certificate change*,
     *.NET Framework 4.0*, *Rust components*, *Rust supportability*,
     *Binary/dependency changes*, *Other*) with a severity of `Critical` /
     `High` / `Medium` / `Low` / `Info`, plus an overall risk rating and summary.
4. **Persist** — attaches the report to the release and commits the results and
   the refreshed dashboard back to the repository.

## Required configuration

* **`ANTHROPIC_API_KEY`** — repository/organization Actions secret used by the
  Claude Code agent. Store it under *Settings → Secrets and variables → Actions*.
  It is never inlined in the workflow. When the secret is absent the analysis
  step is skipped and a minimal placeholder report is written so the pipeline
  still succeeds.
* The workflow uses the built-in `GITHUB_TOKEN` (with `contents: write`) to
  download assets and commit results — no extra token is required.

## Running locally

Install the [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code)
and let the agent do everything — no project-specific dependencies to install:

```bash
npm install -g @anthropic-ai/claude-code

# Unpack the current (and, optionally, previous) release into work/current and
# work/previous, then point the agent at the skill via the EVIDENCE_* env vars:
export ANTHROPIC_API_KEY=...
export EVIDENCE_CURRENT_DIR=work/current EVIDENCE_PREVIOUS_DIR=work/previous
export EVIDENCE_TAG=<tag> EVIDENCE_PREVIOUS_TAG=<prev-tag> EVIDENCE_PRERELEASE=false
export EVIDENCE_BODY_FILE=release-body.md EVIDENCE_MODEL=claude-opus-4-8
export EVIDENCE_OUTPUT_JSON=analysis/<tag>.json EVIDENCE_OUTPUT_MD=analysis/<tag>.md
export EVIDENCE_DASHBOARD=docs/risk-dashboard.md

claude --print --mcp-config .mcp.json --permission-mode bypassPermissions \
  "Analyze this release using the release-risk-analysis skill; inputs are in the EVIDENCE_* env vars."
```

