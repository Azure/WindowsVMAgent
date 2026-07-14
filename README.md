
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

This pipeline is **fully agent-driven**, and the analysis is delegated to
**GitHub's Copilot coding agent**. There are no bespoke analysis programs checked
into the repository — when a release is published, the workflow opens a tracking
issue and assigns it to the Copilot agent. Copilot then loads a reusable
**skill**, connects to an off-the-shelf **MCP server**, runs on the **Claude Opus
4.8** model, writes and runs whatever evidence-collection scripts it needs, and
opens a pull request with the report. Merging that PR publishes the report to the
repository's **GitHub Page**.

## What it does

1. **Trigger** — the [`Release Risk & Compatibility Analysis`](.github/workflows/release-risk-analysis.yml)
   workflow fires on the `release` event (`published`, `released`,
   `prereleased`). It can also be run manually via `workflow_dispatch` with a
   `tag` input to back-fill historical releases.
2. **Delegate to Copilot** — the workflow resolves the release metadata and the
   previous release (the diff baseline), composes a task, and **assigns it to the
   Copilot coding agent** (`copilot-swe-agent`) by creating an issue titled
   *"Release risk analysis for `<tag>`"*. This is the only work the workflow does
   itself.
3. **Agentic analysis (Copilot coding agent)** — Copilot picks up the assigned
   issue in its own ephemeral environment (provisioned by
   [`.github/workflows/copilot-setup-steps.yml`](.github/workflows/copilot-setup-steps.yml))
   and, guided by [`.github/copilot-instructions.md`](.github/copilot-instructions.md):
   * Runs on the **Claude Opus 4.8** model.
   * Loads the [`release-risk-analysis` skill](.claude/skills/release-risk-analysis/SKILL.md),
     which carries all the domain knowledge (fixed project constraints, the
     detection technologies to apply, the workflow, and the output contract).
   * Gets structured file access to the workspace via an off-the-shelf
     filesystem MCP server configured in [`.mcp.json`](.mcp.json).
   * Downloads and unpacks the current + previous release packages, then
     **generates and runs its own scripts** to collect deterministic evidence for
     every `.dll` / `.exe` / `.sys` and native/Rust binary: Authenticode / signing
     certificate details, PE / .NET metadata (target framework, arch, imports,
     managed-vs-native), OS-compatibility signals, Rust fingerprints, the Rust
     compiler / OS supportability check (`rustc` version vs. the agent's OS
     matrix), the change list, and the diff vs. the previous release (including
     **certificate changes**). Throwaway helpers are deleted before it finishes.
   * Writes `analysis/<tag>.json` (validated against
     [`schema/analysis.schema.json`](schema/analysis.schema.json)) and
     `analysis/<tag>.md`, and regenerates the aggregate
     [`docs/risk-dashboard.md`](docs/risk-dashboard.md). Findings are grouped by
     category (*Change list*, *OS compatibility*, *Signing/certificate change*,
     *.NET Framework 4.0*, *Rust components*, *Rust supportability*,
     *Binary/dependency changes*, *Other*) with a severity of `Critical` /
     `High` / `Medium` / `Low` / `Info`, plus an overall risk rating and summary.
   * Opens a pull request with the results.
4. **Publish to GitHub Pages** — when the Copilot pull request is merged into the
   default branch, the [`Publish report to GitHub Pages`](.github/workflows/pages.yml)
   workflow assembles the dashboard and per-release reports into a static site and
   deploys it to the repository's GitHub Page.

## Required configuration

* **Copilot coding agent** must be enabled for the repository so the workflow can
  assign the analysis task to it. See
  [Copilot coding agent](https://docs.github.com/en/copilot/using-github-copilot/coding-agent).
* **MCP servers** — the coding agent loads MCP from *Settings → Copilot → MCP
  servers* (not from a file). The **GitHub MCP server** is enabled by default and
  is what the agent uses to read release metadata and download package assets.
  [`.mcp.json`](.mcp.json) is a committed reference config (an optional filesystem
  server, also usable by the Claude Code CLI); mirror it into the repository MCP
  settings if you want that server available to the agent.
* **`COPILOT_ASSIGN_TOKEN`** *(optional)* — an Actions secret holding a token that
  can create issues and assign the Copilot agent. The built-in `GITHUB_TOKEN` is
  used by default; provide this secret only if your setup needs a PAT to assign
  Copilot.
* **GitHub Pages** must be enabled with the *GitHub Actions* source so the
  `pages.yml` workflow can render and publish the report. The dashboard and each
  report are rendered from Markdown to HTML (release tags containing URL-unsafe
  characters such as `&` are slugified so links resolve correctly).
* The model the agent runs as is pinned in the workflow via the `COPILOT_MODEL`
  environment variable (`claude-opus-4.8`) and restated in
  [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

