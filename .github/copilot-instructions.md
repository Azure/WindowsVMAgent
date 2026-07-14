# Copilot instructions — Windows VM Agent

## Release risk & compatibility analysis (Copilot coding agent tasks)

When you are assigned an issue titled **"Release risk analysis for `<tag>`"**, you
are acting as the release-risk analyst for the Azure Windows VM Agent. Handle it
as follows:

- **Model.** Run the task on the **Claude Opus 4.8** (`claude-opus-4.8`) model and
  record `claude-opus-4.8` in the analysis output `model` field.
- **Skill.** Load and follow the [`release-risk-analysis`
  skill](../.claude/skills/release-risk-analysis/SKILL.md) exactly. It carries all
  domain knowledge: the fixed project constraints, the detection technologies to
  apply, the `rustc >= 1.78` → Windows 10 / Server 2016 supportability rule, and
  the output contract.
- **MCP & tools.** Use the **GitHub MCP server** (enabled by default for the
  coding agent) to read release metadata and download the release `.zip` assets,
  plus your built-in filesystem/shell tools for the workspace. The repository's
  MCP servers are configured under **Settings → Copilot → MCP servers**;
  [`.mcp.json`](../.mcp.json) is the committed reference configuration (an optional
  filesystem server, primarily for running the same skill via the Claude Code CLI)
  — mirror it into the repository MCP settings if you want that server available.
- **Environment.** Your environment is provisioned by
  [`.github/workflows/copilot-setup-steps.yml`](workflows/copilot-setup-steps.yml)
  (Node for the reference MCP server, Rust for `rustc`, plus `unzip`/`jq`).
- **Inputs.** The tracking issue lists the release tag, whether it is a
  pre-release, and the previous (baseline) tag. Download the current release's
  `.zip` assets (and the previous release's assets when a baseline exists) and
  unpack them before analyzing. If a release exposes no downloadable `.zip`
  assets, fall back to a change-list-only analysis and clearly say so (record the
  affected detection technologies as `available: false`).
- **Outputs.** Write the schema-valid report to `analysis/<tag>.json` (validated
  against [`schema/analysis.schema.json`](../schema/analysis.schema.json)), the
  Markdown report to `analysis/<tag>.md`, and regenerate the aggregate dashboard
  at [`docs/risk-dashboard.md`](../docs/risk-dashboard.md). Delete any throwaway
  helper scripts you create before opening the pull request.
- **Publishing.** The dashboard (`docs/risk-dashboard.md`) and the per-release
  reports (`analysis/*.md` / `*.json`) are rendered to HTML and published to the
  repository's GitHub Page by
  [`.github/workflows/pages.yml`](workflows/pages.yml) when your pull request is
  merged, so keep those files up to date.
