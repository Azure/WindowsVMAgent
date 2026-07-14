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
- **MCP.** Use the MCP servers declared in [`.mcp.json`](../.mcp.json) (filesystem
  access to the workspace) together with the GitHub tools available to you.
- **Environment.** Your environment is provisioned by
  [`.github/workflows/copilot-setup-steps.yml`](workflows/copilot-setup-steps.yml)
  (Node for the MCP server, Rust for `rustc`, plus `unzip`/`jq`).
- **Inputs.** The tracking issue lists the release tag, whether it is a
  pre-release, and the previous (baseline) tag. Download the current release's
  `.zip` assets (and the previous release's assets when a baseline exists) and
  unpack them before analyzing.
- **Outputs.** Write the schema-valid report to `analysis/<tag>.json` (validated
  against [`schema/analysis.schema.json`](../schema/analysis.schema.json)), the
  Markdown report to `analysis/<tag>.md`, and regenerate the aggregate dashboard
  at [`docs/risk-dashboard.md`](../docs/risk-dashboard.md). Delete any throwaway
  helper scripts you create before opening the pull request.
- **Publishing.** Everything under `docs/` is published to the repository's GitHub
  Page by [`.github/workflows/pages.yml`](workflows/pages.yml) when your pull
  request is merged, so keep the dashboard and reports there.
