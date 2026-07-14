
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

## What it does

1. **Trigger** — fires on the `release` event (`published`, `released`,
   `prereleased`). It can also be run manually via `workflow_dispatch` with a
   `tag` input to back-fill historical releases.
2. **Acquire artifacts** — downloads the release zip package and the previous
   release's zip (deterministically selected as the diff baseline) and unpacks
   both.
3. **Collect deterministic evidence** ([`scripts/collect_evidence.py`](scripts/collect_evidence.py))
   for every `.dll` / `.exe` / `.sys` and native/Rust binary:
   * Authenticode / signing certificate details (subject, issuer, thumbprint,
     serial, validity, timestamp, digest algorithm) via
     `Get-AuthenticodeSignature` on Windows or `osslsigncode` on Linux.
   * PE / .NET metadata (target framework, arch, subsystem, minimum OS version
     fields, imported DLLs, managed-vs-native).
   * OS-compatibility signals (imports unavailable on the oldest supported OS).
   * Binary diff vs. the previous release (added/removed/changed files, size and
     version deltas, hash changes, **certificate changes**).
   * Parsed change list.
   The result is a single machine-readable `evidence.json`.
4. **LLM analysis** ([`scripts/analyze_release.py`](scripts/analyze_release.py)) —
   sends the evidence to the LLM (**Claude Opus 4.8**) with a fixed context
   prompt (runs on all Azure Windows VM OS versions, targets **.NET Framework
   4.0**, contains **Rust** components, all binaries **Microsoft-signed**,
   certificate changes in scope). The model returns a structured result that is
   validated against [`schema/analysis.schema.json`](schema/analysis.schema.json).
   Findings are grouped by category (*Change list*, *OS compatibility*,
   *Signing/certificate change*, *.NET Framework 4.0*, *Rust components*,
   *Binary/dependency changes*, *Other*) with a severity of `Critical` / `High`
   / `Medium` / `Low` / `Info`, plus an overall risk rating and summary.
5. **Persist & dashboard** ([`scripts/build_dashboard.py`](scripts/build_dashboard.py)) —
   writes `analysis/<tag>.json` and `analysis/<tag>.md`, attaches them to the
   release, and regenerates the aggregate
   [`docs/risk-dashboard.md`](docs/risk-dashboard.md) with a per-release summary
   table (severity counts, cert/​.NET/​Rust/​OS flags) and drill-down sections.

## Required configuration

* **`ANTHROPIC_API_KEY`** — repository/organization Actions secret used to call
  Claude Opus 4.8. Store it under *Settings → Secrets and variables → Actions*.
  It is never inlined in the workflow or scripts. When the secret is absent the
  analysis step falls back to a deterministic, evidence-only result so the
  dashboard still updates.
* The workflow uses the built-in `GITHUB_TOKEN` (with `contents: write`) to
  download assets and commit results — no extra token is required.

## Running locally

```bash
pip install -r scripts/requirements.txt
python scripts/collect_evidence.py --current <unpacked-release-dir> \
    --previous <unpacked-previous-dir> --tag <tag> --output evidence.json
ANTHROPIC_API_KEY=... python scripts/analyze_release.py \
    --evidence evidence.json --schema schema/analysis.schema.json \
    --output analysis/<tag>.json           # add --allow-fallback to skip the LLM
python scripts/build_dashboard.py --release-json analysis/<tag>.json
```

