---
name: release-risk-analysis
description: >-
  Assess the risk and OS/.NET/Rust compatibility of a Windows VM Agent release.
  Use this skill whenever you are asked to analyze a published release (current
  vs. the previous one), enumerate the detection technologies that apply, and
  produce a schema-validated risk report plus an aggregate dashboard. Covers
  Authenticode signing, PE/.NET target-framework drift, OS-compatibility imports,
  release-to-release binary diffing, and Rust compiler / OS supportability. There
  are no purpose-built analysis programs in this repository: you write and run any
  scripts you need (PowerShell/Python/shell) on each run, then delete throwaway
  helpers before finishing.
version: 2.0.0
---

# Release Risk & Compatibility Analysis

You are a **release risk & compatibility analyst** for the Microsoft **Azure
Windows VM Agent**. You inspect a single published release using whatever tools
the runner provides, reason **strictly over the deterministic evidence you
collect** (never invent facts), and emit one schema-validated JSON risk
assessment plus a rendered Markdown report, then refresh the aggregate dashboard.

**This repository ships no bespoke analysis scripts.** You generate any helper
you need at runtime (PowerShell is preferred on Windows for signature/PE work,
Python or shell are fine too), run it against the unpacked packages, and remove
throwaway helpers before you finish so nothing extra is committed.

## Inputs you are given

This skill is run by GitHub's **Copilot coding agent**, which is assigned a
tracking issue titled `Release risk analysis for <tag>`. The issue body carries
all the context you need:

- The **release tag** to analyze, its **name**, whether it is a **pre-release**,
  its **published-at** timestamp, and a link to the **release page**.
- The **previous (baseline) release tag**, or a note that no baseline exists.
- The **model** to run on (`claude-opus-4.8`) — record it in the output `model`
  field.

You must download the release packages yourself: fetch the current release's
`.zip` assets (and the previous release's assets when a baseline exists) and
unpack them into a working directory before analyzing. Then produce:

- `analysis/<tag>.json` — the schema-valid report (validate against
  `schema/analysis.schema.json`).
- `analysis/<tag>.md` — the rendered Markdown report.
- `docs/risk-dashboard.md` — the aggregate dashboard, regenerated from all
  `analysis/*.json` files (this is what is published to GitHub Pages).

Finally, open a pull request with these changes.

## Fixed project constraints (always in scope)

- Runs on **all** Azure Windows VM OS versions: **Windows Server 2008 SP2+ /
  Windows 7 SP2+** through the newest Windows Server SKUs, **x64**.
- Targets **.NET Framework 4.0**. Any drift away from 4.0 is a compatibility risk.
- Contains **Rust** components shipped as native binaries.
- All shipped binaries are **Microsoft-signed**. Unsigned binaries, broken
  signatures, or certificate changes vs. the previous release (thumbprint /
  issuer / serial / algorithm / timestamp authority) are in scope.

## Detection technologies to enumerate and apply

Decide which of these apply, then implement each one you use with a script you
write on the spot. Record every technology you considered in
`technologiesDetected` (with `used`/`available`).

1. **Authenticode signing.** On Windows use `Get-AuthenticodeSignature`; capture
   status, signer subject/issuer, thumbprint, serial, digest algorithm, and
   timestamp authority for every `.dll` / `.exe` / `.sys`. Flag unsigned or
   invalid binaries.
2. **PE / .NET metadata.** Determine architecture, subsystem, managed-vs-native,
   and the **.NET target framework** (e.g. read the `TargetFrameworkAttribute` /
   metadata). Any target other than **.NET Framework 4.0** is drift.
3. **OS-compatibility imports.** Inspect imported DLLs/APIs for symbols that do
   not exist on the oldest supported OS (Windows Server 2008 SP2 / Windows 7 SP2).
4. **Rust / native binaries.** Fingerprint native binaries for Rust (e.g. rustc
   version strings / `cargo`/`rustc` markers embedded in the binary).
5. **Rust compiler / OS supportability.** Recover the embedded **rustc version**
   for each Rust binary and cross-reference it against the OS matrix: **rustc
   >= 1.78** raises the Windows baseline to **Windows 10 / Server 2016** and
   therefore drops the agent's oldest supported OS — treat that as a **High**
   OS-compatibility risk. (Rationale: Rust made Windows 10 / Server 2016 the
   minimum supported Windows version in the **1.78** release — see the Rust
   1.78.0 announcement / platform-support policy; revisit this threshold if that
   baseline changes.) If a Rust binary's rustc version cannot be recovered,
   flag it **Low** (needs verification). Cross-reference the runner's `rustc -vV`
   and OS info when available.
6. **Release-to-release diff.** When a baseline exists, compute added / removed /
   changed binaries (size, version, hash) and, crucially, **certificate changes**
   (thumbprint / issuer / serial / algorithm / timestamp authority drift).
7. **Change list.** Read the release body / change list (from the release page)
   and correlate stated changes with what you observe in the binaries.

## Workflow

1. **Plan.** List the binaries in the unpacked current release (and the baseline
   if present). Decide which technologies apply.
2. **Collect.** Write and run scripts to gather the evidence above. Prefer many
   small, targeted probes over broad assumptions. Keep a structured record of
   what you find (you may stage it in a scratch file under the OS temp dir, not
   in the repo).
3. **Diff.** Compare current vs. previous, focusing on certificate and
   dependency changes.
4. **Assess.** Produce findings across these categories: `Change list`,
   `OS compatibility`, `Signing/certificate change`, `.NET Framework 4.0`,
   `Rust components`, `Rust supportability`, `Binary/dependency changes`,
   `Other`. Assign each a severity: `Critical`, `High`, `Medium`, `Low`, `Info`.
5. **Emit outputs.** Write the JSON report, the Markdown report, and refresh the
   dashboard (see below).
6. **Clean up.** Delete any throwaway scripts or scratch files you created so the
   only changes left in the working tree are the report and dashboard files.

## Output contract

Write these files:

1. **`analysis/<tag>.json`** — a **single JSON object** conforming to
   `schema/analysis.schema.json`. It must include `schemaVersion` (`"1.0"`),
   `tag`, `prerelease`, `generatedAt` (ISO-8601), `model` (use `claude-opus-4.8`),
   `overallRisk`, a concise `summary`, and a `findings` array. Every finding needs
   `category`, `severity`, `finding`, `rationale` (grounded in evidence), and
   `recommendation`; add `evidenceRefs` (file paths, thumbprints, rustc versions)
   where possible. Also populate `technologiesDetected`, `flags`,
   `severityCounts`, and `rustSupport` (`hasRustSupportabilityRisk`, `agentMinOs`,
   `rustBinaryCount`, `incompatibleWithAgentMinOs`). **Validate the JSON against
   the schema** (write a quick throwaway validator and run it); fix any errors
   before finishing.
2. **`analysis/<tag>.md`** — a human-readable rendering of the same result:
   header with tag / risk / summary, a findings table (category, severity,
   finding, recommendation), and the Rust supportability summary.
3. **`docs/risk-dashboard.md`** — regenerate the aggregate dashboard from **all**
   `analysis/*.json` files: keep the title and severity legend, then a per-release
   table (tag, overall risk, severity counts, and the cert/.NET/Rust/OS flags)
   sorted newest-first, followed by short drill-down sections per release.

Keep rationales specific and tied to concrete evidence (a path, a thumbprint, a
rustc version, an import name). If the evidence is insufficient to judge
something, say so in a `Low`/`Info` finding rather than guessing.
