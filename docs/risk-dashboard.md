# Windows VM Agent — Release Risk & Compatibility Dashboard

Automatically generated from `analysis/*.json`. Each release is analyzed for risk & compatibility across the supported Azure Windows VM OS versions (.NET Framework 4.0 + Rust components, Microsoft-signed binaries).

**Severity legend:** 🟥 Critical · 🟧 High · 🟨 Medium · 🟩 Low · 🟦 Info

| Release | Overall risk | Crit | High | Med | Low | Info | Cert | .NET drift | Rust | OS |
|---|---|--:|--:|--:|--:|--:|:--:|:--:|:--:|:--:|

**Flag key:** Cert = signing-certificate change · .NET drift = target moved off .NET Framework 4.0 · Rust = Rust components changed · OS = OS-compatibility concern. ⚠️ = flagged, – = not flagged/none.

_No releases have been analyzed yet. When a release is published, the Copilot coding agent writes `analysis/<tag>.json` / `analysis/<tag>.md` and regenerates this dashboard; the pages workflow then publishes the reports to GitHub Pages._
