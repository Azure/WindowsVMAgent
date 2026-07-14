# Windows VM Agent — Release Risk & Compatibility Dashboard

Automatically generated from `analysis/*.json`. Each release is analyzed for risk & compatibility across the supported Azure Windows VM OS versions (.NET Framework 4.0 + Rust components, Microsoft-signed binaries).

**Severity legend:** 🟥 Critical · 🟧 High · 🟨 Medium · 🟩 Low · 🟦 Info

| Release | Overall risk | Crit | High | Med | Low | Info | Cert | .NET drift | Rust | OS |
|---|---|--:|--:|--:|--:|--:|:--:|:--:|:--:|:--:|
| [2.7.41491.1225AMD64&ARM64](../analysis/2.7.41491.1225AMD64&ARM64.md) | 🟩 Low | 0 | 0 | 0 | 4 | 3 | – | – | ⚠️ | – |

**Flag key:** Cert = signing-certificate change · .NET drift = target moved off .NET Framework 4.0 · Rust = Rust components changed · OS = OS-compatibility concern. ⚠️ = flagged, – = not flagged/none.

## 2.7.41491.1225AMD64&ARM64 — 🟩 Low

- **Baseline:** 2.7.41491.1216AMD64&ARM64
- **Pre-release:** false · **Published:** 2026-05-18T20:11:39Z
- **Model:** claude-opus-4.8

Dry-run analysis based on the published change list — the release exposes no downloadable `.zip` package assets, so binary-level signing, .NET target-framework, OS-import, and `rustc` evidence could not be collected. The change list is a routine feature/telemetry/build-infra update that touches Rust catalog-file code paths; no certificate change, .NET drift, or OS-matrix change is indicated. Signing, .NET target, imports, and `rustc` supportability remain pending until a signed package is attached. See the [full report](../analysis/2.7.41491.1225AMD64&ARM64.md).
