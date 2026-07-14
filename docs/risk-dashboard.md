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

Dry-run analysis of VMAgent 2.7.41491.1225 (baseline 2.7.41491.1216). This release exposes no downloadable .zip package assets on GitHub, so binary-level evidence (Authenticode signatures, PE/.NET target framework, OS-compatibility imports, embedded rustc versions) could not be collected; the assessment is therefore based on the published change list only. The change list is a routine feature/telemetry/build-infra update with no indication of a signing-certificate change, a move away from .NET Framework 4.0, or an OS-matrix change. It does touch Rust code paths (catalog-file install/uninstall), so the Rust compiler / OS supportability check must be re-run against the shipped Rust binaries once package assets are available. Overall risk is Low with several items pending binary verification. See the [full report](../analysis/2.7.41491.1225AMD64&ARM64.md).
