# Windows VM Agent — Release Risk & Compatibility Dashboard

Automatically generated from `analysis/*.json`. Each release is analyzed for risk & compatibility across the supported Azure Windows VM OS versions (.NET Framework 4.0 + Rust components, Microsoft-signed binaries).

**Severity legend:** 🟥 Critical · 🟧 High · 🟨 Medium · 🟩 Low · 🟦 Info

| Release | Overall risk | Crit | High | Med | Low | Info | Cert | .NET drift | Rust | OS |
|---|---|--:|--:|--:|--:|--:|:--:|:--:|:--:|:--:|
| [2.7.41491.1225AMD64&ARM64](../analysis/2.7.41491.1225AMD64&ARM64.md) | 🟧 High | 0 | 1 | 1 | 3 | 2 | ⚠️ | – | ⚠️ | ⚠️ |

**Flag key:** Cert = signing-certificate change · .NET drift = target moved off .NET Framework 4.0 · Rust = Rust components changed · OS = OS-compatibility concern. ⚠️ = flagged, – = not flagged/none.

## 2.7.41491.1225AMD64&ARM64 — 🟧 High

- **Baseline:** 2.7.41491.1216AMD64&ARM64
- **Pre-release:** false · **Published:** 2026-05-18T20:11:39Z
- **Model:** claude-opus-4.8

Binary-level analysis of the amd64 and arm64 GuestAgentPackage .zip assets of VMAgent 2.7.41491.1225 (baseline 2.7.41491.1216); the .wim, .msi and _PDBs.zip assets were intentionally excluded per scope. The amd64 package contains 110 PE files (43 managed, 67 native) and the arm64 package 64 PE files (40 managed, 24 native); every binary is validly Microsoft-signed (leaf CN=Microsoft Corporation), SHA-256 file digest, RFC-3161 timestamped. Two findings drive risk. (1) Rust supportability (High): the native Rust modules rust_common.dll and rust_utils.dll are built with Microsoft rustc 1.92.0 and 1.84.1 respectively (both >= 1.78) and import Windows 8+/Server 2012+ only APIs (WaitOnAddress via api-ms-win-core-synch-l1-2-0.dll, GetSystemTimePreciseAsFileTime), so they cannot load on the agent's oldest declared OS, Windows 7 SP2 / Windows Server 2008 SP2. This condition is pre-existing and identical in the 2.7.41491.1216 baseline (same rustc versions and same imports) rather than a regression introduced by this release. (2) Signing-certificate change (Medium): the code-signing chain rotated from issuing CA 'Microsoft Code Signing PCA 2011' (baseline) to 'Microsoft Code Signing PCA 2024' (this release); the leaf subject is unchanged and both chain to Microsoft Root Certificate Authority 2011 - a benign Microsoft PKI rotation, not a compromise. All managed assemblies still target .NET Framework 4.0 (CLR v4.0.30319; the only exception, the third-party srmlib.dll, targets the legacy CLR v2.0 and is unchanged from baseline) - no .NET drift. Diff vs baseline: one new binary, WindowsAzureGuestAgentGateKeeper.exe (matches the 'pre-validation gate keeper' change-list items), nothing removed, and nearly all binaries re-signed/rebuilt (hash change) consistent with the stated build-image 2019->2022 move plus the certificate rotation. Net release-specific delta is low; overall rating is High solely because of the (carried-over) Rust down-level supportability gap. See the [full report](../analysis/2.7.41491.1225AMD64&ARM64.md).
