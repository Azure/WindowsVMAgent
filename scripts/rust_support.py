#!/usr/bin/env python3
"""Rust supportability checks for the release risk-analysis pipeline.

This module answers a single, concrete question the analysis needs:

    "Is the Rust compiler used to build the shipped native binaries compatible
     with every OS this agent claims to support?"

It does so deterministically, without any external Python dependencies, so it
can run on any runner and be exposed both to ``collect_evidence.py`` and to the
MCP server the LLM agent drives.

Two independent signals are combined:

* **Per-binary rustc version** — Rust embeds a ``rustc version X.Y.Z (hash
  date)`` marker in the binaries it produces. We scan each candidate binary's
  bytes for that marker (and for other Rust fingerprints such as
  ``/rustc/<hash>/`` source paths and ``cargo`` registry paths) to (a) decide
  whether the binary is Rust-built and (b) recover the compiler version.

* **Runner rustc / OS info** — when a ``rustc`` toolchain is present on the
  runner we capture ``rustc -vV`` (release, host triple, LLVM version) and the
  OS the collection ran on. This lets the analysis cross-check the build-time
  compiler against the platform.

The crux of the supportability check is the *minimum Windows version* a given
rustc release still supports. Rust raised its Windows baseline from Windows 7 /
Server 2008 R2 to **Windows 10 / Server 2016** starting with **Rust 1.78.0**
(the pre-1.78 targets were split off into the tier-3 ``*-win7-windows-msvc``
targets). Because the Windows VM Agent officially supports Windows Server
2008 SP2+ / Windows 7 SP2+, any Rust binary built with rustc >= 1.78 using the
default MSVC target is a real OS-compatibility risk and is surfaced as such.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

# Extensions that may contain Rust-compiled code.
RUST_CANDIDATE_EXTENSIONS = {".dll", ".exe", ".sys"}

# rustc release at which the default MSVC targets dropped Windows 7 / 8 /
# Server 2008 R2 / 2012 support and raised the floor to Windows 10 / Server 2016.
RUSTC_WIN10_BASELINE = (1, 78, 0)

# The oldest OS the Windows VM Agent officially supports.
AGENT_MIN_WINDOWS = "Windows Server 2008 SP2 / Windows 7 SP2 (x64)"

# Byte/-string fingerprints that identify a Rust-built binary.
_RUSTC_VERSION_RE = re.compile(rb"rustc version (\d+)\.(\d+)\.(\d+)")
_RUST_SRC_RE = re.compile(rb"/rustc/[0-9a-f]{6,40}[/\\]")
_RUST_MARKERS = (
    b"cargo/registry",
    b".cargo\\registry",
    b"library\\std\\src",
    b"library/std/src",
    b"RUST_BACKTRACE",
    b"called `Result::unwrap()` on an `Err` value",
    b"called `Option::unwrap()` on a `None` value",
)


def _version_tuple(major: int, minor: int, patch: int) -> Tuple[int, int, int]:
    return (major, minor, patch)


def detect_rust_binary(path: str, max_bytes: int = 32 * 1024 * 1024) -> Dict[str, Any]:
    """Inspect a single file and report whether it is Rust-built.

    Returns a dict with ``isRust`` (bool), the detected ``rustcVersion`` string
    (or ``None``), and the list of ``markers`` that matched. Never raises: on any
    I/O error it returns a ``isRust=False`` result.
    """
    result: Dict[str, Any] = {
        "isRust": False,
        "rustcVersion": None,
        "rustcVersionTuple": None,
        "markers": [],
    }
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes)
    except OSError:
        return result

    markers: List[str] = []
    version_match = _RUSTC_VERSION_RE.search(data)
    if version_match:
        major, minor, patch = (int(version_match.group(i)) for i in (1, 2, 3))
        result["rustcVersion"] = f"{major}.{minor}.{patch}"
        result["rustcVersionTuple"] = [major, minor, patch]
        markers.append("rustc-version-string")

    if _RUST_SRC_RE.search(data):
        markers.append("rustc-source-path")
    for marker in _RUST_MARKERS:
        if marker in data:
            markers.append(marker.decode("ascii", "replace"))

    result["markers"] = sorted(set(markers))
    result["isRust"] = bool(result["markers"])
    return result


def windows_baseline_for_rustc(version_tuple: Optional[List[int]]) -> Dict[str, Any]:
    """Return the minimum Windows version a given rustc release supports.

    ``version_tuple`` is ``[major, minor, patch]`` (as produced by
    ``detect_rust_binary``) or ``None`` when the version could not be recovered.
    """
    if not version_tuple:
        return {
            "minWindows": "unknown",
            "supportsAgentMinOs": None,
            "note": "rustc version could not be determined from the binary; "
                    "the Windows baseline is unknown.",
        }
    version = _version_tuple(*version_tuple[:3])
    if version >= RUSTC_WIN10_BASELINE:
        return {
            "minWindows": "Windows 10 / Windows Server 2016",
            "supportsAgentMinOs": False,
            "note": f"rustc {'.'.join(map(str, version))} >= 1.78 uses the default "
                    "MSVC targets whose minimum is Windows 10 / Server 2016; this "
                    "does NOT support the agent's oldest OS "
                    f"({AGENT_MIN_WINDOWS}).",
        }
    return {
        "minWindows": "Windows 7 / Windows Server 2008 R2",
        "supportsAgentMinOs": True,
        "note": f"rustc {'.'.join(map(str, version))} < 1.78 targets Windows 7 / "
                "Server 2008 R2 as the baseline; compatible with the agent's "
                "supported OS matrix (verify Server 2008 SP2 non-R2 separately).",
    }


def rustc_toolchain_info() -> Optional[Dict[str, Any]]:
    """Capture ``rustc -vV`` from the runner, if a toolchain is installed."""
    try:
        proc = subprocess.run(
            ["rustc", "-vV"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, FileNotFoundError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    info: Dict[str, Any] = {"raw": proc.stdout.strip()}
    for line in proc.stdout.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip()] = value.strip()
    return info


def check_rust_support(root: str,
                       binaries: Optional[List[str]] = None) -> Dict[str, Any]:
    """Enumerate Rust binaries under ``root`` and assess OS supportability.

    ``binaries`` may be a pre-computed list of paths relative to ``root``; when
    omitted the tree is walked for candidate binaries.
    """
    if binaries is None:
        binaries = []
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if os.path.splitext(name)[1].lower() in RUST_CANDIDATE_EXTENSIONS:
                    full = os.path.join(dirpath, name)
                    binaries.append(os.path.relpath(full, root))
        binaries.sort()

    detected: List[Dict[str, Any]] = []
    incompatible: List[str] = []
    unknown_version: List[str] = []
    for rel in binaries:
        full = os.path.join(root, rel)
        det = detect_rust_binary(full)
        if not det["isRust"]:
            continue
        baseline = windows_baseline_for_rustc(det.get("rustcVersionTuple"))
        entry = {
            "path": rel.replace(os.sep, "/"),
            "rustcVersion": det["rustcVersion"],
            "markers": det["markers"],
            "minWindows": baseline["minWindows"],
            "supportsAgentMinOs": baseline["supportsAgentMinOs"],
            "note": baseline["note"],
        }
        detected.append(entry)
        if baseline["supportsAgentMinOs"] is False:
            incompatible.append(entry["path"])
        elif baseline["supportsAgentMinOs"] is None:
            unknown_version.append(entry["path"])

    return {
        "agentMinOs": AGENT_MIN_WINDOWS,
        "rustcWin10Baseline": ".".join(map(str, RUSTC_WIN10_BASELINE)),
        "toolchain": rustc_toolchain_info(),
        "runnerOs": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "rustBinaries": detected,
        "rustBinaryCount": len(detected),
        "incompatibleWithAgentMinOs": incompatible,
        "unknownRustcVersion": unknown_version,
        "hasRustSupportabilityRisk": bool(incompatible),
    }


if __name__ == "__main__":  # pragma: no cover - manual smoke test helper
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Rust supportability check.")
    ap.add_argument("root", help="Directory to scan for Rust binaries.")
    args = ap.parse_args()
    print(json.dumps(check_rust_support(args.root), indent=2))
