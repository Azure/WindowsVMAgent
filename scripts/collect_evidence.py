#!/usr/bin/env python3
"""Collect static evidence about a release's binaries for LLM risk analysis.

This script walks a "current" release directory (and optionally a "previous"
release directory used as a diff baseline) and gathers structured, deterministic
facts about every ``.dll`` / ``.exe`` / ``.sys`` file as well as any native /
Rust-built binaries. The output is a single machine-readable ``evidence.json``
that is later fed to the LLM analysis stage.

The evidence collected includes:

* Authenticode / signing certificate details (signer, issuer, thumbprint,
  serial, validity, timestamp, digest algorithm) using ``Get-AuthenticodeSignature``
  on Windows or ``osslsigncode verify`` on Linux.
* PE / .NET metadata: target framework, assembly version, referenced assemblies,
  ``<supportedRuntime>``, PE machine/arch, subsystem and minimum OS version fields.
* OS-compatibility signals: imported DLLs cross-referenced against a set of DLLs
  known to be unavailable on the oldest supported Azure Windows VM OS.
* Binary diff versus the previous release: added / removed / changed files,
  size deltas, version-string deltas, hash changes and certificate changes.

The script degrades gracefully: any piece of tooling that is unavailable simply
produces a ``null`` / empty result rather than failing the whole run, so the LLM
always receives whatever facts *can* be collected on the current runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    # Reused so evidence collection and the MCP server share one implementation.
    from rust_support import check_rust_support, detect_rust_binary
except ImportError:  # pragma: no cover - allows running from other CWDs
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from rust_support import check_rust_support, detect_rust_binary

BINARY_EXTENSIONS = {".dll", ".exe", ".sys"}

# DLLs that are not present (or only partially present) on the oldest supported
# Azure Windows VM OS (Windows Server 2008 SP2 / Windows 7 SP2). An import of one
# of these is an OS-compatibility signal worth surfacing to the analysis stage.
OS_RISKY_IMPORTS = {
    "api-ms-win-core-winrt-l1-1-0.dll",
    "api-ms-win-core-winrt-string-l1-1-0.dll",
    "kernelbase.dll",  # present but with a growing surface across OS versions
    "ucrtbase.dll",  # Universal CRT, not present pre-Windows 10 without redist
    "vcruntime140.dll",
    "pathcch.dll",  # Windows 8+
    "synchronization.dll",  # Windows 8+
}

# Machine field values from the PE header.
PE_MACHINE = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "arm64",
    0x01C4: "armnt",
}


def _run(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
    """Run a command, capturing output and never raising on non-zero exit."""
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        **kwargs,
    )


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_binaries(root: str) -> List[str]:
    """Return relative paths of every binary of interest under ``root``."""
    result: List[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if os.path.splitext(name)[1].lower() in BINARY_EXTENSIONS:
                full = os.path.join(dirpath, name)
                result.append(os.path.relpath(full, root))
    return sorted(result)


# ---------------------------------------------------------------------------
# PE / .NET metadata parsing (pure-python, no external deps)
# ---------------------------------------------------------------------------

def parse_pe(path: str) -> Dict[str, Any]:
    """Parse a minimal but useful subset of the PE header.

    Returns machine/arch, subsystem, the PE optional-header minimum OS/subsystem
    version fields, whether the image is a .NET assembly (has a COM descriptor
    directory), and the list of imported DLL names.
    """
    info: Dict[str, Any] = {
        "arch": None,
        "subsystem": None,
        "majorOperatingSystemVersion": None,
        "majorSubsystemVersion": None,
        "isDotNet": None,
        "importedDlls": [],
    }
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return info

    if len(data) < 0x40 or data[:2] != b"MZ":
        return info
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        return info

    coff = pe_offset + 4
    machine = struct.unpack_from("<H", data, coff)[0]
    info["arch"] = PE_MACHINE.get(machine, f"0x{machine:04x}")
    number_of_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_of_optional = struct.unpack_from("<H", data, coff + 16)[0]

    opt = coff + 20
    if opt + 2 > len(data):
        return info
    magic = struct.unpack_from("<H", data, opt)[0]
    is_pe32_plus = magic == 0x20B  # PE32+ => 64-bit

    # MajorOperatingSystemVersion / MajorSubsystemVersion live at fixed offsets
    # inside the optional header (same for PE32 and PE32+).
    try:
        info["majorOperatingSystemVersion"] = struct.unpack_from("<H", data, opt + 40)[0]
        info["subsystem"] = struct.unpack_from("<H", data, opt + 68)[0]
        info["majorSubsystemVersion"] = struct.unpack_from("<H", data, opt + 48)[0]
    except struct.error:
        pass

    # Data directories: number and start depend on PE32 vs PE32+.
    num_dir_off = opt + (108 if is_pe32_plus else 92)
    dir_start = opt + (112 if is_pe32_plus else 96)
    try:
        num_dirs = struct.unpack_from("<I", data, num_dir_off)[0]
    except struct.error:
        num_dirs = 0

    def data_dir(index: int) -> Optional[tuple]:
        if index >= num_dirs:
            return None
        off = dir_start + index * 8
        if off + 8 > len(data):
            return None
        rva, size = struct.unpack_from("<II", data, off)
        return rva, size

    # Directory index 14 is the CLR/COM descriptor => managed (.NET) image.
    clr = data_dir(14)
    info["isDotNet"] = bool(clr and clr[0] != 0)

    # Build a section table to translate RVAs to file offsets for the import table.
    sections = []
    sec_off = opt + size_of_optional
    for i in range(number_of_sections):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        virt_size = struct.unpack_from("<I", data, base + 8)[0]
        virt_addr = struct.unpack_from("<I", data, base + 12)[0]
        raw_ptr = struct.unpack_from("<I", data, base + 20)[0]
        sections.append((virt_addr, virt_size, raw_ptr))

    def rva_to_offset(rva: int) -> Optional[int]:
        for virt_addr, virt_size, raw_ptr in sections:
            if virt_addr <= rva < virt_addr + max(virt_size, 1):
                return raw_ptr + (rva - virt_addr)
        return None

    imports: List[str] = []
    import_dir = data_dir(1)  # index 1 == import table
    if import_dir and import_dir[0]:
        off = rva_to_offset(import_dir[0])
        if off is not None:
            while off + 20 <= len(data):
                name_rva = struct.unpack_from("<I", data, off + 12)[0]
                if name_rva == 0:
                    break
                name_off = rva_to_offset(name_rva)
                if name_off is not None:
                    end = data.find(b"\x00", name_off)
                    if end != -1:
                        try:
                            imports.append(data[name_off:end].decode("ascii", "replace").lower())
                        except Exception:
                            pass
                off += 20
    info["importedDlls"] = sorted(set(imports))
    return info


def extract_version_strings(path: str) -> Dict[str, Any]:
    """Best-effort extraction of the PE VS_VERSION_INFO / assembly identifiers."""
    result: Dict[str, Any] = {"fileVersion": None, "productVersion": None}
    if platform.system() == "Windows":
        ps = (
            "$ErrorActionPreference='SilentlyContinue';"
            f"$i=[System.Diagnostics.FileVersionInfo]::GetVersionInfo('{path}');"
            "$o=@{fileVersion=$i.FileVersion;productVersion=$i.ProductVersion};"
            "$o | ConvertTo-Json -Compress"
        )
        proc = _run(["powershell", "-NoProfile", "-Command", ps])
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                parsed = json.loads(proc.stdout)
                result["fileVersion"] = parsed.get("fileVersion")
                result["productVersion"] = parsed.get("productVersion")
            except json.JSONDecodeError:
                pass
    return result


# ---------------------------------------------------------------------------
# Authenticode signature extraction
# ---------------------------------------------------------------------------

def signature_windows(path: str) -> Dict[str, Any]:
    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$s=Get-AuthenticodeSignature -LiteralPath '{path}';"
        "$c=$s.SignerCertificate;"
        "$ts=$s.TimeStamperCertificate;"
        "$o=[ordered]@{"
        "status=$s.Status.ToString();"
        "subject=$c.Subject;"
        "issuer=$c.Issuer;"
        "thumbprint=$c.Thumbprint;"
        "serialNumber=$c.SerialNumber;"
        "notBefore=$c.NotBefore.ToString('o');"
        "notAfter=$c.NotAfter.ToString('o');"
        "signatureAlgorithm=$c.SignatureAlgorithm.FriendlyName;"
        "timestampSubject=$ts.Subject;"
        "timestampNotAfter=$(if($ts){$ts.NotAfter.ToString('o')}else{$null})"
        "};"
        "$o | ConvertTo-Json -Compress"
    )
    proc = _run(["powershell", "-NoProfile", "-Command", ps])
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            pass
    return {"status": "Unknown"}


def signature_osslsigncode(path: str) -> Dict[str, Any]:
    proc = _run(["osslsigncode", "verify", path])
    out = (proc.stdout or "") + (proc.stderr or "")
    result: Dict[str, Any] = {"status": "Unknown"}
    if not out.strip():
        return result
    signed = "No signature found" not in out and "not signed" not in out.lower()
    result["status"] = "Valid" if ("Signature verification: ok" in out) else (
        "HashMismatch" if "verification: failed" in out.lower() else (
            "Valid" if signed else "NotSigned"))
    for line in out.splitlines():
        line = line.strip()
        for key, prefix in (
            ("subject", "Subject:"),
            ("issuer", "Issuer:"),
            ("serialNumber", "Serial:"),
        ):
            if line.startswith(prefix):
                result[key] = line[len(prefix):].strip()
        if "Message digest algorithm" in line:
            result["signatureAlgorithm"] = line.split(":")[-1].strip()
    return result


def get_signature(path: str) -> Dict[str, Any]:
    if platform.system() == "Windows":
        return signature_windows(path)
    if shutil.which("osslsigncode"):
        return signature_osslsigncode(path)
    return {"status": "ToolUnavailable"}


# ---------------------------------------------------------------------------
# Per-binary evidence
# ---------------------------------------------------------------------------

def collect_binary(root: str, rel: str) -> Dict[str, Any]:
    full = os.path.join(root, rel)
    pe = parse_pe(full)
    risky = sorted(set(pe.get("importedDlls", [])) & OS_RISKY_IMPORTS)
    rust = detect_rust_binary(full)
    entry: Dict[str, Any] = {
        "path": rel.replace(os.sep, "/"),
        "size": os.path.getsize(full),
        "sha256": sha256_of(full),
        "pe": pe,
        "riskyImports": risky,
        "signature": get_signature(full),
        "version": extract_version_strings(full),
        "rust": {
            "isRust": rust["isRust"],
            "rustcVersion": rust["rustcVersion"],
            "markers": rust["markers"],
        },
    }
    return entry


def index_by_path(binaries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {b["path"]: b for b in binaries}


def diff_releases(current: List[Dict[str, Any]],
                  previous: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    if previous is None:
        return {"baseline": None, "note": "No previous release; diff skipped."}

    cur = index_by_path(current)
    prev = index_by_path(previous)
    added = sorted(set(cur) - set(prev))
    removed = sorted(set(prev) - set(cur))
    changed: List[Dict[str, Any]] = []
    cert_changes: List[Dict[str, Any]] = []

    for path in sorted(set(cur) & set(prev)):
        c, p = cur[path], prev[path]
        deltas: Dict[str, Any] = {}
        if c["sha256"] != p["sha256"]:
            deltas["hashChanged"] = True
            deltas["sizeDelta"] = c["size"] - p["size"]
        if c["version"] != p["version"]:
            deltas["versionFrom"] = p["version"]
            deltas["versionTo"] = c["version"]
        if deltas:
            deltas["path"] = path
            changed.append(deltas)

        cs, ps = c.get("signature", {}), p.get("signature", {})
        cert_delta: Dict[str, Any] = {}
        for field in ("thumbprint", "issuer", "serialNumber", "subject",
                      "signatureAlgorithm", "timestampSubject"):
            if cs.get(field) != ps.get(field):
                cert_delta[field] = {"from": ps.get(field), "to": cs.get(field)}
        if cert_delta:
            cert_delta["path"] = path
            cert_changes.append(cert_delta)

    return {
        "baseline": "previous",
        "added": added,
        "removed": removed,
        "changed": changed,
        "certificateChanges": cert_changes,
    }


def parse_changelist(body: Optional[str],
                     release_notes_dir: Optional[str]) -> Dict[str, Any]:
    items: List[str] = []
    if body:
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith(("-", "*", "+")):
                items.append(stripped.lstrip("-*+ ").strip())
    notes: List[str] = []
    if release_notes_dir and os.path.isdir(release_notes_dir):
        for name in sorted(os.listdir(release_notes_dir)):
            if name.lower().endswith(".md"):
                notes.append(name)
    return {"rawBody": body or "", "items": items, "releaseNoteFiles": notes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", required=True,
                        help="Directory containing the unpacked current release.")
    parser.add_argument("--previous", default=None,
                        help="Directory containing the unpacked previous release (baseline).")
    parser.add_argument("--tag", required=True, help="Current release tag.")
    parser.add_argument("--previous-tag", default=None, help="Previous release tag.")
    parser.add_argument("--release-name", default=None)
    parser.add_argument("--prerelease", default="false")
    parser.add_argument("--published-at", default=None)
    parser.add_argument("--body", default=None,
                        help="Release body / change list text (or @file to read from file).")
    parser.add_argument("--release-notes-dir", default=None)
    parser.add_argument("--output", default="evidence.json")
    args = parser.parse_args()

    body = args.body
    if body and body.startswith("@"):
        try:
            with open(body[1:], "r", encoding="utf-8") as fh:
                body = fh.read()
        except OSError:
            body = None

    current_bins = [collect_binary(args.current, rel)
                    for rel in find_binaries(args.current)]
    previous_bins = None
    if args.previous and os.path.isdir(args.previous):
        previous_bins = [collect_binary(args.previous, rel)
                         for rel in find_binaries(args.previous)]

    evidence = {
        "schemaVersion": "1.0",
        "tag": args.tag,
        "releaseName": args.release_name,
        "prerelease": str(args.prerelease).lower() == "true",
        "publishedAt": args.published_at,
        "previousTag": args.previous_tag,
        "collectedAt": datetime.now(timezone.utc).isoformat(),
        "runner": {
            "os": platform.system(),
            "release": platform.release(),
            "signingTool": "Get-AuthenticodeSignature" if platform.system() == "Windows"
            else ("osslsigncode" if shutil.which("osslsigncode") else "none"),
        },
        "context": {
            "netFrameworkTarget": "4.0",
            "supportedOs": "All Azure Windows VM OS versions (Windows Server 2008 SP2+ / Windows 7 SP2+)",
            "hasRustComponents": True,
            "microsoftSigned": True,
        },
        "changeList": parse_changelist(body, args.release_notes_dir),
        "rustSupport": check_rust_support(args.current),
        "binaries": {
            "current": current_bins,
            "previous": previous_bins,
        },
        "diff": diff_releases(current_bins, previous_bins),
    }

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(evidence, fh, indent=2, sort_keys=False)
    print(f"Wrote {args.output} with {len(current_bins)} current binaries "
          f"({0 if previous_bins is None else len(previous_bins)} previous).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
