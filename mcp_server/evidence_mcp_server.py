#!/usr/bin/env python3
"""MCP server exposing release evidence-collection & analysis tools.

This is the "working set" the LLM-based agent (``agent_runner.py``, Claude Opus
4.8) drives to inspect a release. Instead of pre-baking a single ``evidence.json``
and handing it to the model, the pipeline lets the *agent* enumerate and call
these tools on demand, so it can decide which detection/analysis technologies to
apply and drill in where the risk is.

Tools exposed (all read-only, deterministic, and side-effect free):

* ``list_detection_technologies`` — enumerate every detection/analysis technique
  available in this server, so the agent can plan its assessment.
* ``list_binaries`` — list the binaries under the current (or previous) release.
* ``inspect_binary`` — full per-binary evidence: PE/.NET metadata, signature,
  version strings, risky imports, Rust fingerprints.
* ``inspect_signature`` — Authenticode signature details for one binary.
* ``diff_releases`` — added/removed/changed binaries + certificate changes vs. the
  previous release.
* ``check_rust_support`` — Rust binaries + rustc version vs. OS supportability.
* ``get_release_context`` — fixed project constraints (OS matrix, .NET target …)
  and change list parsed from the release body / notes.
* ``collect_full_evidence`` — the complete ``evidence.json`` in one call (parity
  with the legacy static collector).

The server is transport-agnostic MCP over stdio. It uses the official ``mcp``
Python SDK when installed; when the SDK is absent it still runs as a tiny
line-delimited JSON-RPC server implementing the subset of MCP the agent runner
needs (``initialize``, ``tools/list``, ``tools/call``), so the pipeline never
hard-depends on the SDK being present.

Configuration comes from environment variables so the launcher (the workflow /
agent runner) can point the server at the unpacked release directories:

* ``EVIDENCE_CURRENT_DIR``   — unpacked current release (required).
* ``EVIDENCE_PREVIOUS_DIR``  — unpacked previous release (optional baseline).
* ``EVIDENCE_TAG`` / ``EVIDENCE_PREVIOUS_TAG`` / ``EVIDENCE_RELEASE_NAME``
* ``EVIDENCE_PRERELEASE`` / ``EVIDENCE_PUBLISHED_AT``
* ``EVIDENCE_BODY_FILE``     — file containing the release body / change list.
* ``EVIDENCE_RELEASE_NOTES_DIR`` — directory of release-note markdown files.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

# Make the sibling scripts importable regardless of CWD.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(os.path.dirname(_HERE), "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import collect_evidence as ce  # noqa: E402
from rust_support import check_rust_support  # noqa: E402

try:
    from analyze_release import DETECTION_TECHNOLOGIES  # noqa: E402
except Exception:  # pragma: no cover - defensive
    DETECTION_TECHNOLOGIES = []


# ---------------------------------------------------------------------------
# Environment-driven configuration
# ---------------------------------------------------------------------------

def _config() -> Dict[str, Any]:
    return {
        "current": os.environ.get("EVIDENCE_CURRENT_DIR", "work/current"),
        "previous": os.environ.get("EVIDENCE_PREVIOUS_DIR") or None,
        "tag": os.environ.get("EVIDENCE_TAG", ""),
        "previousTag": os.environ.get("EVIDENCE_PREVIOUS_TAG") or None,
        "releaseName": os.environ.get("EVIDENCE_RELEASE_NAME") or None,
        "prerelease": os.environ.get("EVIDENCE_PRERELEASE", "false"),
        "publishedAt": os.environ.get("EVIDENCE_PUBLISHED_AT") or None,
        "bodyFile": os.environ.get("EVIDENCE_BODY_FILE") or None,
        "releaseNotesDir": os.environ.get("EVIDENCE_RELEASE_NOTES_DIR") or None,
    }


def _resolve_root(which: str, cfg: Dict[str, Any]) -> Optional[str]:
    root = cfg["previous"] if which == "previous" else cfg["current"]
    if root and os.path.isdir(root):
        return root
    return None


def _read_body(cfg: Dict[str, Any]) -> Optional[str]:
    path = cfg["bodyFile"]
    if path and os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except OSError:
            return None
    return None


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def tool_list_detection_technologies(_: Dict[str, Any]) -> Dict[str, Any]:
    return {"technologies": DETECTION_TECHNOLOGIES}


def tool_list_binaries(args: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _config()
    which = args.get("release", "current")
    root = _resolve_root(which, cfg)
    if root is None:
        return {"release": which, "binaries": [], "note": "release directory not available"}
    return {"release": which, "root": root, "binaries": ce.find_binaries(root)}


def tool_inspect_binary(args: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _config()
    which = args.get("release", "current")
    rel = args.get("path")
    root = _resolve_root(which, cfg)
    if root is None or not rel:
        return {"error": "release directory or path not available"}
    full = os.path.join(root, rel)
    if not os.path.isfile(full):
        return {"error": f"binary not found: {rel}"}
    return ce.collect_binary(root, rel)


def tool_inspect_signature(args: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _config()
    which = args.get("release", "current")
    rel = args.get("path")
    root = _resolve_root(which, cfg)
    if root is None or not rel:
        return {"error": "release directory or path not available"}
    full = os.path.join(root, rel)
    if not os.path.isfile(full):
        return {"error": f"binary not found: {rel}"}
    return {"path": rel, "signature": ce.get_signature(full)}


def _all_binaries(root: str) -> List[Dict[str, Any]]:
    return [ce.collect_binary(root, rel) for rel in ce.find_binaries(root)]


def tool_diff_releases(_: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _config()
    cur_root = _resolve_root("current", cfg)
    if cur_root is None:
        return {"error": "current release directory not available"}
    current = _all_binaries(cur_root)
    prev_root = _resolve_root("previous", cfg)
    previous = _all_binaries(prev_root) if prev_root else None
    return ce.diff_releases(current, previous)


def tool_check_rust_support(args: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _config()
    which = args.get("release", "current")
    root = _resolve_root(which, cfg)
    if root is None:
        return {"error": f"{which} release directory not available"}
    return check_rust_support(root)


def tool_get_release_context(_: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _config()
    body = _read_body(cfg)
    return {
        "tag": cfg["tag"],
        "previousTag": cfg["previousTag"],
        "releaseName": cfg["releaseName"],
        "prerelease": str(cfg["prerelease"]).lower() == "true",
        "publishedAt": cfg["publishedAt"],
        "context": {
            "netFrameworkTarget": "4.0",
            "supportedOs": "All Azure Windows VM OS versions "
                           "(Windows Server 2008 SP2+ / Windows 7 SP2+)",
            "hasRustComponents": True,
            "microsoftSigned": True,
        },
        "changeList": ce.parse_changelist(body, cfg["releaseNotesDir"]),
    }


def tool_collect_full_evidence(_: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _config()
    cur_root = _resolve_root("current", cfg)
    if cur_root is None:
        return {"error": "current release directory not available"}
    prev_root = _resolve_root("previous", cfg)
    current = _all_binaries(cur_root)
    previous = _all_binaries(prev_root) if prev_root else None
    body = _read_body(cfg)
    return {
        "schemaVersion": "1.0",
        "tag": cfg["tag"],
        "releaseName": cfg["releaseName"],
        "prerelease": str(cfg["prerelease"]).lower() == "true",
        "publishedAt": cfg["publishedAt"],
        "previousTag": cfg["previousTag"],
        "context": {
            "netFrameworkTarget": "4.0",
            "supportedOs": "All Azure Windows VM OS versions "
                           "(Windows Server 2008 SP2+ / Windows 7 SP2+)",
            "hasRustComponents": True,
            "microsoftSigned": True,
        },
        "changeList": ce.parse_changelist(body, cfg["releaseNotesDir"]),
        "rustSupport": check_rust_support(cur_root),
        "binaries": {"current": current, "previous": previous},
        "diff": ce.diff_releases(current, previous),
    }


# Tool registry: name -> (handler, description, JSON-schema input).
TOOLS: Dict[str, Dict[str, Any]] = {
    "list_detection_technologies": {
        "handler": tool_list_detection_technologies,
        "description": "Enumerate the detection/analysis technologies this server offers so "
                       "the agent can plan a comprehensive assessment.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "list_binaries": {
        "handler": tool_list_binaries,
        "description": "List the .dll/.exe/.sys binaries in the current or previous release.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "release": {"type": "string", "enum": ["current", "previous"],
                            "default": "current"}
            },
            "additionalProperties": False,
        },
    },
    "inspect_binary": {
        "handler": tool_inspect_binary,
        "description": "Full evidence for one binary: PE/.NET metadata, signature, version, "
                       "risky imports and Rust fingerprints.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "release": {"type": "string", "enum": ["current", "previous"],
                            "default": "current"},
                "path": {"type": "string",
                         "description": "Binary path relative to the release root."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    "inspect_signature": {
        "handler": tool_inspect_signature,
        "description": "Authenticode signature details for a single binary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "release": {"type": "string", "enum": ["current", "previous"],
                            "default": "current"},
                "path": {"type": "string"},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    "diff_releases": {
        "handler": tool_diff_releases,
        "description": "Diff the current release against the previous one: added/removed/"
                       "changed binaries and certificate changes.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "check_rust_support": {
        "handler": tool_check_rust_support,
        "description": "Enumerate Rust binaries, detect the rustc version each was built with, "
                       "and verify it against the agent's supported OS matrix.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "release": {"type": "string", "enum": ["current", "previous"],
                            "default": "current"}
            },
            "additionalProperties": False,
        },
    },
    "get_release_context": {
        "handler": tool_get_release_context,
        "description": "Fixed project constraints (OS matrix, .NET target, signing) plus the "
                       "parsed change list for this release.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    "collect_full_evidence": {
        "handler": tool_collect_full_evidence,
        "description": "Return the complete evidence document (all binaries, diff, rust support) "
                       "in a single call.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
}


def call_tool(name: str, arguments: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Dispatch a tool call by name; used by both transports and tests."""
    spec = TOOLS.get(name)
    if spec is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return spec["handler"](arguments or {})
    except Exception as exc:  # pragma: no cover - defensive
        return {"error": f"{type(exc).__name__}: {exc}"}


def tool_list_payload() -> List[Dict[str, Any]]:
    return [
        {"name": name, "description": spec["description"], "inputSchema": spec["inputSchema"]}
        for name, spec in TOOLS.items()
    ]


# ---------------------------------------------------------------------------
# Transport: official MCP SDK when available, else a minimal JSON-RPC stdio loop
# ---------------------------------------------------------------------------

def _run_with_sdk() -> bool:
    """Run using the official ``mcp`` SDK. Returns False if the SDK is absent."""
    try:
        import anyio
        from mcp.server.lowlevel import Server
        from mcp.server.stdio import stdio_server
        import mcp.types as types
    except Exception:
        return False

    server = Server("windowsvmagent-release-evidence")

    @server.list_tools()
    async def _list_tools() -> List[Any]:  # type: ignore[no-untyped-def]
        return [
            types.Tool(name=t["name"], description=t["description"],
                       inputSchema=t["inputSchema"])
            for t in tool_list_payload()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: Dict[str, Any]) -> List[Any]:  # type: ignore[no-untyped-def]
        result = call_tool(name, arguments)
        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    async def _main() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream,
                             server.create_initialization_options())

    anyio.run(_main)
    return True


def _run_minimal_stdio() -> None:
    """Minimal line-delimited JSON-RPC MCP server (no external dependencies)."""
    def _write(msg: Dict[str, Any]) -> None:
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get("method")
        req_id = req.get("id")
        if method == "initialize":
            _write({
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": req.get("params", {}).get("protocolVersion",
                                                                  "2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "windowsvmagent-release-evidence",
                                   "version": "1.0.0"},
                },
            })
        elif method in ("notifications/initialized", "initialized"):
            continue  # notification, no response
        elif method == "tools/list":
            _write({"jsonrpc": "2.0", "id": req_id,
                    "result": {"tools": tool_list_payload()}})
        elif method == "tools/call":
            params = req.get("params", {}) or {}
            result = call_tool(params.get("name", ""), params.get("arguments") or {})
            _write({
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [
                    {"type": "text", "text": json.dumps(result, indent=2)}
                ]},
            })
        elif req_id is not None:
            _write({"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"}})


def main() -> int:
    if not _run_with_sdk():
        _run_minimal_stdio()
    return 0


if __name__ == "__main__":
    sys.exit(main())
