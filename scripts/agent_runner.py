#!/usr/bin/env python3
"""LLM agent driver: analyze a release by driving the evidence MCP server.

This is the entry point the workflow calls after downloading the latest package
and the one before it. It stands up an **LLM-based agent** (Claude Opus 4.8 by
default) that:

1. loads the ``release-risk-analysis`` **skill** (``skills/release-risk-analysis/
   SKILL.md``) as its operating instructions,
2. connects to the **MCP server** (``mcp_server/evidence_mcp_server.py``) over
   stdio and discovers the evidence-collection / analysis tools it exposes,
3. enumerates the available detection technologies, calls the tools to inspect
   the current and previous packages (signing, PE/.NET metadata, OS-compat
   imports, binary diff, and the **Rust compiler / OS supportability** check),
   and
4. produces a single schema-validated risk report written to ``analysis/<tag>.json``.

Design goals:

* **The agent, not the pipeline, decides what to inspect.** The workflow only
  downloads and unpacks the two packages; all evidence gathering happens through
  MCP tool calls the model chooses to make.
* **No hard dependency on secrets or SDKs.** When ``ANTHROPIC_API_KEY`` is unset
  or the ``anthropic`` SDK is missing, ``--allow-fallback`` produces a
  deterministic evidence-only report (reusing ``analyze_release``) so downstream
  stages still work on forks / dry runs.
* **MCP transport is line-delimited JSON-RPC over stdio**, which is compatible
  with both the official ``mcp`` SDK server and this repo's dependency-free
  fallback server.

The Anthropic API key is read from the environment and never inlined.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_MCP_SERVER = os.path.join(_ROOT, "mcp_server", "evidence_mcp_server.py")
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import analyze_release as ar  # noqa: E402


# ---------------------------------------------------------------------------
# Minimal MCP stdio client (line-delimited JSON-RPC)
# ---------------------------------------------------------------------------

class MCPStdioClient:
    """Spawn an MCP server subprocess and talk to it over stdio JSON-RPC."""

    def __init__(self, server_cmd: List[str], env: Dict[str, str]) -> None:
        self._proc = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            bufsize=1,
        )
        self._id = 0
        self._lock = threading.Lock()

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _send(self, payload: Dict[str, Any]) -> None:
        assert self._proc.stdin is not None
        self._proc.stdin.write(json.dumps(payload) + "\n")
        self._proc.stdin.flush()

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        req_id = self._next_id()
        with self._lock:
            self._send({"jsonrpc": "2.0", "id": req_id, "method": method,
                        "params": params or {}})
            assert self._proc.stdout is not None
            # Read lines until we see the matching id (skip notifications/logs).
            while True:
                line = self._proc.stdout.readline()
                if not line:
                    raise RuntimeError(
                        f"MCP server closed the connection while awaiting '{method}'.")
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue  # server diagnostic noise
                if msg.get("id") == req_id:
                    if "error" in msg:
                        raise RuntimeError(f"MCP error for {method}: {msg['error']}")
                    return msg.get("result", {})

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def initialize(self) -> Dict[str, Any]:
        result = self._request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "release-agent-runner", "version": "1.0.0"},
        })
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        return self._request("tools/list").get("tools", [])

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        parts = [c.get("text", "") for c in result.get("content", [])
                 if c.get("type") == "text"]
        return "\n".join(parts) if parts else json.dumps(result)

    def close(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.close()
        except Exception:
            pass
        try:
            self._proc.terminate()
            self._proc.wait(timeout=10)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def load_skill(skill_path: str) -> str:
    try:
        with open(skill_path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def build_system_prompt(skill_text: str) -> str:
    guardrails = (
        "You are operating as an autonomous release-analysis agent. Use the MCP "
        "tools to gather evidence; reason ONLY over what the tools return and do "
        "not invent facts. When you have finished your investigation, output your "
        "final answer as a SINGLE JSON object ONLY (no markdown fences, no prose) "
        "that conforms to the provided analysis schema. Do not call any tool in the "
        "same turn as your final JSON answer."
    )
    if skill_text:
        return skill_text.strip() + "\n\n---\n\n" + guardrails
    return ar.SYSTEM_PROMPT + "\n\n" + guardrails


# ---------------------------------------------------------------------------
# Agentic loop over the Anthropic Messages API with MCP tools
# ---------------------------------------------------------------------------

def run_agent(model: str, schema: Dict[str, Any], client: MCPStdioClient,
              max_tokens: int, max_turns: int) -> Dict[str, Any]:
    import anthropic  # type: ignore

    tools = client.list_tools()
    anthropic_tools = [
        {"name": t["name"], "description": t.get("description", ""),
         "input_schema": t.get("inputSchema", {"type": "object"})}
        for t in tools
    ]

    system = build_system_prompt(load_skill(
        os.environ.get("SKILL_PATH", os.path.join(
            _ROOT, "skills", "release-risk-analysis", "SKILL.md"))))

    user_intro = (
        "Analyze the current Windows VM Agent release against the previous one. "
        "First enumerate the available detection technologies, then use the MCP "
        "tools to collect the evidence you need (signing, PE/.NET metadata, "
        "OS-compatibility imports, release diff, and the Rust compiler / OS "
        "supportability check). Then produce the final schema-validated JSON "
        "report.\n\nThe JSON schema you MUST conform to is:\n\n"
        + json.dumps(schema, indent=2)
    )

    messages: List[Dict[str, Any]] = [{"role": "user", "content": user_intro}]
    api = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    for _turn in range(max_turns):
        message = api.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            tools=anthropic_tools,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": message.content})

        if message.stop_reason == "tool_use":
            tool_results: List[Dict[str, Any]] = []
            for block in message.content:
                if getattr(block, "type", None) != "tool_use":
                    continue
                output = client.call_tool(block.name, dict(block.input or {}))
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": output,
                })
            messages.append({"role": "user", "content": tool_results})
            continue

        # Final answer: concatenate text blocks and extract the JSON object.
        text = "".join(getattr(b, "text", "") for b in message.content
                       if getattr(b, "type", None) == "text")
        return ar._extract_json(text)

    raise RuntimeError(f"Agent did not produce a final result within {max_turns} turns.")


# ---------------------------------------------------------------------------
# Fallback: deterministic evidence-only report (no LLM)
# ---------------------------------------------------------------------------

def fallback_via_mcp(client: MCPStdioClient, model: str) -> Dict[str, Any]:
    raw = client.call_tool("collect_full_evidence", {})
    evidence = json.loads(raw)
    result = ar.fallback_result(evidence, model)
    ar.compute_derived(result, evidence)
    return result, evidence


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _server_env() -> Dict[str, str]:
    """Environment for the MCP server subprocess (evidence source config)."""
    env = dict(os.environ)
    # These are consumed by mcp_server/evidence_mcp_server.py.
    for key in ("EVIDENCE_CURRENT_DIR", "EVIDENCE_PREVIOUS_DIR", "EVIDENCE_TAG",
                "EVIDENCE_PREVIOUS_TAG", "EVIDENCE_RELEASE_NAME", "EVIDENCE_PRERELEASE",
                "EVIDENCE_PUBLISHED_AT", "EVIDENCE_BODY_FILE", "EVIDENCE_RELEASE_NOTES_DIR"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--model", default=ar.DEFAULT_MODEL)
    parser.add_argument("--skill",
                        default=os.path.join(_ROOT, "skills", "release-risk-analysis",
                                             "SKILL.md"))
    parser.add_argument("--mcp-server", default=_MCP_SERVER)
    parser.add_argument("--max-tokens", type=int, default=8000)
    parser.add_argument("--max-turns", type=int, default=24)
    parser.add_argument("--allow-fallback", action="store_true",
                        help="Emit a deterministic evidence-only result if no API key / SDK.")
    parser.add_argument("--evidence-out", default=None,
                        help="Optionally also write the raw evidence document here.")
    args = parser.parse_args()

    os.environ.setdefault("SKILL_PATH", args.skill)
    schema = ar.load_schema(args.schema)

    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    try:
        import anthropic  # type: ignore  # noqa: F401
        has_sdk = True
    except ImportError:
        has_sdk = False

    client = MCPStdioClient([sys.executable, args.mcp_server], _server_env())
    evidence: Optional[Dict[str, Any]] = None
    try:
        client.initialize()

        if has_key and has_sdk:
            result = run_agent(args.model, schema, client, args.max_tokens, args.max_turns)
            # Normalize identity fields from the release context tool.
            ctx = json.loads(client.call_tool("get_release_context", {}))
            result.setdefault("schemaVersion", "1.0")
            result["tag"] = ctx.get("tag", result.get("tag", ""))
            result["prerelease"] = bool(ctx.get("prerelease"))
            result.setdefault("releaseName", ctx.get("releaseName"))
            result.setdefault("publishedAt", ctx.get("publishedAt"))
            result.setdefault("previousTag", ctx.get("previousTag"))
            result["generatedAt"] = datetime.now(timezone.utc).isoformat()
            result.setdefault("model", args.model)
            evidence = json.loads(client.call_tool("collect_full_evidence", {}))
            ar.compute_derived(result, evidence)
        else:
            if not args.allow_fallback:
                print("ERROR: ANTHROPIC_API_KEY unset or 'anthropic' SDK missing and "
                      "--allow-fallback not specified.", file=sys.stderr)
                return 2
            result, evidence = fallback_via_mcp(client, args.model)
    finally:
        client.close()

    errors = ar.validate(result, schema)
    if errors:
        print("ERROR: analysis result failed schema validation:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 4

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=False)
    if args.evidence_out and evidence is not None:
        with open(args.evidence_out, "w", encoding="utf-8") as fh:
            json.dump(evidence, fh, indent=2, sort_keys=False)
    print(f"Wrote {args.output} (overallRisk={result.get('overallRisk')}, "
          f"{len(result.get('findings', []))} findings).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
