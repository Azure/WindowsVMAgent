#!/usr/bin/env python3
"""Invoke the LLM (Claude Opus 4.8) to analyze release evidence and emit a
schema-validated, structured risk & compatibility result.

Inputs:
* ``evidence.json`` produced by ``collect_evidence.py``.
* The analysis JSON schema (``schema/analysis.schema.json``).

The script builds a fixed system/context prompt describing the project (runs on
all Azure Windows VM OS versions, targets .NET Framework 4.0, contains Rust
components, all binaries Microsoft-signed, certificate changes vs. the previous
release are in scope), sends the evidence to the model, parses the model's JSON
response, validates it against the schema, and writes ``analysis/<tag>.json``.

The LLM API key is read from the ``ANTHROPIC_API_KEY`` environment variable and
must be supplied via a GitHub Actions secret; it is never inlined.

If no API key is available (e.g. a dry run or fork PR without secrets), the
script can emit a deterministic evidence-only fallback result with ``--allow-fallback``
so downstream stages (dashboard) still function. The fallback is clearly marked.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DEFAULT_MODEL = "claude-opus-4-8"

CATEGORIES = [
    "Change list",
    "OS compatibility",
    "Signing/certificate change",
    ".NET Framework 4.0",
    "Rust components",
    "Binary/dependency changes",
    "Other",
]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

SYSTEM_PROMPT = """\
You are a release risk & compatibility analyst for the Microsoft Azure Windows \
VM Agent. You must reason strictly over the deterministic evidence provided; do \
not invent facts. The project has these fixed properties:

* It runs on ALL Azure Windows VM OS versions (Windows Server 2008 SP2+ and \
Windows 7 SP2+ through the newest Windows Server SKUs), x64.
* It targets .NET Framework 4.0. Any drift away from 4.0 is a compatibility risk.
* Part of the code is written in Rust and shipped as native binaries.
* All shipped binaries are signed with a Microsoft certificate. Unsigned \
binaries, broken signatures, or certificate changes versus the previous release \
(thumbprint / issuer / serial / algorithm / timestamp authority) are in scope.

Perform a comprehensive risk assessment covering the change list, OS \
compatibility (including imports unavailable on the oldest supported OS), \
signing/certificate changes, .NET Framework 4.0 targeting, Rust components, and \
binary/dependency changes. Assign a severity to each finding.

Respond with a SINGLE JSON object ONLY (no markdown, no prose) that conforms to \
the provided JSON schema. Every finding must have category, severity, finding, \
rationale (grounded in the evidence), and recommendation. Provide an overall \
risk rating and a concise high-level summary.\
"""


def load_schema(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate(result: Dict[str, Any], schema: Dict[str, Any]) -> List[str]:
    """Validate the result against the schema.

    Uses ``jsonschema`` when available, otherwise applies a minimal built-in
    check of the properties this pipeline depends on. Returns a list of error
    strings (empty when valid).
    """
    try:
        import jsonschema  # type: ignore

        validator = jsonschema.Draft7Validator(schema)
        return [f"{'/'.join(str(p) for p in e.path)}: {e.message}"
                for e in validator.iter_errors(result)]
    except ImportError:
        return _minimal_validate(result)


def _minimal_validate(result: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    required = ["schemaVersion", "tag", "prerelease", "generatedAt", "model",
                "overallRisk", "summary", "findings"]
    for key in required:
        if key not in result:
            errors.append(f"missing required property: {key}")
    if result.get("overallRisk") not in SEVERITIES:
        errors.append(f"overallRisk not in {SEVERITIES}")
    if not isinstance(result.get("findings"), list):
        errors.append("findings must be an array")
    else:
        for i, f in enumerate(result["findings"]):
            if not isinstance(f, dict):
                errors.append(f"findings[{i}] must be an object")
                continue
            if f.get("category") not in CATEGORIES:
                errors.append(f"findings[{i}].category invalid")
            if f.get("severity") not in SEVERITIES:
                errors.append(f"findings[{i}].severity invalid")
            for key in ("finding", "rationale", "recommendation"):
                if not f.get(key):
                    errors.append(f"findings[{i}].{key} missing/empty")
    return errors


def compute_derived(result: Dict[str, Any], evidence: Dict[str, Any]) -> None:
    """Fill in severityCounts and flags from findings/evidence if absent."""
    counts = {s: 0 for s in SEVERITIES}
    for f in result.get("findings", []):
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    result.setdefault("severityCounts", counts)

    diff = evidence.get("diff", {}) or {}
    cert_changes = diff.get("certificateChanges") or []
    unsigned = any(
        (b.get("signature", {}) or {}).get("status") in
        ("NotSigned", "Unknown", "HashMismatch")
        for b in (evidence.get("binaries", {}).get("current") or [])
    )
    net_drift = any(
        (b.get("pe", {}) or {}).get("isDotNet") and
        f.get("category") == ".NET Framework 4.0" and f.get("severity") != "Info"
        for b in (evidence.get("binaries", {}).get("current") or [])
        for f in result.get("findings", [])
    )
    rust_changed = bool(diff.get("added") or diff.get("removed"))
    os_concern = any(b.get("riskyImports")
                     for b in (evidence.get("binaries", {}).get("current") or []))
    result.setdefault("flags", {
        "certChanged": bool(cert_changes),
        "netFrameworkDrift": bool(net_drift),
        "rustChanged": bool(rust_changed),
        "osCompatibilityConcern": bool(os_concern),
        "unsignedBinaries": bool(unsigned),
    })


def call_anthropic(model: str, evidence: Dict[str, Any],
                   schema: Dict[str, Any], max_tokens: int) -> Dict[str, Any]:
    """Call the Anthropic Messages API and return the parsed JSON result."""
    import anthropic  # type: ignore

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    user_content = (
        "Analyze the following release evidence and produce the structured "
        "result. The JSON schema you must conform to is:\n\n"
        + json.dumps(schema, indent=2)
        + "\n\nEVIDENCE:\n\n"
        + json.dumps(evidence, indent=2)
    )
    message = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    text = "".join(block.text for block in message.content
                   if getattr(block, "type", None) == "text")
    return _extract_json(text)


def _extract_json(text: str) -> Dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        # strip code fences
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip("` \n")
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("No JSON object found in model response.")
    return json.loads(text[start:end + 1])


def fallback_result(evidence: Dict[str, Any], model: str) -> Dict[str, Any]:
    """Deterministic evidence-only result used when no LLM key is available."""
    findings: List[Dict[str, Any]] = []
    diff = evidence.get("diff", {}) or {}
    for cc in (diff.get("certificateChanges") or []):
        findings.append({
            "category": "Signing/certificate change",
            "severity": "High",
            "finding": f"Certificate metadata changed for {cc.get('path')}",
            "rationale": "Deterministic diff detected a signing certificate field change "
                         "versus the previous release.",
            "recommendation": "Confirm the certificate rotation is expected and Microsoft-issued.",
            "evidenceRefs": [cc.get("path", "")],
        })
    for b in (evidence.get("binaries", {}).get("current") or []):
        if b.get("riskyImports"):
            findings.append({
                "category": "OS compatibility",
                "severity": "Medium",
                "finding": f"{b['path']} imports DLLs that may be unavailable on older OS",
                "rationale": f"Imports flagged: {', '.join(b['riskyImports'])}.",
                "recommendation": "Verify availability on Windows Server 2008 SP2 / Windows 7 SP2.",
                "evidenceRefs": [b["path"]],
            })
        if (b.get("signature", {}) or {}).get("status") in ("NotSigned", "HashMismatch"):
            findings.append({
                "category": "Signing/certificate change",
                "severity": "Critical",
                "finding": f"{b['path']} is not validly signed",
                "rationale": f"Signature status: {b['signature'].get('status')}.",
                "recommendation": "All shipped binaries must carry a valid Microsoft signature.",
                "evidenceRefs": [b["path"]],
            })
    if not findings:
        findings.append({
            "category": "Other",
            "severity": "Info",
            "finding": "No deterministic risks detected; LLM analysis not run.",
            "rationale": "No LLM API key was provided, so only evidence-based heuristics ran.",
            "recommendation": "Provide ANTHROPIC_API_KEY to enable full Claude Opus 4.8 analysis.",
        })
    order = {s: i for i, s in enumerate(SEVERITIES)}
    overall = min((f["severity"] for f in findings), key=lambda s: order[s])
    return {
        "schemaVersion": "1.0",
        "tag": evidence.get("tag", ""),
        "releaseName": evidence.get("releaseName"),
        "prerelease": bool(evidence.get("prerelease")),
        "publishedAt": evidence.get("publishedAt"),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "model": f"{model} (fallback: evidence-only heuristics)",
        "previousTag": evidence.get("previousTag"),
        "overallRisk": overall,
        "summary": "Evidence-only fallback analysis (LLM not invoked). "
                   "Findings are derived solely from deterministic evidence.",
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--max-tokens", type=int, default=8000)
    parser.add_argument("--allow-fallback", action="store_true",
                        help="Emit deterministic evidence-only result if no API key is set.")
    args = parser.parse_args()

    with open(args.evidence, "r", encoding="utf-8") as fh:
        evidence = json.load(fh)
    schema = load_schema(args.schema)

    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    if not has_key:
        if not args.allow_fallback:
            print("ERROR: ANTHROPIC_API_KEY is not set and --allow-fallback was not "
                  "specified.", file=sys.stderr)
            return 2
        result = fallback_result(evidence, args.model)
    else:
        try:
            result = call_anthropic(args.model, evidence, schema, args.max_tokens)
        except ImportError:
            print("ERROR: the 'anthropic' package is not installed.", file=sys.stderr)
            return 3
        # Ensure identity fields are present/correct regardless of model output.
        result.setdefault("schemaVersion", "1.0")
        result["tag"] = evidence.get("tag", result.get("tag", ""))
        result["prerelease"] = bool(evidence.get("prerelease"))
        result.setdefault("releaseName", evidence.get("releaseName"))
        result.setdefault("publishedAt", evidence.get("publishedAt"))
        result.setdefault("previousTag", evidence.get("previousTag"))
        result["generatedAt"] = datetime.now(timezone.utc).isoformat()
        result.setdefault("model", args.model)

    compute_derived(result, evidence)

    errors = validate(result, schema)
    if errors:
        print("ERROR: analysis result failed schema validation:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 4

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=False)
    print(f"Wrote {args.output} (overallRisk={result['overallRisk']}, "
          f"{len(result['findings'])} findings).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
