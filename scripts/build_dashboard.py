#!/usr/bin/env python3
"""Render analysis results into human-readable markdown.

Two outputs are produced:

* ``analysis/<tag>.md`` — a per-release rendering of a single ``analysis/<tag>.json``.
* ``docs/risk-dashboard.md`` — an aggregate dashboard built from every
  ``analysis/*.json``: a summary table (one row per release) plus per-release
  drill-down sections grouped by category and severity.

Both renderers are deterministic and depend only on the standard library so the
workflow can run them on any runner.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any, Dict, List

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_EMOJI = {
    "Critical": "🟥",
    "High": "🟧",
    "Medium": "🟨",
    "Low": "🟩",
    "Info": "🟦",
}


def severity_badge(sev: str) -> str:
    return f"{SEVERITY_EMOJI.get(sev, '⬜')} {sev}"


def load_results(analysis_dir: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for path in glob.glob(os.path.join(analysis_dir, "*.json")):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                results.append(json.load(fh))
        except (OSError, json.JSONDecodeError):
            continue
    # Newest first by publishedAt then tag.
    results.sort(key=lambda r: (r.get("publishedAt") or "", r.get("tag") or ""),
                 reverse=True)
    return results


def counts_for(result: Dict[str, Any]) -> Dict[str, int]:
    counts = result.get("severityCounts")
    if not counts:
        counts = {s: 0 for s in SEVERITIES}
        for f in result.get("findings", []):
            sev = f.get("severity")
            if sev in counts:
                counts[sev] += 1
    return counts


def flag_marks(result: Dict[str, Any]) -> Dict[str, str]:
    flags = result.get("flags", {}) or {}

    def mark(v: Any) -> str:
        return "✅" if v else "—"

    return {
        "cert": mark(flags.get("certChanged")),
        "net": mark(flags.get("netFrameworkDrift")),
        "rust": mark(flags.get("rustChanged")),
        "os": mark(flags.get("osCompatibilityConcern")),
    }


def render_release_md(result: Dict[str, Any]) -> str:
    tag = result.get("tag", "unknown")
    kind = "Pre-release" if result.get("prerelease") else "Latest"
    counts = counts_for(result)
    lines: List[str] = []
    lines.append(f"# Release Risk Analysis — {tag}")
    lines.append("")
    lines.append(f"* **Release type:** {kind}")
    lines.append(f"* **Overall risk:** {severity_badge(result.get('overallRisk', 'Info'))}")
    if result.get("previousTag"):
        lines.append(f"* **Compared against:** `{result['previousTag']}`")
    lines.append(f"* **Model:** {result.get('model', 'n/a')}")
    lines.append(f"* **Generated at:** {result.get('generatedAt', 'n/a')}")
    lines.append("")
    lines.append("**Severity counts:** " + " · ".join(
        f"{severity_badge(s)} {counts.get(s, 0)}" for s in SEVERITIES))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(result.get("summary", "_No summary provided._"))
    lines.append("")

    findings = result.get("findings", [])
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("_No findings recorded._")
        lines.append("")
    else:
        # Group by category, then order by severity.
        order = {s: i for i, s in enumerate(SEVERITIES)}
        by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            by_cat.setdefault(f.get("category", "Other"), []).append(f)
        for cat in sorted(by_cat):
            lines.append(f"### {cat}")
            lines.append("")
            lines.append("| Severity | Finding | Rationale | Recommendation |")
            lines.append("|----------|---------|-----------|----------------|")
            for f in sorted(by_cat[cat], key=lambda x: order.get(x.get("severity"), 99)):
                lines.append(
                    f"| {severity_badge(f.get('severity', 'Info'))} "
                    f"| {_cell(f.get('finding'))} "
                    f"| {_cell(f.get('rationale'))} "
                    f"| {_cell(f.get('recommendation'))} |"
                )
            lines.append("")
    return "\n".join(lines) + "\n"


def _cell(text: Any) -> str:
    if not text:
        return ""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def render_dashboard(results: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append("# Windows VM Agent — Release Risk & Compatibility Dashboard")
    lines.append("")
    lines.append("Automatically generated from `analysis/*.json`. Each release is "
                 "analyzed for risk & compatibility across the supported Azure "
                 "Windows VM OS versions (.NET Framework 4.0 + Rust components, "
                 "Microsoft-signed binaries).")
    lines.append("")
    lines.append("**Severity legend:** " + " · ".join(
        severity_badge(s) for s in SEVERITIES))
    lines.append("")

    if not results:
        lines.append("_No analysis results found yet._")
        lines.append("")
        return "\n".join(lines) + "\n"

    lines.append("## Releases")
    lines.append("")
    lines.append("| Release | Type | Published | Overall | 🟥 | 🟧 | 🟨 | 🟩 | 🟦 "
                 "| Cert Δ | .NET drift | Rust Δ | OS concern |")
    lines.append("|---------|------|-----------|---------|----|----|----|----|----"
                 "|--------|-----------|--------|-----------|")
    for r in results:
        tag = r.get("tag", "unknown")
        kind = "Pre-release" if r.get("prerelease") else "Latest"
        counts = counts_for(r)
        marks = flag_marks(r)
        published = (r.get("publishedAt") or "")[:10]
        link = f"[`{tag}`](../analysis/{tag}.md)"
        lines.append(
            f"| {link} | {kind} | {published} "
            f"| {severity_badge(r.get('overallRisk', 'Info'))} "
            f"| {counts.get('Critical', 0)} | {counts.get('High', 0)} "
            f"| {counts.get('Medium', 0)} | {counts.get('Low', 0)} "
            f"| {counts.get('Info', 0)} "
            f"| {marks['cert']} | {marks['net']} | {marks['rust']} | {marks['os']} |"
        )
    lines.append("")

    lines.append("## Details")
    lines.append("")
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for r in results:
        tag = r.get("tag", "unknown")
        kind = "Pre-release" if r.get("prerelease") else "Latest"
        lines.append(f"### {tag} — {severity_badge(r.get('overallRisk', 'Info'))} ({kind})")
        lines.append("")
        lines.append(r.get("summary", "_No summary._"))
        lines.append("")
        findings = sorted(r.get("findings", []),
                          key=lambda x: order.get(x.get("severity"), 99))
        if findings:
            lines.append("| Severity | Category | Finding | Recommendation |")
            lines.append("|----------|----------|---------|----------------|")
            for f in findings:
                lines.append(
                    f"| {severity_badge(f.get('severity', 'Info'))} "
                    f"| {_cell(f.get('category'))} "
                    f"| {_cell(f.get('finding'))} "
                    f"| {_cell(f.get('recommendation'))} |"
                )
            lines.append("")
        lines.append(f"[Full report »](../analysis/{tag}.md)")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-dir", default="analysis")
    parser.add_argument("--dashboard", default="docs/risk-dashboard.md")
    parser.add_argument("--release-json", default=None,
                        help="If set, also render this single result to --release-md.")
    parser.add_argument("--release-md", default=None)
    args = parser.parse_args()

    if args.release_json:
        with open(args.release_json, "r", encoding="utf-8") as fh:
            result = json.load(fh)
        md = render_release_md(result)
        out_md = args.release_md or os.path.join(
            args.analysis_dir, f"{result.get('tag', 'release')}.md")
        os.makedirs(os.path.dirname(os.path.abspath(out_md)), exist_ok=True)
        with open(out_md, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"Wrote {out_md}")

    results = load_results(args.analysis_dir)
    dashboard = render_dashboard(results)
    os.makedirs(os.path.dirname(os.path.abspath(args.dashboard)), exist_ok=True)
    with open(args.dashboard, "w", encoding="utf-8") as fh:
        fh.write(dashboard)
    print(f"Wrote {args.dashboard} ({len(results)} releases).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
