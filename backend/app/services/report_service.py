"""Security report generation service in Markdown and structured JSON."""

import re
from datetime import datetime, timezone
from app.models.finding import Finding
from app.models.scan import Scan


def _escape_md(text: str | None) -> str:
    """Escape markdown special characters to prevent link/content injection."""
    if not text:
        return ""
    # Escape brackets, parentheses, asterisks, underscores, and backticks
    return re.sub(r"([\\`*_{}\[\]()#+\-.!])", r"\\\1", text)


def build_markdown(scan: Scan, findings: list[Finding]) -> str:
    """Generate safe, injection-proof Markdown audit report."""
    target_name = scan.target.name if scan.target else "Target"
    target_url = scan.target.base_url if scan.target else ""
    date_str = (scan.finished_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Counts by severity
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    md_lines = [
        f"# Aegis-Web Security Assessment Report",
        f"",
        f"**Target:** `{_escape_md(target_name)}` ({_escape_md(target_url)})  ",
        f"**Scan ID:** {scan.id}  ",
        f"**Date:** {date_str}  ",
        f"**Status:** {scan.status}  ",
        f"",
        f"## Executive Summary",
        f"",
        f"| Severity | Findings Count |",
        f"| :--- | :--- |",
        f"| **Critical** | {sev_counts['Critical']} |",
        f"| **High** | {sev_counts['High']} |",
        f"| **Medium** | {sev_counts['Medium']} |",
        f"| **Low** | {sev_counts['Low']} |",
        f"| **Info** | {sev_counts['Info']} |",
        f"| **Total** | **{len(findings)}** |",
        f"",
        f"---",
        f"",
        f"## Detailed Findings",
        f"",
    ]

    if not findings:
        md_lines.append("No access-control vulnerabilities were identified.")
    else:
        for idx, f in enumerate(findings, 1):
            evidence = f.evidence or {}
            orig_meta = evidence.get("original", {})
            replay_meta = evidence.get("replay", {})
            similarity_val = evidence.get("similarity", "N/A")

            md_lines.extend([
                f"### {idx}. {_escape_md(f.title)}",
                f"",
                f"- **Vulnerability Type:** `{f.type}`",
                f"- **Severity:** **{f.severity}** (Confidence: {f.confidence}%)",
                f"- **CVSS v3.1:** `{f.cvss_score}` (`{f.cvss_vector}`)",
                f"- **CWE:** {f.cwe}",
                f"- **OWASP:** {f.owasp}",
                f"- **Endpoint:** `{f.method} {_escape_md(f.signature)}`",
                f"- **Target URL:** `{_escape_md(f.url)}`",
                f"- **Source Role:** `{_escape_md(f.source_role)}`",
                f"- **Tested Role:** `{_escape_md(f.tested_role)}`",
                f"- **Triage Status:** `{f.status}`",
                f"",
                f"#### Description",
                f"{_escape_md(f.description)}",
                f"",
                f"#### Verification Metadata",
                f"- Original Response Status: `{orig_meta.get('status', 'N/A')}`",
                f"- Replay Response Status: `{replay_meta.get('status', 'N/A')}`",
                f"- Normalized Response Similarity: `{similarity_val}`",
                f"",
                f"#### Remediation",
                f"{_escape_md(f.remediation)}",
                f"",
                f"---",
                f"",
            ])

    return "\n".join(md_lines)
