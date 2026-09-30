"""Scan comparison service evaluating new, fixed, and persisting findings."""

from app.models.finding import Finding
from app.models.scan import Scan


def compare_scans(scan_a: Scan, scan_b: Scan, findings_a: list[Finding], findings_b: list[Finding]) -> dict:
    """Compare two scans for the same target and partition findings into new, fixed, persisting."""
    # Exclude false positives from regression comparison
    valid_a = [f for f in findings_a if f.status != "false_positive"]
    valid_b = [f for f in findings_b if f.status != "false_positive"]

    map_a = {f.fingerprint: f for f in valid_a}
    map_b = {f.fingerprint: f for f in valid_b}

    fps_a = set(map_a.keys())
    fps_b = set(map_b.keys())

    new_fps = fps_b - fps_a
    fixed_fps = fps_a - fps_b
    persisting_fps = fps_a & fps_b

    def _summary(finding: Finding) -> dict:
        return {
            "id": finding.id,
            "fingerprint": finding.fingerprint,
            "type": finding.type,
            "title": finding.title,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "signature": finding.signature,
            "url": finding.url,
            "status": finding.status,
        }

    return {
        "new": [_summary(map_b[fp]) for fp in new_fps],
        "fixed": [_summary(map_a[fp]) for fp in fixed_fps],
        "persisting": [_summary(map_b[fp]) for fp in persisting_fps],
    }
