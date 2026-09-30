"""Finding fingerprint generation for deduplication and regression comparison."""

import hashlib


def compute_fingerprint(
    finding_type: str,
    method: str,
    signature: str,
    source_role: str,
    tested_role: str,
) -> str:
    """Generate canonical 16-hex fingerprint from finding coordinates.

    Spec: first 16 hex of sha256(f"{type}|{method}|{signature}|{source_role}|{tested_role}")
    """
    raw = f"{finding_type}|{method}|{signature}|{source_role}|{tested_role}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
