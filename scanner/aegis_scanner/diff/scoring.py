"""Confidence scoring and candidate evaluation based on diff signals."""

import json
import re
from dataclasses import dataclass
from typing import Any

from aegis_scanner.models import AccountConfig

EMAIL_REGEX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
SENSITIVE_JSON_KEY_RE = re.compile(
    r"(?i)password|passwd|secret|api[_-]?key|token|ssn|iban|credit|card|balance|address|phone|salary|e-?mail"
)


@dataclass
class Signals:
    """Signals extracted from original, control, and replay responses."""
    original_has_content: bool   # normalized original is not empty ({} / no text)
    similarity: float            # replay vs original [0..1]
    stability: float             # original vs control replay by the same role [0..1]
    personalized: bool           # original body contains the source account's identifiers
    has_source_identifiers: bool # replay body contains the source account's identifiers
    served_own_data: bool        # replay body contains tested account's identifiers but NOT the source's
    id_in_path: bool             # signature contains {id}
    body_len: int                # length of replay body
    sensitive_fields: bool       # body has keys/words matching the sensitive pattern
    looks_public: bool           # anonymous replay is also similar AND no identifiers AND no id AND no sensitive fields


def extract_identifiers(account: AccountConfig) -> set[str]:
    """Extract normalized identifier strings (len >= 3) for an account."""
    idents = set()
    if account.username:
        u = account.username.strip()
        if len(u) >= 3:
            idents.add(u)
        if "@" in u:
            local = u.split("@")[0].strip()
            if len(local) >= 3:
                idents.add(local)

    for item in account.identifiers:
        s = str(item).strip()
        if len(s) >= 3:
            idents.add(s)

    return idents


def contains_identifier(text: str, identifiers: set[str]) -> bool:
    """Case-insensitive, word-boundary match for any identifier in text."""
    if not text or not identifiers:
        return False
    for ident in identifiers:
        pattern = rf"\b{re.escape(ident)}\b"
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def check_sensitive_fields(body: str, is_json: bool = False) -> bool:
    """Check if raw body contains sensitive data indicators."""
    if not body:
        return False

    if is_json:
        try:
            parsed = json.loads(body)

            def _has_sensitive_key(node: Any) -> bool:
                if isinstance(node, dict):
                    for k, v in node.items():
                        if SENSITIVE_JSON_KEY_RE.search(str(k)):
                            return True
                        if _has_sensitive_key(v):
                            return True
                elif isinstance(node, list):
                    for item in node:
                        if _has_sensitive_key(item):
                            return True
                return False

            return _has_sensitive_key(parsed)
        except Exception:
            pass

    # HTML / plain text: only consider email addresses as sensitive
    return bool(EMAIL_REGEX.search(body))


def is_finding_candidate(signals: Signals) -> bool:
    """Determine whether a replayed response qualifies as an access-control finding."""
    # 0. If original has no meaningful content, it cannot be compared
    if not signals.original_has_content:
        return False

    # 1. If server returned the tested user's own data, not an access violation
    if signals.served_own_data:
        return False

    # 2. If the original was personalized to source, replay must contain source's identifiers
    if signals.personalized and not signals.has_source_identifiers:
        return False

    # 4. If the page is too unstable across identical requests, results are unreliable
    if signals.stability < 0.5:
        return False

    # 3. Required similarity bar (allows slight variance on dynamic pages)
    required_sim = min(0.85, signals.stability - 0.05)
    if signals.similarity < required_sim:
        return False

    return True


def confidence_score(signals: Signals) -> int:
    """Calculate finding confidence score (0 to 100)."""
    score = 0

    # Base similarity credit relative to stability
    rel_sim = min(1.0, signals.similarity / max(signals.stability, 0.5))
    score += round(50 * rel_sim)

    if signals.has_source_identifiers:
        score += 25
    if signals.id_in_path:
        score += 15
    if signals.body_len >= 100:
        score += 10
    if signals.sensitive_fields:
        score += 10
    if signals.looks_public:
        score -= 30

    return max(0, min(100, score))


def adjust_severity(severity: str, confidence: int) -> str:
    """Downgrade severity by one level if confidence < 70."""
    if confidence >= 70:
        return severity

    downgrades = {
        "Critical": "High",
        "High": "Medium",
        "Medium": "Low",
        "Low": "Info",
        "Info": "Info",
    }
    return downgrades.get(severity, severity)
