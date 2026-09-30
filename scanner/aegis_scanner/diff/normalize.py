"""Response body normalization to eliminate dynamic noise (CSRF tokens, timestamps, etc.)."""

import json
import re
from dataclasses import dataclass
from typing import Any
from bs4 import BeautifulSoup, Comment

VOLATILE_KEY_RE = re.compile(
    r"^(iat|exp|nbf|timestamp|time|date|createdat|updatedat|created_at|updated_at|"
    r"lastlogin|last_login|requestid|request_id|traceid|trace_id|nonce|csrf|csrftoken|"
    r"_csrf|etag|token|access_token|refresh_token)$",
    re.IGNORECASE,
)

ISO_TIMESTAMP_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    re.IGNORECASE,
)

HEX_LONG_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

HIDDEN_CSRF_NAME_RE = re.compile(r"^(csrf|token|nonce|_csrf)$", re.IGNORECASE)


@dataclass
class Normalized:
    """Normalized response representation for structural and textual comparison."""
    kind: str                    # "json" | "text"
    flat: dict[str, str] | None  # flattened path -> str value for JSON
    text: str                    # canonical string for comparison
    raw_len: int                 # length of raw input

    @property
    def has_content(self) -> bool:
        """Return True if normalized body contains meaningful content after noise removal."""
        if self.kind == "json":
            return bool(self.flat)
        return bool(self.text.strip())



def _clean_json_node(node: Any) -> Any:
    """Recursively strip volatile keys and normalize datetime values in JSON structures."""
    if isinstance(node, dict):
        cleaned = {}
        for k, v in node.items():
            if VOLATILE_KEY_RE.match(str(k)):
                continue
            cleaned[str(k)] = _clean_json_node(v)
        return cleaned
    elif isinstance(node, list):
        return [_clean_json_node(elem) for elem in node]
    elif isinstance(node, str):
        if ISO_TIMESTAMP_RE.search(node):
            return ISO_TIMESTAMP_RE.sub("<TS>", node)
        return node
    return node


def _flatten_json(node: Any, prefix: str = "") -> dict[str, str]:
    """Flatten a nested JSON object into dot/bracket paths mapping to string representations."""
    items: dict[str, str] = {}
    if isinstance(node, dict):
        for k, v in node.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                items.update(_flatten_json(v, path))
            else:
                items[path] = str(v)
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            path = f"{prefix}[{idx}]"
            if isinstance(item, (dict, list)):
                items.update(_flatten_json(item, path))
            else:
                items[path] = str(item)
    else:
        if prefix:
            items[prefix] = str(node)
    return items


def normalize_body(text: str | None, content_type: str | None = None) -> Normalized:
    """Normalize an HTTP response body by removing noise for reproducible diffing."""
    if text is None:
        return Normalized(kind="text", flat=None, text="", raw_len=0)

    raw_len = len(text)
    stripped = text.strip()
    if not stripped:
        return Normalized(kind="text", flat=None, text="", raw_len=raw_len)

    # Check for JSON content
    is_json = bool(content_type and "json" in content_type.lower()) or stripped.startswith(("{", "["))
    if is_json:
        try:
            parsed = json.loads(stripped)
            cleaned = _clean_json_node(parsed)
            flat = _flatten_json(cleaned)
            canonical_text = json.dumps(cleaned, sort_keys=True)
            return Normalized(kind="json", flat=flat, text=canonical_text, raw_len=raw_len)
        except Exception:
            pass  # Fall through to HTML / text normalization

    # HTML / plain text normalization
    soup = BeautifulSoup(text, "html.parser")

    # Remove script and style elements
    for el in soup(["script", "style"]):
        el.decompose()

    # Remove comments
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()

    # Remove hidden anti-CSRF / token inputs
    for inp in soup.find_all("input", type="hidden"):
        name = inp.get("name") or ""
        if HIDDEN_CSRF_NAME_RE.match(name):
            inp.decompose()

    raw_text = soup.get_text()

    # Lowercase, remove timestamps, hex tokens, and collapse whitespace
    lowered = raw_text.lower()
    no_ts = ISO_TIMESTAMP_RE.sub(" ", lowered)
    no_hex = HEX_LONG_RE.sub(" ", no_ts)
    collapsed = re.sub(r"\s+", " ", no_hex).strip()

    return Normalized(kind="text", flat=None, text=collapsed, raw_len=raw_len)
