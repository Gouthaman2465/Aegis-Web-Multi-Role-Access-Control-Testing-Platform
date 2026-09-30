"""URL signature extraction to group dynamic URLs into templated endpoints."""

import re
from urllib.parse import urlparse, parse_qsl

UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_REGEX = re.compile(r"^[0-9a-fA-F]{16,}$")


def _is_id_segment(segment: str) -> bool:
    """Return True if path segment looks like an object identifier (int, UUID, or long hex)."""
    if segment.isdigit():
        return True
    if UUID_REGEX.match(segment):
        return True
    if HEX_REGEX.match(segment):
        return True
    return False


def make_signature(method: str, url: str) -> str:
    """Normalize a request method and URL into a canonical signature template.

    Example:
        GET /orders/1 -> GET /orders/{id}
        GET /api/products?limit=5&page=2 -> GET /api/products?limit&page
    """
    parsed = urlparse(url)
    path = parsed.path or "/"

    # Support hash-routed Single Page Applications (e.g. /#/basket)
    if parsed.fragment and parsed.fragment.startswith("/"):
        base_path = path.rstrip("/")
        path = f"{base_path}#{parsed.fragment}"

    # Replace dynamic ID segments
    segments = path.split("/")
    norm_segments = []
    for seg in segments:
        if _is_id_segment(seg):
            norm_segments.append("{id}")
        else:
            norm_segments.append(seg)
    norm_path = "/".join(norm_segments)
    if not norm_path.startswith("/"):
        norm_path = "/" + norm_path

    # Extract, deduplicate, and sort query parameter names without values
    query_params = sorted(list({k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
    query_str = f"?{'&'.join(query_params)}" if query_params else ""

    norm_method = method.strip().upper()
    return f"{norm_method} {norm_path}{query_str}"
