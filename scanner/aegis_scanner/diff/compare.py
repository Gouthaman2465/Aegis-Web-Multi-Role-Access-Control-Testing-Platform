"""Response comparison and similarity scoring using Jaccard similarity."""

from aegis_scanner.diff.normalize import Normalized


def similarity(a: Normalized, b: Normalized) -> float:
    """Compute similarity between two normalized responses in range [0.0, 1.0].

    - Mixed kinds (JSON vs text) -> 0.0
    - Both JSON -> Jaccard similarity of flattened (path, value) pairs (both empty -> 1.0)
    - Text -> Jaccard similarity of 3-word shingles (if < 3 words, 1.0 if equal else 0.0)
    """
    if a.kind != b.kind:
        return 0.0

    if a.kind == "json":
        items_a = set(a.flat.items()) if a.flat is not None else set()
        items_b = set(b.flat.items()) if b.flat is not None else set()

        if not items_a and not items_b:
            return 1.0
        union = items_a | items_b
        if not union:
            return 1.0
        intersection = items_a & items_b
        return len(intersection) / len(union)

    # Text / HTML comparison
    words_a = a.text.split()
    words_b = b.text.split()

    if len(words_a) < 3 or len(words_b) < 3:
        return 1.0 if a.text == b.text else 0.0

    shingles_a = {" ".join(words_a[i : i + 3]) for i in range(len(words_a) - 2)}
    shingles_b = {" ".join(words_b[i : i + 3]) for i in range(len(words_b) - 2)}

    if not shingles_a and not shingles_b:
        return 1.0
    union = shingles_a | shingles_b
    if not union:
        return 1.0
    intersection = shingles_a & shingles_b
    return len(intersection) / len(union)
