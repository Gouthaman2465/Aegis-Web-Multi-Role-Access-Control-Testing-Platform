"""Unit tests for response similarity scoring."""

from aegis_scanner.diff.compare import similarity
from aegis_scanner.diff.normalize import normalize_body, Normalized


def test_compare_identical():
    body = '{"name": "Alice", "role": "admin", "id": 1}'
    n1 = normalize_body(body, content_type="application/json")
    n2 = normalize_body(body, content_type="application/json")
    assert similarity(n1, n2) == 1.0


def test_compare_disjoint():
    n1 = normalize_body('{"a": "1", "b": "2"}', content_type="application/json")
    n2 = normalize_body('{"c": "3", "d": "4"}', content_type="application/json")
    assert similarity(n1, n2) == 0.0


def test_compare_one_changed_value_large_json():
    large1 = {f"key_{i}": f"val_{i}" for i in range(20)}
    large2 = dict(large1)
    large2["key_0"] = "different_val"

    n1 = normalize_body(str(large1).replace("'", '"'), content_type="application/json")
    n2 = normalize_body(str(large2).replace("'", '"'), content_type="application/json")

    sim = similarity(n1, n2)
    assert 0.8 < sim < 1.0


def test_compare_mixed_kinds():
    n_json = normalize_body('{"msg": "hello"}', content_type="application/json")
    n_text = normalize_body("<p>hello</p>", content_type="text/html")
    assert similarity(n_json, n_text) == 0.0


def test_compare_short_texts():
    # Fewer than 3 words: exact match gives 1.0, difference gives 0.0
    n1 = Normalized(kind="text", flat=None, text="hello world", raw_len=11)
    n2 = Normalized(kind="text", flat=None, text="hello world", raw_len=11)
    n3 = Normalized(kind="text", flat=None, text="goodbye world", raw_len=13)

    assert similarity(n1, n2) == 1.0
    assert similarity(n1, n3) == 0.0
