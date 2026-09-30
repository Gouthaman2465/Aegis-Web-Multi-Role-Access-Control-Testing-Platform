"""Unit tests for URL signature generation."""

from aegis_scanner.signature import make_signature


def test_signature_numeric_id():
    assert make_signature("GET", "http://example.com/orders/1") == "GET /orders/{id}"
    assert make_signature("GET", "/orders/12345") == "GET /orders/{id}"


def test_signature_query_params():
    url = "http://example.com/api/products?limit=5&page=2"
    assert make_signature("GET", url) == "GET /api/products?limit&page"

    # Sorting of query params
    url_reversed = "http://example.com/api/products?page=2&limit=5"
    assert make_signature("GET", url_reversed) == "GET /api/products?limit&page"


def test_signature_uuid():
    uuid_str = "3f2b8c1e-7b3a-4e2a-9f1c-1a2b3c4d5e6f"
    url = f"http://example.com/items/{uuid_str}"
    assert make_signature("GET", url) == "GET /items/{id}"


def test_signature_hex_id():
    hex_str = "0123456789abcdef0123"
    url = f"http://example.com/users/{hex_str}/profile"
    assert make_signature("GET", url) == "GET /users/{id}/profile"


def test_signature_spa_hash_routes():
    assert make_signature("GET", "http://example.com/#/basket") == "GET /#/basket"
    assert make_signature("GET", "http://example.com/#/orders/42") == "GET /#/orders/{id}"
