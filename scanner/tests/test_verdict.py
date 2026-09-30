"""Unit tests for response classification (verdict engine)."""

from aegis_scanner.models import RecordedRequest, ReplayResult
from aegis_scanner.replay.verdict import classify_response


def _make_orig(body="<h1>Order #1</h1>"):
    return RecordedRequest(
        account_label="alice",
        method="GET",
        url="http://example.com/orders/1",
        headers={},
        body=None,
        resource_type="document",
        status=200,
        response_headers={},
        response_body=body,
        content_type="text/html",
        signature="GET /orders/{id}",
    )


def test_verdict_explicit_denied():
    orig = _make_orig()
    for code in (401, 403, 404, 410):
        res = ReplayResult(status=code, headers={}, body="Forbidden")
        assert classify_response(res, orig) == "denied"


def test_verdict_redirect_denied():
    orig = _make_orig()
    res = ReplayResult(
        status=302, headers={"location": "/login?next=/orders/1"}, body=""
    )
    assert classify_response(res, orig) == "denied"


def test_verdict_soft_denial_body():
    orig = _make_orig()
    res = ReplayResult(
        status=200, headers={}, body="<p>Access Denied! You are not authorized.</p>"
    )
    assert classify_response(res, orig) == "denied"


def test_verdict_login_page_with_password():
    orig = _make_orig("<h1>Order details</h1>")
    # Replay returned a login form containing password input
    res = ReplayResult(
        status=200,
        headers={},
        body='<form action="/login"><input type="password" name="p" /></form>',
    )
    assert classify_response(res, orig) == "denied"


def test_verdict_allowed_real_data():
    orig = _make_orig("<h1>Order #1</h1><p>Items: Blue Mug</p>")
    res = ReplayResult(
        status=200, headers={}, body="<h1>Order #1</h1><p>Items: Blue Mug</p>"
    )
    assert classify_response(res, orig) == "allowed"


def test_verdict_error_statuses():
    orig = _make_orig()
    res_500 = ReplayResult(status=500, headers={}, body="Internal Server Error")
    assert classify_response(res_500, orig) == "error"

    res_net_err = ReplayResult(
        status=0, headers={}, body="", error="ConnectTimeout: Connection timed out"
    )
    assert classify_response(res_net_err, orig) == "error"
