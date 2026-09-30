"""Unit tests for SSRF protection and network guard."""

import socket
import pytest
from aegis_scanner.net_guard import (
    validate_url,
    is_blocked_ip,
    host_in_scope,
    BlockedTargetError,
)

BLOCKED_URLS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://2130706433",
    "http://0x7f.0.0.1",
    "http://0177.0.0.1",
    "http://10.0.0.5",
    "http://172.16.0.1",
    "http://192.168.1.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::ffff:127.0.0.1]",
    "http://0.0.0.0",
    "http://user:pass@example.com",
    "ftp://example.com",
    "file:///etc/passwd",
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_blocked_urls(url):
    with pytest.raises(BlockedTargetError):
        validate_url(url, allow_private=False)


def test_public_allowed(monkeypatch):
    def mock_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    ips = validate_url("http://example.com/test", allow_private=False)
    assert "93.184.216.34" in ips


def test_allow_private_mode():
    # Loopback and RFC1918 allowed when allow_private=True
    assert validate_url("http://127.0.0.1:8080/test", allow_private=True) == ["127.0.0.1"]
    assert validate_url("http://10.0.0.5/test", allow_private=True) == ["10.0.0.5"]

    # Cloud metadata is STILL blocked even when allow_private=True
    with pytest.raises(BlockedTargetError):
        validate_url("http://169.254.169.254/latest/meta-data/", allow_private=True)

    with pytest.raises(BlockedTargetError):
        validate_url("http://169.254.170.2/v2/metadata", allow_private=True)

    with pytest.raises(BlockedTargetError):
        validate_url("http://100.100.100.200/latest/meta-data/", allow_private=True)


def test_mixed_ip_resolution_blocked(monkeypatch):
    def mock_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    with pytest.raises(BlockedTargetError):
        validate_url("http://evil-dual-homed.example.com", allow_private=False)


def test_host_in_scope():
    scope = ["example.com", "*.target.test", "api.sub.org"]

    # Exact matches
    assert host_in_scope("example.com", scope) is True
    assert host_in_scope("api.sub.org", scope) is True
    assert host_in_scope("other.com", scope) is False

    # Subdomain not allowed on exact match
    assert host_in_scope("sub.example.com", scope) is False

    # Wildcard subdomain matches
    assert host_in_scope("target.test", scope) is True
    assert host_in_scope("app.target.test", scope) is True
    assert host_in_scope("deep.app.target.test", scope) is True
    assert host_in_scope("fake-target.test", scope) is False
