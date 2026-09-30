"""SSRF protection and outbound network guard for Aegis-Web."""

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import httpx

# Specific cloud metadata addresses that are ALWAYS blocked
ALWAYS_BLOCKED_EXACT_IPS = {
    "169.254.169.254",   # AWS/Azure/GCP metadata
    "169.254.170.2",     # AWS ECS container metadata
    "fd00:ec2::254",     # AWS IMDSv6
    "100.100.100.200",   # Alibaba cloud metadata
}

# Subnets that are ALWAYS blocked (even when allow_private=True)
ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),     # IPv4 Link-local
    ipaddress.ip_network("fe80::/10"),          # IPv6 Link-local
    ipaddress.ip_network("224.0.0.0/4"),        # IPv4 Multicast
    ipaddress.ip_network("ff00::/8"),           # IPv6 Multicast
    ipaddress.ip_network("0.0.0.0/8"),          # Unspecified / "this" network
    ipaddress.ip_network("::/128"),             # IPv6 Unspecified
    ipaddress.ip_network("240.0.0.0/4"),        # IPv4 Reserved
    ipaddress.ip_network("100.64.0.0/10"),      # IPv4 CGNAT
]

# Subnets blocked unless allow_private=True
PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),        # IPv4 Loopback
    ipaddress.ip_network("::1/128"),            # IPv6 Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),      # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),     # RFC1918
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA (Unique Local)
]


class BlockedTargetError(ValueError):
    """Raised when an outbound URL points to a forbidden or unresolvable destination."""
    pass


@dataclass
class SafeResponse:
    """Minimal HTTP response returned by safe_get."""
    status_code: int
    headers: dict[str, str]
    text: str
    content: bytes


def _parse_raw_ip(ip_str: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Try to parse an IP address string, normalizing IPv4-mapped IPv6."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            return addr.ipv4_mapped
        return addr
    except ValueError:
        return None


def is_blocked_ip(ip: str, allow_private: bool = False) -> bool:
    """Return True if an IP is prohibited by SSRF rules."""
    ip_str = ip.strip()

    # Check exact metadata addresses
    if ip_str in ALWAYS_BLOCKED_EXACT_IPS:
        return True

    addr = _parse_raw_ip(ip_str)
    if addr is None:
        # Check POSIX legacy numeric formats (octal, hex, dword)
        try:
            packed = socket.inet_aton(ip_str)
            addr = ipaddress.IPv4Address(packed)
        except (socket.error, OSError):
            return True  # If unparseable as IP, treat as blocked

    # Check if exact IP after normalization matches metadata
    if str(addr) in ALWAYS_BLOCKED_EXACT_IPS:
        return True

    # Always-blocked subnets
    for net in ALWAYS_BLOCKED_NETWORKS:
        if addr in net:
            return True

    # Standard python address checks
    if addr.is_multicast or addr.is_unspecified or addr.is_link_local:
        return True

    # Blocked unless private is explicitly allowed
    if not allow_private:
        for net in PRIVATE_NETWORKS:
            if addr in net:
                return True
        if addr.is_loopback or addr.is_private or addr.is_reserved:
            return True

    return False


def _resolve_host(host: str) -> list[str]:
    """Resolve a hostname or IP string to all associated IP address strings."""
    # Check if host is already directly an IP or numeric IP
    direct_ip = _parse_raw_ip(host)
    if direct_ip is not None:
        return [str(direct_ip)]

    try:
        packed = socket.inet_aton(host)
        return [str(ipaddress.IPv4Address(packed))]
    except (socket.error, OSError):
        pass

    try:
        results = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ips = []
        for res in results:
            sockaddr = res[4]
            ip = sockaddr[0]
            ips.append(ip)
        unique_ips = list(dict.fromkeys(ips))
        if not unique_ips:
            raise BlockedTargetError(f"Host '{host}' could not be resolved.")
        return unique_ips
    except socket.gaierror as e:
        raise BlockedTargetError(f"Failed to resolve host '{host}': {e}") from e


def validate_url(url: str, allow_private: bool = False, syntax_only: bool = False) -> list[str]:
    """Validate a URL against SSRF rules and return all resolved IPs.

    Raises BlockedTargetError if scheme, userinfo, port, host, or any resolved IP is prohibited.
    If syntax_only is True, hostname resolution is skipped (only direct IP strings are checked).
    """
    if not url or not isinstance(url, str):
        raise BlockedTargetError("URL must be a non-empty string.")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise BlockedTargetError(f"Invalid URL structure: {e}") from e

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise BlockedTargetError(f"Unsupported scheme '{scheme}'. Only http and https are allowed.")

    if parsed.username or parsed.password:
        raise BlockedTargetError("Userinfo (user:pass@) is not permitted in target URLs.")

    hostname = parsed.hostname
    if not hostname:
        raise BlockedTargetError("Target URL host cannot be empty.")

    # Check port
    try:
        port = parsed.port
    except ValueError:
        raise BlockedTargetError("Invalid port in target URL.")

    if port is not None and port == 0:
        raise BlockedTargetError("Port 0 is prohibited.")

    if syntax_only:
        direct_ip = _parse_raw_ip(hostname)
        if direct_ip is not None:
            if is_blocked_ip(str(direct_ip), allow_private=allow_private):
                raise BlockedTargetError(
                    f"Target host '{hostname}' is prohibited IP '{direct_ip}' (allow_private={allow_private})."
                )
            return [str(direct_ip)]
        return []

    resolved_ips = _resolve_host(hostname)

    for ip in resolved_ips:
        if is_blocked_ip(ip, allow_private=allow_private):
            raise BlockedTargetError(
                f"Target host '{hostname}' resolved to prohibited IP '{ip}' (allow_private={allow_private})."
            )

    return resolved_ips


def host_in_scope(host: str, scope_hosts: list[str]) -> bool:
    """Check if host matches the target scope.

    Exact host match is required unless scope item starts with '*.' (subdomain wildcard).
    """
    if not host or not scope_hosts:
        return False

    clean_host = host.split(":")[0].strip().lower()

    for pattern in scope_hosts:
        pat = pattern.split(":")[0].strip().lower()
        if pat.startswith("*."):
            base_domain = pat[2:]
            if clean_host == base_domain or clean_host.endswith("." + base_domain):
                return True
        else:
            if clean_host == pat:
                return True
    return False


def safe_get(
    url: str,
    *,
    allow_private: bool = False,
    max_bytes: int = 65536,
    max_redirects: int = 3,
) -> SafeResponse:
    """Safely fetch a URL with IP pinning, re-validated redirects, size capping, and SSRF checks."""
    current_url = url
    redirects_remaining = max_redirects

    while True:
        resolved_ips = validate_url(current_url, allow_private=allow_private)
        target_ip = resolved_ips[0]

        parsed = urlparse(current_url)
        scheme = parsed.scheme.lower()
        original_host = parsed.hostname
        port = parsed.port or (443 if scheme == "https" else 80)

        # Construct connection URL pinned to resolved IP
        ip_formatted = f"[{target_ip}]" if ":" in target_ip else target_ip
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query = f"{path_and_query}?{parsed.query}"

        pinned_url = f"{scheme}://{ip_formatted}:{port}{path_and_query}"

        headers = {
            "Host": f"{original_host}:{port}" if parsed.port else original_host,
            "User-Agent": "Aegis-Web-Guard/1.0",
            "Accept": "*/*",
        }

        extensions = {}
        if scheme == "https":
            extensions["sni_hostname"] = original_host

        try:
            with httpx.Client(
                follow_redirects=False,
                timeout=httpx.Timeout(10.0, connect=5.0),
                verify=False if allow_private else True,
            ) as client:
                with client.stream(
                    "GET",
                    pinned_url,
                    headers=headers,
                    extensions=extensions,
                ) as response:
                    body = bytearray()
                    for chunk in response.iter_bytes():
                        body.extend(chunk)
                        if len(body) >= max_bytes:
                            body = body[:max_bytes]
                            break

                    resp_status = response.status_code
                    resp_headers = dict(response.headers)
                    resp_bytes = bytes(body)

        except Exception as e:
            raise BlockedTargetError(f"Network error requesting '{current_url}': {e}") from e

        # Handle redirects manually
        if resp_status in (301, 302, 303, 307, 308) and "location" in resp_headers:
            if redirects_remaining <= 0:
                raise BlockedTargetError(f"Too many redirects (max {max_redirects}).")
            redirects_remaining -= 1
            next_url = urljoin(current_url, resp_headers["location"])
            current_url = next_url
            continue

        return SafeResponse(
            status_code=resp_status,
            headers=resp_headers,
            text=resp_bytes.decode("utf-8", errors="replace"),
            content=resp_bytes,
        )
