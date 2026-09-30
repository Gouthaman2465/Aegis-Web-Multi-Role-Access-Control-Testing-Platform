"""Bounded browser crawler and network request recorder using Playwright."""

from collections import deque
import re
import time
from urllib.parse import urlparse, urljoin
from typing import Callable, Sequence

from playwright.sync_api import Browser, Route, Request as PwRequest, Response as PwResponse

from aegis_scanner.models import AccountConfig, RecordedRequest, ScanConfig
from aegis_scanner.net_guard import host_in_scope, validate_url
from aegis_scanner.recorder.auth_state import build_auth_state, AuthState
from aegis_scanner.recorder.login import login
from aegis_scanner.signature import make_signature

ABORT_RESOURCE_TYPES = {"image", "media", "font"}
LOGOUT_DELETE_RE = re.compile(r"(logout|signout|log-out|delete|remove|destroy)", re.IGNORECASE)
STATIC_EXT_RE = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|css|js|map|woff2?|ttf|eot|mp4|webm|pdf)(\?.*)?$",
    re.IGNORECASE,
)


def record_account(
    browser: Browser,
    account: AccountConfig,
    config: ScanConfig,
    report: Callable[[str, int, str, str], None],
    should_cancel: Callable[[], bool],
) -> tuple[list[RecordedRequest], AuthState]:
    """Log in as account and crawl target within scope, capturing traffic."""
    context = browser.new_context(accept_downloads=False)

    # Hardening route handler: block images/media, out-of-scope, SSRF targets, and logout URLs
    def handle_route(route: Route):
        pw_req = route.request
        res_type = pw_req.resource_type
        if res_type in ABORT_RESOURCE_TYPES:
            route.abort()
            return

        req_url = pw_req.url
        if LOGOUT_DELETE_RE.search(req_url):
            route.abort()
            return

        try:
            parsed = urlparse(req_url)
            host = parsed.hostname or ""
            if not host_in_scope(host, config.scope_hosts):
                route.abort()
                return

            validate_url(req_url, allow_private=config.allow_private)
        except Exception:
            route.abort()
            return

        route.continue_()

    context.route("**/*", handle_route)

    recorded: list[RecordedRequest] = []
    seen_keys: set[tuple[str, str]] = set()  # (method, url)
    sig_url_counts: dict[str, set[str]] = {}

    def on_response(response: PwResponse):
        try:
            req = response.request
            res_type = req.resource_type

            # Stage 1 captures document, xhr, fetch. Stage 2 adds scripts if enabled.
            allowed_types = {"document", "xhr", "fetch"}
            if "js_analysis" in config.modules:
                allowed_types.add("script")

            if res_type not in allowed_types:
                return

            method = req.method.upper()
            url = response.url
            if LOGOUT_DELETE_RE.search(url):
                return

            pair_key = (method, url)
            if pair_key in seen_keys:
                return

            sig = make_signature(method, url)
            if sig not in sig_url_counts:
                sig_url_counts[sig] = set()

            if url not in sig_url_counts[sig]:
                if len(sig_url_counts[sig]) >= 5:
                    return
                sig_url_counts[sig].add(url)

            # Extract body if text or JSON
            body_text = None
            max_bytes = 2097152 if res_type == "script" else 204800  # 2MB for script, 200KB for text
            try:
                body_bytes = response.body()
                if body_bytes:
                    trimmed = body_bytes[:max_bytes]
                    body_text = trimmed.decode("utf-8", errors="replace")
            except Exception:
                body_text = None

            content_type = response.headers.get("content-type", "")

            recorded_req = RecordedRequest(
                account_label=account.label,
                method=method,
                url=url,
                headers=dict(req.headers),
                body=req.post_data,
                resource_type=res_type,
                status=response.status,
                response_headers=dict(response.headers),
                response_body=body_text,
                content_type=content_type,
                signature=sig,
            )
            seen_keys.add(pair_key)
            recorded.append(recorded_req)
        except Exception:
            pass

    page = context.new_page()
    page.set_default_navigation_timeout(20000)
    page.on("response", on_response)

    # 1. Authenticate account
    report("recording", 5, f"Logging in as '{account.label}'...", "info")
    login(page, account, config)

    # 2. Seed URLs for BFS crawler
    start_urls: list[str] = []
    base_clean = config.base_url.rstrip("/")
    start_urls.append(base_clean)
    for seed in config.seed_paths:
        seed_clean = seed if seed.startswith("/") else f"/{seed}"
        start_urls.append(urljoin(base_clean, seed_clean))

    queue: deque[tuple[str, int]] = deque((u, 0) for u in dict.fromkeys(start_urls))
    visited: set[str] = set()

    # 3. BFS crawl loop
    while queue and len(visited) < config.max_pages:
        if should_cancel():
            break

        url, depth = queue.popleft()
        if url in visited or depth > config.max_depth:
            continue

        visited.add(url)
        report(
            "recording",
            min(40, 5 + int((len(visited) / max(1, config.max_pages)) * 35)),
            f"Account '{account.label}': visiting page {len(visited)}/{config.max_pages} ({url})",
            "info",
        )

        try:
            page.goto(url, timeout=20000, wait_until="networkidle")
        except Exception:
            try:
                page.goto(url, timeout=10000, wait_until="load")
            except Exception:
                continue

        if config.request_delay_ms > 0:
            time.sleep(config.request_delay_ms / 1000.0)

        # Discover same-origin links
        try:
            links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            for link in links:
                if not link or not isinstance(link, str):
                    continue
                parsed = urlparse(link)
                host = parsed.hostname or ""
                if not host_in_scope(host, config.scope_hosts):
                    continue
                if STATIC_EXT_RE.search(parsed.path):
                    continue
                if LOGOUT_DELETE_RE.search(link):
                    continue
                if link not in visited:
                    queue.append((link, depth + 1))
        except Exception:
            pass

    # Extract cookies and build AuthState
    auth_state = build_auth_state(context.cookies(), recorded)
    context.close()
    return recorded, auth_state
