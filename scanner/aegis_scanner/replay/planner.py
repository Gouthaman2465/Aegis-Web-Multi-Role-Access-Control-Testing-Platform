"""Replay task planner that constructs peer, lower-role, and anonymous test jobs."""

import re
from dataclasses import dataclass
from typing import Sequence, Union

from aegis_scanner.diff.compare import similarity
from aegis_scanner.diff.normalize import normalize_body, Normalized
from aegis_scanner.models import AccountConfig, RecordedRequest, ScanConfig

SAFE_METHODS = {"GET"}

STATIC_EXT_RE = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|css|js|map|woff2?|ttf|eot|mp4|webm|pdf)(\?.*)?$",
    re.IGNORECASE,
)

LOGOUT_DELETE_RE = re.compile(
    r"(logout|signout|log-out|delete|remove|destroy)", re.IGNORECASE
)

PASSWORD_INPUT_RE = re.compile(r'<input[^>]*type=["\']password["\']', re.IGNORECASE)


@dataclass
class ReplayTask:
    """A planned test request to execute against a target role or anonymously."""
    request: RecordedRequest
    source: str
    tested: str | None  # None indicates anonymous replay


def build_replay_plan(
    recorded_by_account: Union[dict[str, list[RecordedRequest]], Sequence[RecordedRequest]],
    accounts: list[AccountConfig],
    config: ScanConfig,
    app_shell_fingerprint: Normalized | None = None,
) -> list[ReplayTask]:
    """Build an ordered list of replay tasks based on privilege levels and safety rules."""
    account_map = {acc.label: acc for acc in accounts}

    # Normalize recorded requests into a flat list
    all_requests: list[RecordedRequest] = []
    if isinstance(recorded_by_account, dict):
        for req_list in recorded_by_account.values():
            all_requests.extend(req_list)
    else:
        all_requests.extend(recorded_by_account)

    candidate_tasks: list[ReplayTask] = []
    # Track signature count per source role to cap at 5 distinct URLs per signature
    sig_counts: dict[tuple[str, str], int] = {}
    seen_urls_per_sig: dict[tuple[str, str], set[str]] = {}

    for req in all_requests:
        source_label = req.account_label
        if source_label not in account_map:
            continue
        source_acc = account_map[source_label]

        # 1. Method filter: GET only in Stage 1
        if req.method.upper() not in SAFE_METHODS:
            continue

        # 2. Status filter: Original must be 2xx
        if not (200 <= req.status < 300):
            continue

        # 3. Resource type filter: Exclude scripts
        if req.resource_type == "script":
            continue

        # 4. Body length filter: Must be at least 20 bytes
        body = req.response_body or ""
        if len(body.strip()) < 20:
            continue

        # 5. Public login page filter: Never replay original login forms
        if PASSWORD_INPUT_RE.search(body):
            continue

        # 6. Static asset filter
        if STATIC_EXT_RE.search(req.url):
            continue

        # 7. Dangerous / session-terminating URL filter
        if LOGOUT_DELETE_RE.search(req.url):
            continue

        # 8. SPA App Shell filter: Skip document bodies identical to base_url app shell
        if req.resource_type == "document" and app_shell_fingerprint is not None:
            norm_doc = normalize_body(body, req.content_type)
            if similarity(norm_doc, app_shell_fingerprint) >= 0.95:
                continue

        # 9. Cap per signature (at most 5 distinct URLs per signature per account)
        sig_key = (source_label, req.signature)
        if sig_key not in seen_urls_per_sig:
            seen_urls_per_sig[sig_key] = set()

        if req.url not in seen_urls_per_sig[sig_key]:
            if len(seen_urls_per_sig[sig_key]) >= 5:
                continue
            seen_urls_per_sig[sig_key].add(req.url)

        # 10. Generate tasks for peers and lower-privileged accounts
        for other_acc in accounts:
            if other_acc.label == source_label:
                continue
            if other_acc.privilege_level <= source_acc.privilege_level:
                candidate_tasks.append(
                    ReplayTask(request=req, source=source_label, tested=other_acc.label)
                )

        # 11. Anonymous replay task
        candidate_tasks.append(
            ReplayTask(request=req, source=source_label, tested=None)
        )

    # Order tasks by descending source privilege so highest-value checks run first
    candidate_tasks.sort(
        key=lambda t: account_map[t.source].privilege_level if t.source in account_map else 0,
        reverse=True,
    )

    # Cap total tasks at max_replays
    return candidate_tasks[: config.max_replays]
