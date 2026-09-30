#!/usr/bin/env python3
"""Benchmark script to measure Aegis Scanner precision, recall, and false-positive rates."""

import json
import socket
import sys
import threading
import time
from pathlib import Path
from werkzeug.serving import make_server

# Ensure project root is in sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aegis_scanner.models import AccountConfig, ScanConfig
from aegis_scanner.modules.access_control import run_access_control_scan
from labs.vulnerable_app.app import create_app


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    print("=" * 70)
    print(" Aegis-Web Access-Control Scanner Benchmark (Oracle Verification)")
    print("=" * 70)

    gt_path = REPO_ROOT / "labs" / "vulnerable_app" / "ground_truth.json"
    with open(gt_path, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    must_find = ground_truth["must_find"]
    must_not_flag = set(ground_truth["must_not_flag"])

    port = find_free_port()
    app = create_app()
    server = make_server("127.0.0.1", port, app)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"
    print(f"[*] Started vulnerable lab target at {base_url}")

    accounts = [
        AccountConfig(
            label="admin",
            privilege_level=100,
            login_url=f"{base_url}/login",
            username="admin",
            password="admin-pass",
            username_selector="input[name=username]",
            password_selector="input[name=password]",
            submit_selector="button[type=submit]",
            success_url_contains="/dashboard",
        ),
        AccountConfig(
            label="alice",
            privilege_level=10,
            login_url=f"{base_url}/login",
            username="alice",
            password="alice-pass",
            username_selector="input[name=username]",
            password_selector="input[name=password]",
            submit_selector="button[type=submit]",
            success_url_contains="/dashboard",
        ),
        AccountConfig(
            label="bob",
            privilege_level=10,
            login_url=f"{base_url}/login",
            username="bob",
            password="bob-pass",
            username_selector="input[name=username]",
            password_selector="input[name=password]",
            submit_selector="button[type=submit]",
            success_url_contains="/dashboard",
        ),
    ]

    config = ScanConfig(
        base_url=base_url,
        scope_hosts=["127.0.0.1", "localhost"],
        accounts=accounts,
        seed_paths=["/dashboard"],
        max_pages=20,
        max_depth=3,
        request_delay_ms=50,
        allow_private=True,
        modules=["access_control", "js_analysis", "misconfig"],
    )

    def report_progress(stage: str, percent: int, msg: str, level: str):
        print(f"[{percent:3d}%] [{stage.upper()}] {msg}")

    print("\n[*] Commencing full-spectrum scan (Stage 1 + Stage 2)...")
    start_time = time.time()
    try:
        scan_result = run_access_control_scan(
            config=config,
            report=report_progress,
            should_cancel=lambda: False,
        )
    finally:
        server.shutdown()

    elapsed = time.time() - start_time
    print(f"\n[*] Scan completed in {elapsed:.2f} seconds.")
    print(f"    Total requests recorded: {scan_result.stats.get('requests_recorded', 0)}")
    print(f"    Total replays executed:  {scan_result.stats.get('replays_sent', 0)}")
    print(f"    Discarded low-conf:      {scan_result.stats.get('discarded_low_confidence', 0)}")
    print(f"    Total findings produced: {len(scan_result.findings)}\n")

    # Evaluate Stage 1 against ground truth
    tp_count = 0
    fn_count = 0
    print("-" * 70)
    print(" STAGE 1: ACCESS-CONTROL GROUND TRUTH VERIFICATION (MUST FIND)")
    print("-" * 70)

    for item in must_find:
        expected_type = item["type"]
        expected_sig = item["signature"]

        matches = [
            f for f in scan_result.findings
            if f.type == expected_type and f.signature == expected_sig
        ]

        if matches:
            tp_count += 1
            best_match = max(matches, key=lambda m: m.confidence)
            print(f" [✔] FOUND: {expected_type:<23} {expected_sig:<25} (Conf: {best_match.confidence}%, {best_match.severity})")
        else:
            fn_count += 1
            print(f" [✘] MISSED: {expected_type:<23} {expected_sig:<25}")

    # Check for False Positives
    false_positives = [
        f for f in scan_result.findings
        if f.signature in must_not_flag
    ]
    fp_count = len(false_positives)

    print("\n" + "-" * 70)
    print(" FALSE POSITIVE AUDIT (MUST NOT FLAG)")
    print("-" * 70)
    if fp_count == 0:
        print(" [✔] Zero false positives detected on safe routes.")
    else:
        for fp in false_positives:
            print(f" [✘] FALSE POSITIVE: {fp.type:<22} {fp.signature:<25} (URL: {fp.url})")

    # Evaluate Stage 2 separately
    stage2_must_find = ground_truth.get("stage2_must_find", [])
    s2_tp = 0
    s2_fn = 0
    if stage2_must_find:
        print("\n" + "-" * 70)
        print(" STAGE 2: EXTENDED MISCONFIG & JS ANALYSIS VERIFICATION")
        print("-" * 70)
        for item in stage2_must_find:
            exp_type = item.get("type")
            exp_sig = item.get("signature")
            exp_title = item.get("title")

            matches = [
                f for f in scan_result.findings
                if (exp_type is None or f.type == exp_type)
                and (exp_sig is None or f.signature == exp_sig)
                and (exp_title is None or f.title == exp_title)
            ]

            label = exp_sig or exp_title or exp_type
            if matches:
                s2_tp += 1
                best_match = max(matches, key=lambda m: m.confidence)
                print(f" [✔] FOUND: {exp_type:<23} {label:<25} (Conf: {best_match.confidence}%, {best_match.severity})")
            else:
                s2_fn += 1
                print(f" [✘] MISSED: {exp_type:<23} {label:<25}")

    # Metrics
    precision = (tp_count / (tp_count + fp_count)) if (tp_count + fp_count) > 0 else 0.0
    recall = (tp_count / (tp_count + fn_count)) if (tp_count + fn_count) > 0 else 0.0

    print("\n" + "=" * 70)
    print(f" BENCHMARK SUMMARY:")
    print(f"   Stage 1 Core: Found {tp_count} of {len(must_find)} | False Positives: {fp_count}")
    print(f"   Stage 1 Metrics: Precision: {precision:.1%} | Recall: {recall:.1%}")
    if stage2_must_find:
        print(f"   Stage 2 Bonus: Found {s2_tp} of {len(stage2_must_find)} planted issues")
    print("=" * 70 + "\n")

    if fn_count > 0 or fp_count > 0 or s2_fn > 0:
        print("[!] Benchmark FAILED: Missed flaws or false positives encountered.")
        sys.exit(1)

    print("[*] Benchmark PASSED: All Stage 1 and Stage 2 issues detected with 0 false positives.")
    sys.exit(0)


if __name__ == "__main__":
    main()
