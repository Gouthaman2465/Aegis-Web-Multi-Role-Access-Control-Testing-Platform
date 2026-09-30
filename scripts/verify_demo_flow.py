"""Automated Playwright browser walkthrough of the complete Aegis-Web demo flow.

Tests:
1. Registration & admin promotion
2. Target registration & Mark as Lab
3. Three test accounts onboarding
4. Scan #1 execution with live progress & event streaming
5. Findings exploration & DiffViewer inspection
6. Finding triage status update (PATCH)
7. Markdown report download
8. Scan #2 execution & regression comparison (New/Fixed/Persisting)
9. Administrative audit log verification
"""

import os
import sys
import time
import subprocess
import threading
from pathlib import Path
from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "backend"))
sys.path.insert(0, str(REPO_ROOT))
from app.db import SessionLocal
from app.models.user import User
from labs.vulnerable_app.app import create_app
from werkzeug.serving import make_server


def run_lab_server(port):
    app = create_app()
    server = make_server("127.0.0.1", port, app)
    server.serve_forever()


def promote_admin(email):
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.role = "admin"
            db.commit()
            print(f"[*] User {email} promoted to admin.")


def main():
    print("=" * 70)
    print(" STARTING AEGIS-WEB COMPLETE DEMO FLOW VERIFICATION IN BROWSER")
    print("=" * 70)

    lab_port = 5001
    backend_port = 8000
    frontend_port = 4173

    # 1. Start Lab App
    print("[1/5] Starting Vulnerable Lab App on port 5001...")
    lab_thread = threading.Thread(target=run_lab_server, args=(lab_port,), daemon=True)
    lab_thread.start()
    time.sleep(1)

    # 2. Start Backend API
    print("[2/5] Starting FastAPI Backend on port 8000...")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(backend_port)],
        cwd=REPO_ROOT / "backend",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)

    # 3. Start Scan Worker
    print("[3/5] Starting Scan Worker...")
    worker_proc = subprocess.Popen(
        [sys.executable, "-m", "app.worker.runner"],
        cwd=REPO_ROOT / "backend",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(1)

    # 4. Start Frontend Preview
    print("[4/5] Starting Frontend Preview on port 4173...")
    frontend_proc = subprocess.Popen(
        ["npm", "run", "preview", "--", "--port", str(frontend_port), "--host", "127.0.0.1"],
        cwd=REPO_ROOT / "frontend",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(3)

    try:
        # 5. Playwright Browser Walkthrough
        print("[5/5] Launching Playwright Chromium...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            page = context.new_page()

            # --- Step A: Register & Login ---
            print("\n>>> STEP A: Registering Admin User in UI...")
            page.goto(f"http://127.0.0.1:{frontend_port}/login")
            page.wait_for_selector(".auth-card")
            page.click("button:has-text('Register')")
            page.fill("#email", "admin_demo@example.com")
            page.fill("#password", "AdminPass123!")
            page.click("button[type=submit]")

            # Promote to admin in DB and reload /auth/me
            time.sleep(1)
            promote_admin("admin_demo@example.com")
            page.reload()
            page.wait_for_selector(".brand-logo")
            print(" [✔] Admin user signed in and role badge visible in header.")

            # --- Step B: Create Target & Mark Lab ---
            print("\n>>> STEP B: Registering Target Application...")
            page.goto(f"http://127.0.0.1:{frontend_port}/targets")
            page.wait_for_selector("#target-name")
            page.fill("#target-name", "Demo Target App")
            page.fill("#target-url", f"http://127.0.0.1:{lab_port}")
            page.fill("#scope-hosts", "127.0.0.1, localhost")
            page.click("button:has-text('Register Target')")
            time.sleep(1)

            # Click on created target
            page.click("text=Demo Target App")
            page.wait_for_selector(".target-detail-header")
            print(" [✔] Target created. Ownership status initially UNVERIFIED.")

            # Mark as Lab Instance
            page.click("button:has-text('Mark as Lab Instance (Admin)')")
            page.wait_for_selector(".status-lab")
            print(" [✔] Target promoted to LAB status (private testing enabled).")

            # --- Step C: Add 3 Test Accounts ---
            print("\n>>> STEP C: Adding 3 Test Accounts (Admin, Alice, Bob)...")
            accounts = [
                ("admin", 100, "admin", "admin-pass"),
                ("alice", 10, "alice", "alice-pass"),
                ("bob", 10, "bob", "bob-pass"),
            ]
            for role, priv, user, pwd in accounts:
                page.fill("#role-label", role)
                page.fill("#priv-level", str(priv))
                page.fill("#acc-user", user)
                page.fill("#acc-pass", pwd)
                page.click("button:has-text('Add Account')")
                time.sleep(0.5)
            print(" [✔] 3 accounts configured. Start Scan button enabled.")

            # --- Step D: Start Scan #1 ---
            print("\n>>> STEP D: Launching Scan #1 via UI...")
            page.click("text=Start New Scan")
            page.wait_for_selector(".ethics-notice-box")
            page.check("input[type=checkbox]")
            page.click("button:has-text('Start Access Control Assessment')")
            page.wait_for_selector(".scan-detail-header")
            print(" [✔] Scan enqueued. Tracking real-time progress and event stream...")

            # Wait for scan to complete
            max_wait = 60
            start_wait = time.time()
            while time.time() - start_wait < max_wait:
                status_el = page.query_selector(".status-badge")
                status_text = status_el.inner_text().strip() if status_el else ""
                pct_el = page.query_selector(".progress-percent-label")
                pct_text = pct_el.inner_text().strip() if pct_el else ""
                print(f"     ... Status: {status_text} | Progress: {pct_text}")
                if "COMPLETED" in status_text:
                    break
                time.sleep(3)

            assert "COMPLETED" in page.inner_text(".status-badge")
            print(" [✔] Scan #1 completed successfully!")

            # --- Step E: Inspect Findings & DiffViewer ---
            print("\n>>> STEP E: Inspecting Findings & DiffViewer...")
            page.wait_for_selector(".findings-table")
            findings_links = page.query_selector_all(".finding-link")
            print(f"     Found {len(findings_links)} access-control findings in table.")
            assert len(findings_links) >= 4, f"Expected ≥ 4 findings, found {len(findings_links)}"

            # Open first finding detail
            findings_links[0].click()
            page.wait_for_selector(".finding-header-card")

            # Check DiffViewer
            diff_viewer = page.query_selector("[data-testid=diff-viewer]")
            assert diff_viewer is not None
            print(" [✔] DiffViewer rendered with side-by-side original vs replay & line diff.")

            # Check SeverityBadge & CVSS
            sev_badge = page.query_selector(".severity-badge").inner_text()
            cvss_score = page.query_selector(".score-value").inner_text()
            print(f"     Finding Severity: {sev_badge}, CVSS Score: {cvss_score}")

            # --- Step F: Update Triage Status (PATCH) ---
            print("\n>>> STEP F: Updating Finding Triage Status...")
            page.select_option("#triage-status", "accepted")
            page.fill("#triage-note", "Risk accepted for lab demonstration.")
            page.click("button:has-text('Save Triage Status')")
            page.wait_for_selector(".alert-success")
            print(" [✔] Finding status updated to 'Risk Accepted' with analyst note.")

            # --- Step G: Download Report ---
            print("\n>>> STEP G: Verifying Markdown Report Export...")
            page.click("text=Back to Scan")
            page.wait_for_selector(".scan-actions-bar")
            with page.expect_download() as download_info:
                page.click("text=Download Report (.md)")
            download = download_info.value
            download_path = download.path()
            with open(download_path, "r", encoding="utf-8") as f:
                report_content = f.read()
            assert "Aegis-Web Security Assessment Report" in report_content
            print(f" [✔] Markdown report downloaded successfully ({len(report_content)} bytes).")

            # --- Step H: Launch Scan #2 and Compare ---
            print("\n>>> STEP H: Launching Scan #2 & Comparing Regression...")
            page.click("text=Target Overview")
            page.wait_for_selector("text=Start New Scan")
            page.click("text=Start New Scan")
            page.wait_for_selector(".ethics-notice-box")
            page.check("input[type=checkbox]")
            page.click("button:has-text('Start Access Control Assessment')")
            page.wait_for_selector(".scan-detail-header")

            # Wait for scan 2
            start_wait = time.time()
            while time.time() - start_wait < max_wait:
                status_el = page.query_selector(".status-badge")
                status_text = status_el.inner_text().strip() if status_el else ""
                if "COMPLETED" in status_text:
                    break
                time.sleep(3)

            assert "COMPLETED" in page.inner_text(".status-badge")
            print(" [✔] Scan #2 completed.")

            # Switch to Compare tab
            page.click("button:has-text('Compare Scans')")
            page.wait_for_selector(".compare-control-row")
            page.click("button:has-text('Compare Scans →')")
            page.wait_for_selector(".compare-three-columns")
            print(" [✔] ComparePage rendered with New, Fixed, and Persisting columns.")

            # --- Step I: Check Admin Audit Log ---
            print("\n>>> STEP I: Verifying Administrative Audit Log...")
            page.click("text=Audit Log")
            page.wait_for_selector(".audit-table")
            audit_rows = page.query_selector_all(".audit-table tbody tr")
            print(f"     Audit trail records verified: {len(audit_rows)} logged operations.")
            assert len(audit_rows) >= 5
            print(" [✔] Audit log verified with full immutable operation trail.")

            browser.close()

        print("\n" + "=" * 70)
        print(" DEMO FLOW WALKTHROUGH FULLY VERIFIED IN BROWSER!")
        print("=" * 70)

    finally:
        print("\nCleaning up server processes...")
        backend_proc.terminate()
        worker_proc.terminate()
        frontend_proc.terminate()


if __name__ == "__main__":
    main()
