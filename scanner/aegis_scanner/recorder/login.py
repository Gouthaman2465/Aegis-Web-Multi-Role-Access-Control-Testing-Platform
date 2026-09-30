"""Playwright form login automation."""

from playwright.sync_api import Page
from aegis_scanner.models import AccountConfig, ScanConfig


class LoginFailedError(Exception):
    """Raised when authentication on the target application fails."""
    pass


def login(page: Page, account: AccountConfig, config: ScanConfig) -> None:
    """Perform automated form login using Playwright for a specific test account."""
    try:
        page.goto(account.login_url, timeout=20000)
    except Exception as e:
        raise LoginFailedError(f"Failed to navigate to login URL for '{account.label}': {e}") from e

    # Dismiss modals / cookie banners if specified
    for sel in account.dismiss_selectors:
        try:
            loc = page.locator(sel).first
            if loc.is_visible(timeout=1500):
                loc.click(timeout=1500)
        except Exception:
            pass  # Ignore absent or unclickable dismiss selectors

    # Fill username and password, then submit
    try:
        page.locator(account.username_selector).first.fill(account.username, timeout=5000)
        page.locator(account.password_selector).first.fill(account.password, timeout=5000)
        page.locator(account.submit_selector).first.click(timeout=5000)
    except Exception as e:
        raise LoginFailedError(f"Error submitting login form for '{account.label}': {e}") from e

    # Wait for network requests to settle
    try:
        page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass

    # Verify successful login
    if account.success_url_contains:
        if account.success_url_contains not in page.url:
            raise LoginFailedError(f"Login failed for account '{account.label}': URL mismatch")
    else:
        # Default verification: password input should no longer be visible
        try:
            pwd_visible = page.locator(account.password_selector).first.is_visible(timeout=2000)
            if pwd_visible:
                raise LoginFailedError(f"Login failed for account '{account.label}': form still visible")
        except LoginFailedError:
            raise
        except Exception:
            pass
