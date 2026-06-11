"""
Headless page rendering (v8.5)
==============================

Optional Playwright-backed renderer.  Some pages — especially made-for-
advertising content farms — inject their ad units (and sometimes their real
content) CLIENT-SIDE, so a static HTTP fetch under-sees them.  Rendering the
page in a real headless browser executes that JavaScript and returns the
post-render DOM, which the content / consumer-harm scanners can then analyze.

Design
------
* Lazy, guarded import — if Playwright (or its browser) isn't installed, this
  module degrades to a no-op (`render_html` returns None) and callers fall back
  to the static fetch.  This guarantees the analyzer keeps working even when the
  browser layer is unavailable (e.g. a Nixpacks build without Chromium).
* Synchronous API (`sync_playwright`) so it drops into the existing synchronous
  analyzer without an event loop.
* Hard timeout + blocking of obviously-heavy resources is avoided — we WANT ad
  scripts to run, since detecting them is the point.  We only cap total time.

Public API
----------
    render_html(url, timeout=12.0, wait_until="networkidle", settle_ms=1500) -> str | None
    RENDER_AVAILABLE: bool
"""

from __future__ import annotations

import sys
from typing import Optional


def _log(msg: str) -> None:
    """Lightweight stderr diagnostics (captured by Railway logs)."""
    try:
        print(f"[render] {msg}", file=sys.stderr, flush=True)
    except Exception:
        pass


try:
    from playwright.sync_api import sync_playwright  # type: ignore
    RENDER_AVAILABLE = True
except Exception as _e:  # pragma: no cover - import guard
    sync_playwright = None  # type: ignore[assignment]
    RENDER_AVAILABLE = False
    _log(f"playwright import failed: {type(_e).__name__}: {_e}")

# Set True after the first failed browser launch (e.g. browser not installed) so
# subsequent calls short-circuit instead of repeatedly paying a slow failure.
_BROWSER_DISABLED = False


_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def render_html(
    url: str,
    timeout: float = 12.0,
    wait_until: str = "networkidle",
    settle_ms: int = 1500,
) -> Optional[str]:
    """Render `url` in headless Chromium and return the post-render HTML.

    Returns None on any failure (browser missing, navigation error, timeout) so
    the caller can fall back to the static fetch.  `timeout` is the per-page
    ceiling in seconds; `settle_ms` is an extra wait after load for late ad
    injection.
    """
    global _BROWSER_DISABLED
    if not RENDER_AVAILABLE or _BROWSER_DISABLED or not url:
        return None
    timeout_ms = int(max(1.0, timeout) * 1000)
    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                )
            except Exception as e:
                # No usable browser (e.g. Streamlit Cloud: playwright pkg present
                # but no Chromium installed). Disable for the rest of the process
                # so we don't pay a failed launch on every gated page.
                _BROWSER_DISABLED = True
                _log(f"browser launch failed — disabling render: {type(e).__name__}: {str(e)[:120]}")
                return None
            try:
                context = browser.new_context(
                    user_agent=_UA,
                    viewport={"width": 1366, "height": 900},
                    ignore_https_errors=True,
                )
                page = context.new_page()
                page.set_default_timeout(timeout_ms)
                try:
                    page.goto(url, wait_until=wait_until, timeout=timeout_ms)
                except Exception:
                    # networkidle can time out on ad-heavy pages that never go
                    # idle — fall back to a looser load state, content is usually
                    # already present.
                    try:
                        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    except Exception:
                        return None
                # Give late client-side ad injection a moment to run.
                try:
                    page.wait_for_timeout(settle_ms)
                except Exception:
                    pass
                html = page.content()
                _log(f"ok url={url[:80]} len={len(html or '')}")
                return html or None
            finally:
                browser.close()
    except Exception as e:
        _log(f"failed url={url[:80]} {type(e).__name__}: {str(e)[:160]}")
        return None
