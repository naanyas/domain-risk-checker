"""
Offline tests for the v8.5 headless-render auto-gate and graceful fallback.

The render itself needs a browser, so these cover the deterministic parts:
  * analyzer._should_render() decides correctly when to pay for a render.
  * headless_render degrades safely (render_html(None) -> None).

No network/browser required.

Run:  python tests/test_render_gate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import analyzer            # noqa: E402
import headless_render     # noqa: E402


def test_gate_fires_on_ad_network():
    html = ('<html><head><script src="https://pagead2.googlesyndication.com/'
            'pagead/js/adsbygoogle.js"></script></head><body>hi</body></html>')
    assert analyzer._should_render(html) is True


def test_gate_skips_plain_page():
    html = "<html><body>" + ("hello world " * 80) + "</body></html>"
    assert analyzer._should_render(html) is False


def test_gate_fires_on_short_wordpress():
    html = ("<html><head><link href='/wp-content/themes/x/style.css'></head>"
            "<body>" + ("word " * 100) + "</body></html>")
    assert analyzer._should_render(html) is True


def test_gate_skips_longform_wordpress():
    html = ("<html><head><link href='/wp-content/themes/x/style.css'></head>"
            "<body>" + ("word " * 2000) + "</body></html>")
    assert analyzer._should_render(html) is False


def test_gate_empty_html():
    assert analyzer._should_render("") is False


def test_render_graceful_on_empty_url():
    # Must return None (not raise) regardless of whether a browser is installed.
    assert headless_render.render_html("") is None


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"✓ {name}")
    print("\nAll render-gate tests passed.")
