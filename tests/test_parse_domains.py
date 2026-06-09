"""
Offline tests for app.parse_domains() — the v8.4 dual root/URL parser.

Verifies that a pasted URL is split into a registrable-root descriptor and a
submitted-URL descriptor (path/subdomain), that case-sensitive paths are
preserved, and that bare domains / www are treated as non-differing.

No network required (parse_domains is pure string work + get_registrable_domain).

Run with:
    python -m pytest tests/test_parse_domains.py -v
or as a plain script:
    python tests/test_parse_domains.py
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import app  # noqa: E402  (imports streamlit, but parse_domains makes no st calls)


def _one(text: str) -> dict:
    entries = app.parse_domains(text)
    assert len(entries) == 1, f"expected 1 entry, got {len(entries)}: {entries}"
    return entries[0]


def test_payhip_path_splits_root_and_url():
    """The reported case: platform root vs the specific product page."""
    e = _one("https://payhip.com/b/h4LuB?utm_source=Pinterest&utm_medium=organic")
    assert e["root"] == "payhip.com", e
    assert e["url_host"] == "payhip.com", e
    assert e["differs"] is True, e
    # Case-sensitive path MUST be preserved (h4LuB, not h4lub).
    assert e["url_path"] == "/b/h4LuB", e
    assert e["url"] == "https://payhip.com/b/h4LuB?utm_source=Pinterest&utm_medium=organic", e


def test_bare_domain_does_not_differ():
    e = _one("example.com")
    assert e["root"] == "example.com"
    assert e["differs"] is False
    assert e["url_path"] == ""


def test_www_is_not_a_differing_subdomain():
    e = _one("https://www.example.com")
    assert e["root"] == "example.com"
    assert e["differs"] is False


def test_real_subdomain_differs():
    e = _one("https://seller.gumroad.com")
    assert e["root"] == "gumroad.com"
    assert e["url_host"] == "seller.gumroad.com"
    assert e["differs"] is True


def test_url_label_disambiguates():
    """_url_label gives each pass a unique, readable row key."""
    path_entry = _one("https://payhip.com/b/h4LuB")
    assert app._url_label(path_entry) == "payhip.com/b/h4LuB"

    bare_entry = _one("example.com")
    assert app._url_label(bare_entry) == "example.com (page)"  # distinct from root row

    sub_entry = _one("https://seller.gumroad.com")
    assert app._url_label(sub_entry) == "seller.gumroad.com"


def test_compound_tld_root():
    e = _one("https://shop.acme.co.uk/product/123")
    assert e["root"] == "acme.co.uk", e
    assert e["differs"] is True
    assert e["url_path"] == "/product/123"


def test_shortener_host_detection():
    assert app._host_is_shortener("a.co") is True
    assert app._host_is_shortener("bit.ly") is True
    assert app._host_is_shortener("amazon.com") is False
    assert app._host_is_shortener("notashortener.example") is False


def test_expand_shorteners_retargets_to_destination():
    """With resolution mocked, a shortener entry is re-pointed at the
    destination (root + path) and tagged with via_shortener."""
    orig = app._resolve_final_url
    app._resolve_final_url = lambda url, timeout=10.0: "https://www.amazon.com/dp/B0H4D6B7GH?ref=x"
    try:
        entries = app.parse_domains("https://a.co/d/06eJm1RH")
        out = app._expand_shorteners(entries, {"timeout": 5.0})[0]
    finally:
        app._resolve_final_url = orig
    assert out["root"] == "amazon.com", out
    assert out["url_host"] == "www.amazon.com"
    assert out["url_path"] == "/dp/B0H4D6B7GH"
    assert out["shortener_host"] == "a.co"
    assert out["via_shortener"] == "https://a.co/d/06eJm1RH"
    assert "(via a.co)" in app._url_label(out)


def test_expand_shorteners_noop_on_resolve_failure():
    """If resolution fails, the entry is left as the shortener (graceful)."""
    orig = app._resolve_final_url
    app._resolve_final_url = lambda url, timeout=10.0: None
    try:
        entries = app.parse_domains("https://a.co/d/06eJm1RH")
        out = app._expand_shorteners(entries, {"timeout": 5.0})[0]
    finally:
        app._resolve_final_url = orig
    assert out["root"] == "a.co"
    assert "shortener_host" not in out


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"✓ {name}")
    print("\nAll parse_domains tests passed.")
