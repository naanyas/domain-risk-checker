"""
Smoke tests for consumer_harm_checks.run().

Two scenarios:
  1. A benign static page returns the "no signals" consumer_risk_level.
  2. A page that loads a pop-ad network AND has a cloaking branch crosses
     a meaningful score threshold (40+ once the ads+cloak combo bonus fires).

The dynamic probe is disabled here so the tests can run in any CI
environment without outbound network egress.

Run with:
    python -m pytest tests/test_consumer_harm.py -v
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the repo root importable when invoked as a plain script (handy in
# environments without pytest's conftest auto-discovery).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import consumer_harm_checks as ch

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_benign_html_returns_no_signals() -> None:
    """Acme Widgets fixture: standard small-business site, no ad networks,
    no cloak, no scareware.  Should land in the 'none' risk band."""
    html = _load("benign.html")
    result = ch.run(
        url="https://acmewidgets.example/",
        html=html,
        facade=False,
        do_dynamic_probe=False,  # no network in CI
    )
    assert result["consumer_risk_level"] == "none", (
        f"Expected 'none' for benign fixture, got "
        f"{result['consumer_risk_level']!r}. "
        f"Score: {result['score_contribution']}, "
        f"Categories: {result['categories_hit']}"
    )
    assert result["score_contribution"] == 0, (
        f"Expected 0 score for benign fixture, got "
        f"{result['score_contribution']} (breakdown: "
        f"{result['internal_breakdown']})"
    )
    assert not result["combo_hits"]
    assert not result["ad_push_hosts_hit"]


def test_pop_network_plus_cloak_crosses_40() -> None:
    """Pop+cloak fixture: two pop-ad network scripts + two cloak patterns.
    Expected scoring (at default weights):
      • CONSUMER_AD_POP_HOST × 2 hosts = 24 → capped at 25 (ads cap)
      • CONSUMER_CLOAK_STATIC = 12 (one signal even with 2 matches)
      • ads+cloak combo bonus = +10
      → minimum 40+ for this fixture.
    """
    html = _load("pop_cloak.html")
    result = ch.run(
        url="https://aff-tracker.example/",
        html=html,
        facade=False,
        do_dynamic_probe=False,  # no network in CI
    )
    assert result["score_contribution"] >= 40, (
        f"Expected pop+cloak fixture to score >= 40, got "
        f"{result['score_contribution']} (breakdown: "
        f"{result['internal_breakdown']}, "
        f"categories: {result['categories_hit']})"
    )
    assert "ads" in result["categories_hit"]
    assert "cloak" in result["categories_hit"]
    # Combo bonus MUST have fired (ads + cloak)
    assert any("ads+cloak" in c for c in result["combo_hits"]), (
        f"Expected ads+cloak combo hit, got {result['combo_hits']}"
    )
    # Risk level should be 'severe' (the >=30 band) given the score
    assert result["consumer_risk_level"] in ("high", "severe"), (
        f"Expected high or severe risk level, got "
        f"{result['consumer_risk_level']!r}"
    )
    # The ad-network hosts must be reported so the analyzer's
    # UNKNOWN_EXTERNAL_SCRIPT logic knows to skip them.
    assert "propellerads.com" in result["ad_push_hosts_hit"]
    assert "popads.net" in result["ad_push_hosts_hit"]


if __name__ == "__main__":
    # Allow running as a plain script when pytest isn't installed.
    test_benign_html_returns_no_signals()
    print("✓ test_benign_html_returns_no_signals")
    test_pop_network_plus_cloak_crosses_40()
    print("✓ test_pop_network_plus_cloak_crosses_40")
    print("\nAll consumer-harm smoke tests passed.")
