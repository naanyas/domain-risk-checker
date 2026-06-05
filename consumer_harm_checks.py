"""
Consumer Harm Checks (v8.3)
===========================

Detects on-page experiences that are hostile to the end user even when the
domain itself isn't a phishing kit: pop/popunder ad networks, push-notification
ad spam, scareware popups, browser-lock JavaScript, native-ad chumbox, and
crawler-vs-visitor cloaking.

Why a separate module?  These are CONSUMER-facing harms — they don't affect
email deliverability (the rest of the analyzer's bread and butter) but they
DO mean the destination URL behind a sender's email is a hostile experience,
which is grounds to deny approval.  Keeping the logic + scoring in one place
makes the user-facing notice ("this site does X to you") easy to assemble and
easy for an analyst to audit.

Public API
----------
    run(url, html, facade=False, do_dynamic_probe=True) -> dict

    Returns:
      {
        "score_contribution":  int,   # add to analyzer's total before threshold
        "consumer_risk_level": str,   # "none" | "caution" | "high" | "severe"
        "consumer_notice":     str,   # what to show a consumer / sender
        "internal_breakdown":  dict,  # signal -> points (analyst-only)
        "analyst_evidence":    dict,  # signal -> list of evidence (analyst-only)
        "combo_hits":          list,  # combo names that fired (analyst-only)
        "categories_hit":      set,   # which categories scored (for double-count guard)
        "ad_push_hosts_hit":   set,   # hosts already scored here — analyzer skips these
                                      #   in its UNKNOWN_EXTERNAL_SCRIPT logic
      }

Design notes
------------
* All taxonomies (AD_POP_NETWORKS, PUSH_AD_PROVIDERS, etc.) and per-signal
  scores live in config.py — single source of truth, admin-tunable.
* The dynamic probe (`do_dynamic_probe=True`) makes TWO outbound requests,
  one with a Googlebot UA and one with a plain Chrome UA, and diffs the
  results.  Set False in environments without network egress (CI sandbox)
  so the static scan still runs.
* `facade=True` (passed in from analyzer's res.content_is_facade) skips
  scareware visible-text detection because SPA shells have empty bodies —
  the relevant JavaScript trap shapes still fire because they live in
  <script> source which we ALWAYS scan.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# requests is already in requirements.txt for the rest of the analyzer.
# Import is lazy-guarded so unit tests that pass do_dynamic_probe=False
# don't require it to be installed (handy in airgapped CI).
try:
    import requests
    _REQUESTS_OK = True
except ImportError:  # pragma: no cover
    requests = None  # type: ignore[assignment]
    _REQUESTS_OK = False

# All taxonomies + per-signal weights come from config.py — single source of truth.
from config import (
    DEFAULT_CONFIG,
    DO_PROBE,
    CONSUMER_LEVELS,
    CONSUMER_CATEGORY_CAP,
    CONSUMER_COMBO_BONUS,
    CONSUMER_AD_POP_NETWORKS,
    CONSUMER_PUSH_AD_PROVIDERS,
    CONSUMER_PUSH_PLATFORMS_NEUTRAL,
    CONSUMER_NATIVE_CHUMBOX,
    CONSUMER_SCAREWARE_PATTERNS,
    CONSUMER_BROWLOCK_PATTERNS,
    CONSUMER_CLOAK_PATTERNS,
)

# ----------------------------------------------------------------------------
# Pre-compiled regex (compile once at import, reuse per call)
# ----------------------------------------------------------------------------

_SCAREWARE_COMPILED = [re.compile(p, re.IGNORECASE) for p in CONSUMER_SCAREWARE_PATTERNS]
_BROWLOCK_COMPILED  = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in CONSUMER_BROWLOCK_PATTERNS]
_CLOAK_COMPILED     = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in CONSUMER_CLOAK_PATTERNS]

# Pulled from any url=... attribute that loads remote code (script/iframe/link/img)
_URL_ATTR_RE = re.compile(
    r'''(?:src|href|data-src|data-href)\s*=\s*["']([^"']+)["']''',
    re.IGNORECASE,
)

# Notification.requestPermission() (push prompt — generic regardless of provider)
_PUSH_PROMPT_RE = re.compile(
    r'''Notification\s*\.\s*requestPermission\s*\(|navigator\.serviceWorker\.register\s*\(''',
    re.IGNORECASE,
)

# Strip HTML tags for "visible text" analysis (scareware patterns).  Cheap;
# accurate enough for keyword-shape matching.
_TAG_STRIP_RE = re.compile(r'<[^>]+>')


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def _host_in_set(host: str, host_set: Set[str]) -> bool:
    """Match `host` against `host_set` as exact-match OR suffix.

    Example: "trc.taboola.com" matches the set entry "taboola.com" via
    suffix.  Bare-eTLD entries (single-label) are NEVER allowed — that
    would let "example.com" match the wildcard "com".
    """
    if not host:
        return False
    h = host.lower().strip(".")
    for entry in host_set:
        e = entry.lower().strip(".")
        if not e or "." not in e:
            continue
        if h == e or h.endswith("." + e):
            return True
    return False


def _extract_remote_hosts(html: str) -> Set[str]:
    """Return distinct remote hosts referenced by src/href/data-src attributes."""
    hosts: Set[str] = set()
    for match in _URL_ATTR_RE.finditer(html):
        raw = match.group(1).strip()
        if not raw or raw.startswith(("#", "/", "javascript:", "data:", "mailto:", "tel:")):
            continue
        if raw.startswith("//"):
            raw = "https:" + raw
        try:
            p = urlparse(raw)
            host = (p.hostname or "").lower()
        except Exception:
            continue
        if host and "." in host:
            hosts.add(host)
    return hosts


def _weight(weights: Dict[str, int], key: str) -> int:
    """Pull a weight from the merged config, falling back to DEFAULT_CONFIG."""
    return weights.get(key, DEFAULT_CONFIG["weights"].get(key, 0))


# ----------------------------------------------------------------------------
# Per-category detectors
# ----------------------------------------------------------------------------

def _scan_ad_networks(
    hosts: Set[str],
    weights: Dict[str, int],
) -> Tuple[int, Dict[str, int], List[str], Set[str]]:
    """Score remote hosts against AD_POP_NETWORKS.  Returns (capped_score,
    breakdown, evidence_list, hosts_we_owned)."""
    per_host = _weight(weights, "CONSUMER_AD_POP_HOST")
    matched: List[str] = []
    for h in hosts:
        if _host_in_set(h, CONSUMER_AD_POP_NETWORKS):
            matched.append(h)
    if not matched:
        return 0, {}, [], set()
    raw = per_host * len(matched)
    capped = min(raw, CONSUMER_CATEGORY_CAP["ads"])
    breakdown = {"CONSUMER_AD_POP_HOST": capped}
    return capped, breakdown, sorted(matched), set(matched)


def _scan_push(
    hosts: Set[str],
    html: str,
    weights: Dict[str, int],
) -> Tuple[int, Dict[str, int], List[str], Set[str]]:
    """Push-ad networks + Notification.requestPermission() prompt.

    Neutral push platforms (OneSignal etc.) are deliberately NOT scored:
    a SaaS app legitimately asks for push permission via OneSignal.  We
    only count a push prompt when there is ALSO a push-ad host present.
    """
    per_host = _weight(weights, "CONSUMER_PUSH_AD_HOST")
    prompt_pts = _weight(weights, "CONSUMER_PUSH_PROMPT")

    push_ad_hosts: List[str] = [h for h in hosts if _host_in_set(h, CONSUMER_PUSH_AD_PROVIDERS)]
    has_neutral_push = any(_host_in_set(h, CONSUMER_PUSH_PLATFORMS_NEUTRAL) for h in hosts)
    has_prompt = bool(_PUSH_PROMPT_RE.search(html))

    raw = 0
    breakdown: Dict[str, int] = {}
    evidence: List[str] = []

    if push_ad_hosts:
        host_pts = per_host * len(push_ad_hosts)
        raw += host_pts
        breakdown["CONSUMER_PUSH_AD_HOST"] = host_pts
        evidence.extend(sorted(push_ad_hosts))

    if has_prompt and not has_neutral_push and not push_ad_hosts:
        # Prompt with NO known platform behind it — opaque push attempt.
        # Mild signal; the cap below clamps it.
        raw += prompt_pts
        breakdown["CONSUMER_PUSH_PROMPT"] = prompt_pts
        evidence.append("Notification.requestPermission() with no known platform")
    elif has_prompt and push_ad_hosts:
        # Prompt + push-ad host = the spam funnel.
        raw += prompt_pts
        breakdown["CONSUMER_PUSH_PROMPT"] = breakdown.get("CONSUMER_PUSH_PROMPT", 0) + prompt_pts
        evidence.append("Notification.requestPermission() wired to push-ad provider")

    if raw == 0:
        return 0, {}, [], set()
    capped = min(raw, CONSUMER_CATEGORY_CAP["push"])
    if capped < raw:
        # Proportionally scale entries so post-cap math still reads sensibly.
        scale = capped / raw
        breakdown = {k: max(1, int(round(v * scale))) for k, v in breakdown.items()}
    return capped, breakdown, evidence, set(push_ad_hosts)


def _scan_chumbox(
    hosts: Set[str],
    weights: Dict[str, int],
) -> Tuple[int, Dict[str, int], List[str], Set[str]]:
    """Taboola/Outbrain-style content recommendation networks.  Mild signal."""
    per_host = _weight(weights, "CONSUMER_CHUMBOX_HOST")
    matched: List[str] = [h for h in hosts if _host_in_set(h, CONSUMER_NATIVE_CHUMBOX)]
    if not matched:
        return 0, {}, [], set()
    raw = per_host * len(matched)
    capped = min(raw, CONSUMER_CATEGORY_CAP["chumbox"])
    return capped, {"CONSUMER_CHUMBOX_HOST": capped}, sorted(matched), set(matched)


def _scan_scareware(
    html: str,
    facade: bool,
    weights: Dict[str, int],
) -> Tuple[int, Dict[str, int], List[str]]:
    """Look for fake-virus / tech-support copy in visible body text.

    Skipped on facade SPAs — the body is empty in source, so the entire
    detection is moot until you JS-render it (which this static module
    does not do)."""
    if facade:
        return 0, {}, []
    visible = _TAG_STRIP_RE.sub(" ", html)
    visible = re.sub(r"\s+", " ", visible)
    hits: List[str] = []
    for pat in _SCAREWARE_COMPILED:
        m = pat.search(visible)
        if m:
            # Trim evidence to a 120-char window centered on the match
            start = max(0, m.start() - 40)
            end   = min(len(visible), m.end() + 40)
            hits.append(visible[start:end].strip())
    if not hits:
        return 0, {}, []
    pts = _weight(weights, "CONSUMER_SCAREWARE_TEXT")
    # Multiple distinct hits are corroborating but capped — one signal's worth
    # since the category cap is enforced below.  We use min(2*pts, cap) so a
    # single match still scores meaningfully but ten matches don't blow up.
    raw = pts * min(2, len(hits))
    capped = min(raw, CONSUMER_CATEGORY_CAP["scareware"])
    return capped, {"CONSUMER_SCAREWARE_TEXT": capped}, hits[:5]


def _scan_browlock(
    html: str,
    weights: Dict[str, int],
) -> Tuple[int, Dict[str, int], List[str]]:
    """Browser-lock JS shapes — runs even on facade pages (the trap code
    lives in <script>, which IS in source even on SPA shells)."""
    hits: List[str] = []
    for pat in _BROWLOCK_COMPILED:
        m = pat.search(html)
        if m:
            hits.append(pat.pattern[:60])
    if not hits:
        return 0, {}, []
    pts = _weight(weights, "CONSUMER_BROWLOCK_PATTERN")
    raw = pts * min(2, len(hits))
    capped = min(raw, CONSUMER_CATEGORY_CAP["browlock"])
    return capped, {"CONSUMER_BROWLOCK_PATTERN": capped}, hits


def _scan_cloak_static(
    html: str,
    weights: Dict[str, int],
) -> Tuple[int, Dict[str, int], List[str]]:
    """Cloak signatures visible in HTML/JS source.  No network calls."""
    hits: List[str] = []
    for pat in _CLOAK_COMPILED:
        if pat.search(html):
            hits.append(pat.pattern[:80])
    if not hits:
        return 0, {}, []
    pts = _weight(weights, "CONSUMER_CLOAK_STATIC")
    capped = min(pts, CONSUMER_CATEGORY_CAP["cloak"])
    return capped, {"CONSUMER_CLOAK_STATIC": capped}, hits


def _scan_cloak_dynamic(
    url: str,
    html: str,
    weights: Dict[str, int],
    timeout: float = 8.0,
) -> Tuple[int, Dict[str, int], List[str]]:
    """Fetch the URL twice (Chrome UA + Googlebot UA) and diff.  Returns
    (score, breakdown, evidence).

    "Different" means one of:
      • different effective host after redirects (cloaked redirect)
      • visible-word-count ratio < 0.5 or > 2.0 (one version is a stub)
      • known scareware/ad signals present in one response but not the other
    """
    if not _REQUESTS_OK or not url:
        return 0, {}, ["dynamic probe skipped (requests unavailable or no URL)"]
    UA_CHROME = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) "
                 "AppleWebKit/537.36 (KHTML, like Gecko) "
                 "Chrome/120.0.0.0 Safari/537.36")
    UA_BOT    = ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
    try:
        r_chrome = requests.get(url, headers={"User-Agent": UA_CHROME}, timeout=timeout,
                                allow_redirects=True)
        r_bot    = requests.get(url, headers={"User-Agent": UA_BOT}, timeout=timeout,
                                allow_redirects=True)
    except Exception as e:
        return 0, {}, [f"dynamic probe failed: {type(e).__name__}: {str(e)[:120]}"]

    body_chrome = (r_chrome.text or "")[:500_000]
    body_bot    = (r_bot.text or "")[:500_000]

    host_chrome = urlparse(r_chrome.url).hostname or ""
    host_bot    = urlparse(r_bot.url).hostname or ""

    findings: List[str] = []

    # 1. Different host after redirect
    if host_chrome and host_bot and host_chrome != host_bot:
        findings.append(f"Different effective host: chrome={host_chrome} bot={host_bot}")

    # 2. Visible word count divergence
    vw_chrome = len(_TAG_STRIP_RE.sub(" ", body_chrome).split())
    vw_bot    = len(_TAG_STRIP_RE.sub(" ", body_bot).split())
    if vw_chrome > 30 and vw_bot > 30:
        ratio = vw_chrome / vw_bot
        if ratio < 0.5 or ratio > 2.0:
            findings.append(f"Word-count divergence: chrome={vw_chrome} bot={vw_bot}")
    elif (vw_chrome > 100) != (vw_bot > 100):
        findings.append(f"One UA gets stub page: chrome={vw_chrome}w bot={vw_bot}w")

    # 3. Scareware copy in one response only
    sc_chrome = any(p.search(body_chrome) for p in _SCAREWARE_COMPILED)
    sc_bot    = any(p.search(body_bot) for p in _SCAREWARE_COMPILED)
    if sc_chrome and not sc_bot:
        findings.append("Scareware copy visible to browser but hidden from crawler")
    if sc_bot and not sc_chrome:
        # Unusual direction (cloaking FOR the bot) — still cloaking; flag.
        findings.append("Scareware copy visible to crawler but hidden from browser")

    # 4. Ad-network host in one response only
    hosts_chrome = _extract_remote_hosts(body_chrome)
    hosts_bot    = _extract_remote_hosts(body_bot)
    ad_chrome = {h for h in hosts_chrome if _host_in_set(h, CONSUMER_AD_POP_NETWORKS)}
    ad_bot    = {h for h in hosts_bot if _host_in_set(h, CONSUMER_AD_POP_NETWORKS)}
    only_chrome = ad_chrome - ad_bot
    if only_chrome:
        findings.append(f"Ad networks served only to browser: {sorted(only_chrome)[:4]}")

    if not findings:
        return 0, {}, []
    pts = _weight(weights, "CONSUMER_CLOAK_DYNAMIC")
    # Even with the cap, dynamic cloak is the strongest single signal here.
    capped = min(pts, CONSUMER_CATEGORY_CAP["cloak"])
    return capped, {"CONSUMER_CLOAK_DYNAMIC": capped}, findings


# ----------------------------------------------------------------------------
# Risk-level bucket + consumer-facing notice
# ----------------------------------------------------------------------------

def _bucket_level(score: int) -> str:
    # CONSUMER_LEVELS maps level → inclusive lower bound; pick highest match.
    level = "none"
    for name, lo in sorted(CONSUMER_LEVELS.items(), key=lambda kv: kv[1]):
        if score >= lo:
            level = name
    return level


def _build_notice(categories_hit: Set[str], level: str) -> str:
    """Plain-English summary for a consumer panel.  No internal jargon, no
    counts of signals — the analyst view has all of that."""
    if not categories_hit or level == "none":
        return "No consumer-harm signals detected on this page."

    pieces: List[str] = []
    if "ads" in categories_hit:
        pieces.append("loads popup or popunder ads that may open without your action")
    if "push" in categories_hit:
        pieces.append("tries to send you browser notifications that can continue after you leave")
    if "chumbox" in categories_hit:
        pieces.append("embeds third-party clickbait recommendation widgets")
    if "scareware" in categories_hit:
        pieces.append("displays fake virus or security warnings designed to scare you into action")
    if "browlock" in categories_hit:
        pieces.append("runs JavaScript that tries to prevent you from closing the tab")
    if "cloak" in categories_hit:
        pieces.append("shows different content to visitors than to search-engine crawlers")

    if len(pieces) == 1:
        body = pieces[0]
    elif len(pieces) == 2:
        body = f"{pieces[0]} and {pieces[1]}"
    else:
        body = ", ".join(pieces[:-1]) + f", and {pieces[-1]}"

    headline = {
        "caution": "⚠️ This site",
        "high":    "🚫 This site",
        "severe":  "⛔ This site",
    }.get(level, "This site")

    return f"{headline} {body}."


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------

def run(
    url: str,
    html: str,
    facade: bool = False,
    do_dynamic_probe: bool = True,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Score consumer-harm signals on a single page.  See module docstring."""
    weights: Dict[str, int] = (config or {}).get("weights", DEFAULT_CONFIG["weights"])
    html = html or ""

    breakdown: Dict[str, int] = {}
    evidence:  Dict[str, List[str]] = {}
    categories_hit: Set[str] = set()
    ad_push_hosts_hit: Set[str] = set()
    total = 0

    # 1. Remote-host inventory (one HTML scan, reused across detectors).
    hosts = _extract_remote_hosts(html)

    # 2. Ads
    s, b, ev, owned = _scan_ad_networks(hosts, weights)
    if s:
        total += s
        breakdown.update(b)
        evidence["ads"] = ev
        categories_hit.add("ads")
        ad_push_hosts_hit |= owned

    # 3. Push
    s, b, ev, owned = _scan_push(hosts, html, weights)
    if s:
        total += s
        for k, v in b.items():
            breakdown[k] = breakdown.get(k, 0) + v
        evidence["push"] = ev
        categories_hit.add("push")
        ad_push_hosts_hit |= owned

    # 4. Chumbox
    s, b, ev, _owned = _scan_chumbox(hosts, weights)
    if s:
        total += s
        breakdown.update(b)
        evidence["chumbox"] = ev
        categories_hit.add("chumbox")

    # 5. Scareware (skipped on facade SPAs — body is empty in source)
    s, b, ev = _scan_scareware(html, facade, weights)
    if s:
        total += s
        breakdown.update(b)
        evidence["scareware"] = ev
        categories_hit.add("scareware")

    # 6. Browlock (script source, always runs)
    s, b, ev = _scan_browlock(html, weights)
    if s:
        total += s
        breakdown.update(b)
        evidence["browlock"] = ev
        categories_hit.add("browlock")

    # 7. Cloak — static signatures + (optionally) dynamic probe
    s_static, b_static, ev_static = _scan_cloak_static(html, weights)
    if s_static:
        total += s_static
        breakdown.update(b_static)
        evidence.setdefault("cloak", []).extend(ev_static)
        categories_hit.add("cloak")

    if do_dynamic_probe and DO_PROBE and url:
        s_dyn, b_dyn, ev_dyn = _scan_cloak_dynamic(url, html, weights)
        if s_dyn:
            total += s_dyn
            for k, v in b_dyn.items():
                breakdown[k] = breakdown.get(k, 0) + v
            evidence.setdefault("cloak", []).extend(ev_dyn)
            categories_hit.add("cloak")

    # 8. Combo bonuses — each pair fires AT MOST once
    combo_hits: List[str] = []
    for (a, b_), bonus in CONSUMER_COMBO_BONUS.items():
        if a in categories_hit and b_ in categories_hit:
            total += bonus
            combo_hits.append(f"{a}+{b_} (+{bonus})")
            breakdown[f"CONSUMER_COMBO_{a.upper()}_{b_.upper()}"] = bonus

    level  = _bucket_level(total)
    notice = _build_notice(categories_hit, level)

    return {
        "score_contribution":  int(total),
        "consumer_risk_level": level,
        "consumer_notice":     notice,
        "internal_breakdown":  breakdown,
        "analyst_evidence":    evidence,
        "combo_hits":          combo_hits,
        "categories_hit":      categories_hit,
        "ad_push_hosts_hit":   ad_push_hosts_hit,
    }
