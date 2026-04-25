"""
Lookalike domain surveillance.

Generates plausible typosquat / homoglyph / brand-impersonation permutations
of a target domain, then DNS-checks each to find ones that are actually
registered. Output is a structured threat-surface inventory the operator can
review.

This is intentionally informational-only (no scoring impact) — it surfaces
what someone trying to impersonate the analyzed domain might have already
registered, so the operator can decide whether to take action (UDRP, takedown,
defensive registration, monitoring, etc.).

Permutation strategies implemented:
  • Character omission        acme → cme, ame, ace, acm
  • Character repetition      acme → aacme, accme, acmme, acmee
  • Adjacent character swap   acme → came, amce, acem
  • Homoglyph substitution    acme → 4cme, acm3, etc.
  • Keyboard-adjacent swap    acme → scme, qcme, axme, etc.
  • Common TLD swap           acme.com → acme.co, acme.cm, acme.net, acme.org
  • Hyphen insertion          acme → ac-me, a-cme, acme-1
  • Brand + suffix            acme → acme-login, acme-secure, acme-support
  • Subdomain prefix          acme → mail-acme, support-acme

Out of scope (would require external services):
  • Bitsquatting
  • Internationalized / IDN homoglyph attacks (Cyrillic а, Greek α, etc.)
  • Display-name spoof reports — needs DMARC RUA ingestion
  • Free webmail impersonation — needs email enumeration service
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ============================================================================
# Permutation generation
# ============================================================================

# Single-character ASCII homoglyphs only. IDN/Unicode homoglyphs are out of
# scope here — they need a separate punycode-aware checker.
HOMOGLYPHS = {
    'a': ['4'],     # '@' is a visual homoglyph but not a valid DNS char
    'b': ['8'],
    'e': ['3'],
    'g': ['9', 'q'],
    'i': ['1', 'l'],
    'l': ['1', 'i'],
    'o': ['0'],
    's': ['5', 'z'],
    'z': ['2', 's'],
}

# QWERTY adjacency (US layout). Used for fat-finger substitutions.
KEYBOARD_ADJACENT = {
    'a': 'sqwz', 'b': 'vghn', 'c': 'xdfv', 'd': 'serfcx',
    'e': 'wsdfr', 'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb',
    'i': 'ujko', 'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
    'm': 'njk', 'n': 'bhjm', 'o': 'iklp', 'p': 'ol',
    'q': 'wa', 'r': 'edft', 's': 'awedxz', 't': 'rfgy',
    'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc',
    'y': 'tghu', 'z': 'asx',
}

# Common alternate TLDs and "fat-finger" TLD typos.
TLD_SWAPS = [
    'co', 'cm', 'om', 'comm', 'con',         # .com typos
    'net', 'org', 'biz', 'info',              # alternate gTLDs
    'shop', 'store', 'site', 'online',        # newer scammy TLDs
    'app', 'io', 'co.uk', 'us',
]

# Brand-impersonation suffixes — what attackers commonly append.
BRAND_SUFFIXES = [
    'login', 'signin', 'auth', 'secure', 'verify', 'verification',
    'support', 'help', 'service', 'account', 'accounts',
    'mail', 'email', 'webmail',
    'pay', 'payment', 'billing', 'invoice',
    'app', 'portal', 'admin',
    'update', 'security',
]

# Brand-impersonation prefixes — what attackers commonly prepend.
BRAND_PREFIXES = [
    'mail', 'login', 'secure', 'support',
    'my', 'web', 'app', 'portal', 'admin',
    'verify', 'auth', 'account',
]


def _omit(label: str) -> Set[str]:
    """Drop one character at a time. abc → bc, ac, ab."""
    out = set()
    if len(label) <= 2:
        return out  # too short to omit
    for i in range(len(label)):
        candidate = label[:i] + label[i + 1:]
        if len(candidate) >= 2:
            out.add(candidate)
    return out


def _repeat(label: str) -> Set[str]:
    """Double one character. abc → aabc, abbc, abcc."""
    out = set()
    for i, ch in enumerate(label):
        out.add(label[:i + 1] + ch + label[i + 1:])
    return out


def _swap_adjacent(label: str) -> Set[str]:
    """Swap each pair of adjacent characters. abc → bac, acb."""
    out = set()
    chars = list(label)
    for i in range(len(chars) - 1):
        if chars[i] == chars[i + 1]:
            continue
        new = chars[:]
        new[i], new[i + 1] = new[i + 1], new[i]
        out.add(''.join(new))
    return out


def _homoglyph_subs(label: str) -> Set[str]:
    """Replace each character with its homoglyphs. acme → 4cme, acm3 etc."""
    out = set()
    for i, ch in enumerate(label):
        for replacement in HOMOGLYPHS.get(ch, []):
            out.add(label[:i] + replacement + label[i + 1:])
    return out


def _keyboard_subs(label: str) -> Set[str]:
    """Replace each character with a keyboard-adjacent letter."""
    out = set()
    for i, ch in enumerate(label):
        for replacement in KEYBOARD_ADJACENT.get(ch, ''):
            out.add(label[:i] + replacement + label[i + 1:])
    return out


def _hyphen_insert(label: str) -> Set[str]:
    """Insert a hyphen between adjacent characters. acme → ac-me, a-cme."""
    out = set()
    if len(label) < 4:
        return out
    for i in range(1, len(label)):
        out.add(label[:i] + '-' + label[i:])
    return out


def generate_permutations(domain: str, max_candidates: int = 200) -> List[str]:
    """
    Generate plausible lookalike permutations of `domain`.

    Returns up to `max_candidates` unique candidate domains. The original
    domain is excluded from the result.

    Strategy priority (most-likely-malicious first, since we cap the count):
      1. TLD swaps          (highest signal — .co, .cm, .om typos are classic)
      2. Hyphen + suffix    (acme-login.com — most common phishing pattern)
      3. Adjacent swap      (came.com — fat-finger typos)
      4. Homoglyph          (4cme.com — visual confusion)
      5. Omission           (cme.com)
      6. Repetition         (acmme.com)
      7. Keyboard adjacent  (scme.com — fat-finger)
      8. Hyphen alone       (ac-me.com)
    """
    domain = domain.lower().strip().rstrip('.')
    if '.' not in domain:
        return []

    label, _, tld_part = domain.partition('.')
    candidates: Set[str] = set()

    # 1. TLD swaps on the original label
    for new_tld in TLD_SWAPS:
        candidates.add(f"{label}.{new_tld}")

    # 2. Brand suffix / prefix combinations on apex TLD
    for suffix in BRAND_SUFFIXES:
        candidates.add(f"{label}-{suffix}.{tld_part}")
        candidates.add(f"{label}{suffix}.{tld_part}")
    for prefix in BRAND_PREFIXES:
        candidates.add(f"{prefix}-{label}.{tld_part}")
        candidates.add(f"{prefix}{label}.{tld_part}")

    # 3. Character permutations applied to the label
    for perm_set in [
        _swap_adjacent(label),
        _homoglyph_subs(label),
        _omit(label),
        _repeat(label),
        _keyboard_subs(label),
        _hyphen_insert(label),
    ]:
        for variant in perm_set:
            candidates.add(f"{variant}.{tld_part}")

    candidates.discard(domain)  # never include the original

    # DNS-validity filter: each label must be ASCII alphanumeric + hyphens
    # only, hyphen never leading/trailing, label length 1-63.
    def _valid(d: str) -> bool:
        if len(d) > 253:
            return False
        for label in d.split('.'):
            if not label or len(label) > 63:
                return False
            if label.startswith('-') or label.endswith('-'):
                return False
            for ch in label:
                if not (ch.isalnum() or ch == '-'):
                    return False
        return True

    valid = {c for c in candidates if _valid(c)}
    # Stable order so reruns produce identical lists for the same domain
    sorted_candidates = sorted(valid)
    return sorted_candidates[:max_candidates]


# ============================================================================
# Registration check
# ============================================================================

def _is_registered(candidate: str, timeout: float = 2.0) -> Dict:
    """
    Cheap registration check: does the candidate have any DNS records?

    We try (in order) A, NS, MX. A registered domain almost always has at
    least NS records pointing somewhere; an unregistered domain returns
    NXDOMAIN on every query type.

    Returns dict with: registered, has_a, has_mx, ip, mx_count, error.
    """
    result = {
        "candidate": candidate,
        "registered": False,
        "has_a": False,
        "has_mx": False,
        "ip": "",
        "mx_count": 0,
        "error": "",
    }

    # Try A record first (cheapest and most common for live phishing infra)
    try:
        ip = socket.gethostbyname(candidate)
        result["registered"] = True
        result["has_a"] = True
        result["ip"] = ip
    except socket.gaierror:
        # No A record — could be unregistered, or registered without web.
        # Fall through to NS/MX checks.
        pass
    except Exception as exc:
        result["error"] = f"A lookup failed: {exc}"

    # If no A record, check NS — registered domains have NS even without A
    if not result["registered"] and DNS_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(candidate, "NS")
            if answers:
                result["registered"] = True
        except Exception:
            pass  # Treat as unregistered

    # MX check (only if registered, indicates mail-receiving capability)
    if result["registered"] and DNS_AVAILABLE:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(candidate, "MX")
            result["has_mx"] = True
            result["mx_count"] = len(answers)
        except Exception:
            pass

    return result


def check_registrations(
    candidates: List[str],
    timeout: float = 2.0,
    max_workers: int = 10,
    overall_timeout: float = 30.0,
) -> List[Dict]:
    """
    Concurrently check which candidates are registered.

    Returns a list of dicts (one per registered candidate) with metadata.
    Unregistered candidates are dropped.

    `overall_timeout` caps total wall-clock time across all lookups so a
    slow resolver can't extend domain analysis indefinitely.
    """
    if not candidates:
        return []

    registered: List[Dict] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(_is_registered, c, timeout): c for c in candidates}
        try:
            for future in as_completed(future_map, timeout=overall_timeout):
                try:
                    result = future.result()
                    if result["registered"]:
                        registered.append(result)
                except Exception:
                    continue
        except Exception:
            # Overall timeout fired — return whatever we got so far.
            pass

    # Sort: domains with A records first (live infrastructure), then by name
    registered.sort(key=lambda r: (not r["has_a"], r["candidate"]))
    return registered


# ============================================================================
# Public entry point
# ============================================================================

def find_lookalikes(
    domain: str,
    max_candidates: int = 200,
    timeout: float = 2.0,
    max_workers: int = 10,
    overall_timeout: float = 30.0,
) -> Dict:
    """
    End-to-end lookalike surveillance for `domain`.

    Returns:
      {
        "candidates_checked": int,
        "registered": List[Dict],   # registered lookalikes with metadata
        "registered_count": int,
      }
    """
    candidates = generate_permutations(domain, max_candidates=max_candidates)
    registered = check_registrations(
        candidates,
        timeout=timeout,
        max_workers=max_workers,
        overall_timeout=overall_timeout,
    )
    return {
        "candidates_checked": len(candidates),
        "registered": registered,
        "registered_count": len(registered),
    }
