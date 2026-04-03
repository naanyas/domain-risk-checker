"""
Threat Intelligence Checkers
=============================
Lightweight domain/IP reputation checks against free threat intel services.
All functions return dicts — designed to run as ThreadPoolExecutor futures.

Services:
- Google Safe Browsing (requires API key)
- URLhaus / Abuse.ch (no key required)
- PhishTank (optional key for higher rate limits)
- AbuseIPDB (requires API key, free tier: 1000 checks/day)
"""

import json
import urllib.request
import urllib.error
from typing import Dict, Optional


# =============================================================================
# GOOGLE SAFE BROWSING
# =============================================================================

def check_google_safebrowsing(domain: str, api_key: str = "", timeout: float = 5.0) -> Dict:
    """
    Check domain against Google Safe Browsing API v4.
    Returns threat types if listed (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, etc.).
    Requires a free Google Cloud API key with Safe Browsing API enabled.
    """
    result = {
        "available": False,
        "listed": False,
        "threat_types": [],
        "platform_types": [],
        "error": "",
    }
    if not api_key:
        result["error"] = "No Google Safe Browsing API key configured"
        return result

    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = json.dumps({
        "client": {"clientId": "config-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": f"http://{domain}/"},
                {"url": f"https://{domain}/"},
            ],
        },
    }).encode("utf-8")

    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        result["available"] = True
        matches = data.get("matches", [])
        if matches:
            result["listed"] = True
            result["threat_types"] = list({m.get("threatType", "") for m in matches})
            result["platform_types"] = list({m.get("platformType", "") for m in matches})
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# =============================================================================
# URLHAUS / ABUSE.CH
# =============================================================================

def check_urlhaus(domain: str, timeout: float = 5.0) -> Dict:
    """
    Check domain against URLhaus (abuse.ch) malware URL database.
    No API key required. Returns active malware URL count and threat tags.
    """
    result = {
        "available": False,
        "listed": False,
        "url_count": 0,
        "urls_online": 0,
        "tags": [],
        "error": "",
    }
    url = "https://urlhaus-api.abuse.ch/v1/host/"
    payload = f"host={domain}".encode("utf-8")

    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        result["available"] = True
        status = data.get("query_status", "")
        if status == "no_results":
            return result
        url_count = data.get("url_count", 0) or 0
        urls = data.get("urls", []) or []
        online_count = sum(1 for u in urls if u.get("url_status") == "online")
        all_tags = set()
        for u in urls:
            for t in (u.get("tags") or []):
                if t:
                    all_tags.add(t)
        result["url_count"] = url_count
        result["urls_online"] = online_count
        result["tags"] = sorted(all_tags)
        if url_count > 0:
            result["listed"] = True
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# =============================================================================
# PHISHTANK
# =============================================================================

def check_phishtank(domain: str, api_key: str = "", timeout: float = 5.0) -> Dict:
    """
    Check domain against PhishTank database.
    Optional API key for higher rate limits (without key: ~20 req/min).
    Returns whether the domain has verified phishing URLs.
    """
    result = {
        "available": False,
        "listed": False,
        "verified": False,
        "phish_detail_url": "",
        "error": "",
    }
    # PhishTank checks URLs, so we check the root URL
    check_url = f"http://{domain}/"
    api_url = "https://checkurl.phishtank.com/checkurl/"

    payload_parts = [f"url={urllib.request.quote(check_url)}", "format=json"]
    if api_key:
        payload_parts.append(f"app_key={api_key}")
    payload = "&".join(payload_parts).encode("utf-8")

    try:
        req = urllib.request.Request(api_url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", "phishtank/config-checker")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        result["available"] = True
        results = data.get("results", {})
        in_database = results.get("in_database", False)
        if in_database:
            result["listed"] = True
            result["verified"] = results.get("verified", False)
            result["phish_detail_url"] = results.get("phish_detail_page", "")
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


# =============================================================================
# ABUSEIPDB
# =============================================================================

def check_abuseipdb(ip: str, api_key: str = "", timeout: float = 5.0) -> Dict:
    """
    Check IP reputation against AbuseIPDB.
    Requires API key (free tier: 1000 checks/day).
    Returns abuse confidence score (0-100) and report count.
    """
    result = {
        "available": False,
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "is_whitelisted": False,
        "isp": "",
        "usage_type": "",
        "country_code": "",
        "error": "",
    }
    if not api_key:
        result["error"] = "No AbuseIPDB API key configured"
        return result
    if not ip:
        result["error"] = "No IP address to check"
        return result

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"

    try:
        req = urllib.request.Request(url)
        req.add_header("Key", api_key)
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        result["available"] = True
        d = data.get("data", {})
        result["abuse_confidence_score"] = d.get("abuseConfidenceScore", 0)
        result["total_reports"] = d.get("totalReports", 0)
        result["is_whitelisted"] = d.get("isWhitelisted", False)
        result["isp"] = d.get("isp", "")
        result["usage_type"] = d.get("usageType", "")
        result["country_code"] = d.get("countryCode", "")
    except urllib.error.HTTPError as e:
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result
