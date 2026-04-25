"""
Analyst-facing remediation guidance for DMARC RUA findings.

These differ from remediations.py (which is operator-facing — for the
domain owner to fix their own setup) because the consumer here is a
OneSignal analyst whose job is to explain a finding to the customer
and recommend next steps.

Each entry has three fields:

  what_it_means      — analyst-readable interpretation of the finding,
                       including impact assessment.
  analyst_actions    — step-by-step actions the analyst should take.
  customer_message   — copy-pasteable message template the analyst can
                       send the customer (rendered with {domain} etc.).

Detection rules live in `evaluate_rollup()` below — given a DmarcRollup
they fire zero or more remediation entries by name.
"""

from typing import List

from dmarc_aggregate import DmarcRollup, top_sources


# ============================================================================
# Detection rule thresholds — tunable
# ============================================================================

SPOOF_VOLUME_LOW = 10            # below this we don't bother flagging
SPOOF_VOLUME_HIGH = 1000         # above this it's an active campaign
MISALIGNED_PCT_THRESHOLD = 0.05  # 5% of total volume — likely real config drift
DOMINANT_SOURCE_PCT = 0.80       # one source = ≥80% volume
P_NONE_SPOOF_THRESHOLD = 100     # at p=none with spoof volume ≥100, escalate


# ============================================================================
# Remediation registry
# ============================================================================

DMARC_REMEDIATIONS = {
    "no_data": {
        "what_it_means": (
            "We are not currently receiving DMARC aggregate reports for {domain}. "
            "Either the customer has not yet pointed their `rua=` tag at our "
            "endpoint, or no receiving organizations have generated reports in "
            "the lookback window."
        ),
        "analyst_actions": (
            "1. Confirm the customer's DMARC record has been updated to include "
            "OneSignal's `rua=mailto:` address.\n"
            "2. Check the customer's domain DNS for the current DMARC record:\n"
            "   `dig TXT _dmarc.{domain}`\n"
            "3. If recently updated, allow 24-72h for receivers to start sending "
            "reports.\n"
            "4. If the rua= is correct and 72h+ have passed, escalate to "
            "infra to verify the receiver pipeline is processing inbound."
        ),
        "customer_message": (
            "Hi — to populate spoofing visibility data for {domain}, please "
            "update your DMARC record to include our reporting address. Add "
            "the following `rua=` tag to your existing DMARC record:\n\n"
            "    rua=mailto:dmarc@onesignal.com\n\n"
            "If you already have a `rua=` tag, you can list multiple addresses "
            "comma-separated. After the change propagates, expect 24-72h "
            "before reports start arriving."
        ),
    },

    "high_spoofing_volume": {
        "what_it_means": (
            "DMARC reports show {real_domain_spoofing} messages claiming to be "
            "from {domain} that failed both SPF and DKIM in the last "
            "{days_back} days. This is genuine spoofing activity — someone is "
            "actively sending mail as the customer's domain from infrastructure "
            "they do not control. Receiver dispositions: {quarantined} "
            "quarantined, {rejected} rejected. The spoofers are being blocked "
            "where DMARC enforcement exists, but anywhere DMARC is honored "
            "weakly (or the customer's policy is `p=none`) these messages may "
            "still be delivered."
        ),
        "analyst_actions": (
            "1. Pull the top spoofing source IPs from the rollup. If any IP "
            "is in a single block / ASN, that's a campaign infrastructure "
            "pattern worth flagging to the customer.\n"
            "2. Check the customer's DMARC policy. If `p=none`, recommend "
            "escalating to `p=quarantine` once their legitimate mail is fully "
            "aligned (SPF + DKIM passing).\n"
            "3. If `p=quarantine` or `p=reject` is already set, the spoofing "
            "is being mitigated — confirm with the customer that they're "
            "monitoring deliverability for their legitimate mail and not "
            "seeing collateral damage.\n"
            "4. Offer to file abuse reports with the hosting providers of the "
            "top spoofing IPs (use AbuseIPDB / Spamhaus / arin.net WHOIS to "
            "find abuse@ contacts)."
        ),
        "customer_message": (
            "We're seeing significant spoofing activity targeting {domain}. "
            "In the last {days_back} days, DMARC reports show "
            "{real_domain_spoofing} messages claiming to be from your domain "
            "that failed both SPF and DKIM authentication. Of those, "
            "{quarantined} were quarantined and {rejected} were rejected by "
            "receivers — but anywhere your domain is delivered to mailboxes "
            "with weaker DMARC enforcement, these messages may still land in "
            "inboxes.\n\n"
            "Recommended next steps:\n"
            "1. Verify all your legitimate mail sources are SPF-aligned and "
            "DKIM-signed. We can review your current config.\n"
            "2. Once aligned, escalate your DMARC policy from p=none → "
            "p=quarantine → p=reject so receivers actively block these "
            "spoofs.\n"
            "3. We can help file abuse reports against the top spoofing "
            "source IPs if you'd like."
        ),
    },

    "low_grade_spoofing": {
        "what_it_means": (
            "DMARC reports show a small but non-zero amount of spoofing "
            "activity ({real_domain_spoofing} messages) targeting {domain}. "
            "Likely opportunistic / low-effort — not an active campaign."
        ),
        "analyst_actions": (
            "1. Note the volume in the customer record but don't escalate.\n"
            "2. If volume trends up over the next 30 days, escalate to "
            "the high-volume remediation."
        ),
        "customer_message": (
            "We're seeing low-volume spoofing attempts against {domain} "
            "({real_domain_spoofing} messages over {days_back} days). This "
            "is typical background-noise activity — your DMARC policy is "
            "handling it. We'll keep watching trends and let you know if "
            "volume escalates."
        ),
    },

    "p_none_with_spoofing": {
        "what_it_means": (
            "{domain} has DMARC published at `p=none`, which means receivers "
            "are reporting spoofing attempts but not actively blocking them. "
            "Combined with {real_domain_spoofing} spoofing attempts in the "
            "lookback window, this is a real risk — anywhere these messages "
            "land in user inboxes, they appear legitimate."
        ),
        "analyst_actions": (
            "1. Show the customer their current DMARC policy and explain that "
            "`p=none` is monitor-only.\n"
            "2. Verify their legitimate mail is fully aligned (use SDAT's "
            "main analysis to confirm SPF + DKIM align with header-from).\n"
            "3. Recommend a phased policy escalation: p=none → p=quarantine "
            "(monitor 30 days for FPs) → p=reject.\n"
            "4. Make sure they have a DMARC aggregate report processor "
            "configured (Postmark Digests, dmarcian, EasyDMARC) so they "
            "can monitor enforcement impact."
        ),
        "customer_message": (
            "Your DMARC policy for {domain} is currently set to `p=none`, "
            "which means receivers are reporting spoofing to us but not "
            "actively blocking it. We're seeing {real_domain_spoofing} "
            "spoofing attempts in the last {days_back} days — anywhere "
            "those land, they appear legitimate to your recipients.\n\n"
            "Recommended path forward:\n"
            "1. Confirm your legitimate mail is fully SPF + DKIM aligned "
            "(we can review).\n"
            "2. Update your DMARC record to `p=quarantine`. This tells "
            "receivers to send unaligned mail to spam.\n"
            "3. Monitor for 30 days — make sure none of your legitimate "
            "mail is being misclassified.\n"
            "4. Escalate to `p=reject` for full protection.\n\n"
            "We'll review the rollouts with you at each step."
        ),
    },

    "misaligned_legitimate_sources": {
        "what_it_means": (
            "{misaligned_messages} messages from {domain} are passing one of "
            "SPF/DKIM but not the other. Most common cause: forwarding "
            "(SPF breaks but DKIM survives) or an internal sender that's "
            "DKIM-signing without SPF authorization. Less common but worth "
            "checking: a legitimate sending source the customer hasn't "
            "added to their SPF record."
        ),
        "analyst_actions": (
            "1. Pull the top misaligned source IPs from the rollup.\n"
            "2. Cross-reference each IP against the customer's known senders "
            "(ESP, internal mail server, marketing platform).\n"
            "3. For sources that should be authorized: add to SPF or "
            "configure DKIM signing.\n"
            "4. For pure forwarding scenarios: explain to the customer that "
            "this is expected and DMARC alignment will still pass via DKIM."
        ),
        "customer_message": (
            "We're seeing {misaligned_messages} messages from {domain} that "
            "pass one of SPF or DKIM but not both. Reasons can include:\n\n"
            "- **Forwarding**: a recipient is auto-forwarding your mail; SPF "
            "breaks because the forwarder rewrites the envelope-from. As long "
            "as DKIM passes, DMARC alignment is maintained.\n"
            "- **A legitimate sender not in your SPF record**: a marketing "
            "platform, internal server, or partner that should be authorized.\n"
            "- **A configuration drift**: a service that used to be aligned "
            "but isn't anymore.\n\n"
            "We've pulled the top source IPs — let us know which are "
            "yours and we'll help align the rest."
        ),
    },

    "dominant_source_concentration": {
        "what_it_means": (
            "A single source IP ({top_source}) accounts for {top_source_pct}% "
            "of all mail traffic claiming to be from {domain} in the last "
            "{days_back} days ({top_source_count} messages). This is "
            "expected for a single ESP customer. It becomes risky if the "
            "customer doesn't recognize the source — could indicate a "
            "compromised sending account, a lost ESP credential, or a "
            "misconfigured legitimate platform."
        ),
        "analyst_actions": (
            "1. Look up the AS / ASN for the top source IP. If it matches a "
            "known ESP (SendGrid, Mailgun, etc.), this is normal.\n"
            "2. If the ASN doesn't match the customer's known infrastructure, "
            "flag to the customer immediately — could be a compromise.\n"
            "3. If the source is the customer's own infra, no action needed."
        ),
        "customer_message": (
            "A single source IP ({top_source}) is responsible for "
            "{top_source_pct}% of the mail traffic claiming to be from "
            "{domain} ({top_source_count} messages over {days_back} days).\n\n"
            "Can you confirm whether this source is recognized as one of "
            "your legitimate senders (ESP, internal mail server, marketing "
            "platform, etc.)?\n\n"
            "If you don't recognize the source, this could indicate a "
            "compromised credential or unauthorized sender — we should "
            "investigate together."
        ),
    },
}


# ============================================================================
# Detection logic — given a rollup, which remediations fire?
# ============================================================================

def evaluate_rollup(rollup: DmarcRollup, days_back: int = 7) -> List[dict]:
    """
    Evaluate a DmarcRollup and return the remediations that apply, with
    template variables already substituted. Each item is a dict with
    name, what_it_means, analyst_actions, customer_message.

    Returns an empty list if the domain has no data (the no_data
    remediation is fired by the caller when appropriate — we don't
    want this function to fabricate findings).
    """
    out = []

    # If there's no data, return empty — the caller surfaces the
    # no_data remediation explicitly so the analyst sees the right
    # context (no data ≠ no findings).
    if rollup.total_messages == 0:
        return out

    domain = rollup.domain or "this domain"
    sources = top_sources(rollup, limit=1)
    top_ip = sources[0]["source_ip"] if sources else "(unknown)"
    top_count = sources[0]["count"] if sources else 0
    top_pct = (
        round(100 * top_count / rollup.total_messages, 1)
        if rollup.total_messages else 0
    )

    template_vars = {
        "domain": domain,
        "days_back": days_back,
        "real_domain_spoofing": rollup.real_domain_spoofing,
        "misaligned_messages": rollup.misaligned_messages,
        "quarantined": rollup.quarantined,
        "rejected": rollup.rejected,
        "top_source": top_ip,
        "top_source_count": top_count,
        "top_source_pct": top_pct,
    }

    # --- Spoofing volume bands ---
    if rollup.real_domain_spoofing >= SPOOF_VOLUME_HIGH:
        out.append(_render("high_spoofing_volume", template_vars))
    elif rollup.real_domain_spoofing >= SPOOF_VOLUME_LOW:
        out.append(_render("low_grade_spoofing", template_vars))

    # --- p=none with measurable spoofing ---
    # NOTE: requires rollup.policy data; today the rollup doesn't carry the
    # policy so we use a heuristic — high spoof + low rejected count means
    # the policy isn't aggressively enforcing. Future improvement: wire the
    # policy field through the rollup.
    weak_enforcement = rollup.rejected < (rollup.real_domain_spoofing * 0.5)
    if (
        rollup.real_domain_spoofing >= P_NONE_SPOOF_THRESHOLD
        and weak_enforcement
    ):
        out.append(_render("p_none_with_spoofing", template_vars))

    # --- Misaligned legitimate sources ---
    if rollup.misaligned_messages > 0 and rollup.total_messages > 0:
        misaligned_pct = rollup.misaligned_messages / rollup.total_messages
        if misaligned_pct >= MISALIGNED_PCT_THRESHOLD:
            out.append(_render("misaligned_legitimate_sources", template_vars))

    # --- Dominant source concentration ---
    if rollup.total_messages > 0 and top_count > 0:
        if (top_count / rollup.total_messages) >= DOMINANT_SOURCE_PCT:
            out.append(_render("dominant_source_concentration", template_vars))

    return out


def _render(name: str, vars_: dict) -> dict:
    entry = DMARC_REMEDIATIONS[name]
    return {
        "name": name,
        "what_it_means": entry["what_it_means"].format(**vars_),
        "analyst_actions": entry["analyst_actions"].format(**vars_),
        "customer_message": entry["customer_message"].format(**vars_),
    }


def render_no_data(domain: str) -> dict:
    """
    Convenience helper for the no_data case — caller fires this when
    a domain has no rollup data, so the analyst sees an actionable
    "the customer hasn't pointed RUA at us yet" message.
    """
    entry = DMARC_REMEDIATIONS["no_data"]
    return {
        "name": "no_data",
        "what_it_means": entry["what_it_means"].format(domain=domain),
        "analyst_actions": entry["analyst_actions"].format(domain=domain),
        "customer_message": entry["customer_message"].format(domain=domain),
    }
