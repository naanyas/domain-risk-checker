"""
Operational guidance for SDAT signals.

Maps signal names to copy-pasteable remediation steps. SDAT consumers
(the Streamlit UI, an API, etc.) can look up REMEDIATIONS[signal_name]
and surface the fix alongside the issue.

Each entry is a dict with three fields:
  title       — one-line summary of the problem
  why         — short explanation of impact
  fix         — markdown-formatted concrete steps (DNS records, code,
                config) the operator can paste

Placeholders use {domain} so callers can str.format(domain=res.domain)
to produce a domain-specific fix.
"""

REMEDIATIONS = {
    # ============================================================
    # SPF
    # ============================================================
    "no_spf": {
        "title": "No SPF record published",
        "why": (
            "Without SPF, receivers cannot verify which servers are authorized "
            "to send mail for {domain}. Spammers can spoof your domain freely, "
            "and your legitimate mail will fail Gmail/Yahoo bulk-sender checks."
        ),
        "fix": (
            "Publish an SPF TXT record at the apex `{domain}`:\n\n"
            "```\n"
            "{domain}.  IN  TXT  \"v=spf1 include:_spf.google.com ~all\"\n"
            "```\n\n"
            "Replace `_spf.google.com` with your actual sending provider:\n"
            "- Google Workspace: `include:_spf.google.com`\n"
            "- Microsoft 365: `include:spf.protection.outlook.com`\n"
            "- SendGrid: `include:sendgrid.net`\n"
            "- Mailgun: `include:mailgun.org`\n"
            "- Postmark: `include:spf.mtasv.net`\n\n"
            "Use `~all` (softfail) initially. After 30 days of clean DMARC "
            "reports, harden to `-all` (hardfail)."
        ),
    },
    "spf_pass_all": {
        "title": "SPF policy is `+all` (allow everyone)",
        "why": (
            "`+all` tells receivers that any IP in the world is authorized to "
            "send mail for {domain}. This is functionally equivalent to having "
            "no SPF at all, and it is a strong spoofing indicator."
        ),
        "fix": (
            "Change the trailing mechanism from `+all` to `~all` (softfail) or "
            "`-all` (hardfail):\n\n"
            "```\n"
            "v=spf1 include:_spf.google.com -all\n"
            "```\n\n"
            "If you don't know your full sender list, use `~all` and monitor "
            "DMARC aggregate reports for 2-4 weeks before tightening to `-all`."
        ),
    },
    "spf_neutral_all": {
        "title": "SPF policy is `?all` (neutral)",
        "why": (
            "`?all` tells receivers to make no assertion about unauthorized "
            "senders. Most receivers treat this like no SPF at all."
        ),
        "fix": (
            "Replace the trailing `?all` with `~all` (softfail) or `-all` "
            "(hardfail) once you've confirmed your full sender list via DMARC "
            "aggregate reports."
        ),
    },
    "spf_softfail_all": {
        "title": "SPF policy is `~all` (softfail)",
        "why": (
            "`~all` is a reasonable starting policy but does not protect against "
            "spoofing as strongly as `-all`. Mail from unauthorized senders is "
            "marked suspicious but still delivered."
        ),
        "fix": (
            "Once you have 2-4 weeks of clean DMARC aggregate reports confirming "
            "your full sender list, harden the policy to `-all`:\n\n"
            "```\n"
            "v=spf1 include:_spf.google.com -all\n"
            "```"
        ),
    },
    "spf_too_many_lookups": {
        "title": "SPF exceeds the 10-lookup limit (RFC 7208)",
        "why": (
            "When SPF requires more than 10 DNS lookups to evaluate, RFC 7208 "
            "requires receivers to return PermError — which fails DMARC. Mail "
            "from {domain} will be rejected even though SPF is configured."
        ),
        "fix": (
            "Flatten your SPF record. Tools that help:\n\n"
            "- [SPF Surveyor (dmarcian)](https://dmarcian.com/spf-survey/) — visualize the lookup chain\n"
            "- [EasyDMARC SPF Flattener](https://easydmarc.com/tools/spf-record-checker)\n"
            "- [Mailhardener](https://www.mailhardener.com/tools/spf-validator)\n\n"
            "Manual flattening: replace `include:` mechanisms with the actual "
            "IP ranges they resolve to. Re-flatten quarterly because provider "
            "IPs change."
        ),
    },
    "spf_syntax_error": {
        "title": "SPF record has syntax errors",
        "why": (
            "Receivers that hit a syntax error return PermError, which fails "
            "DMARC and damages deliverability."
        ),
        "fix": (
            "Validate your SPF with:\n\n"
            "- [Kitterman SPF Validator](https://www.kitterman.com/spf/validate.html)\n"
            "- [MXToolbox SPF Lookup](https://mxtoolbox.com/spf.aspx)\n\n"
            "Common errors: trailing semicolons, unquoted spaces, missing `v=spf1` "
            "prefix, or multiple SPF records at the apex (only one is allowed)."
        ),
    },

    # ============================================================
    # DKIM
    # ============================================================
    "no_dkim": {
        "title": "No DKIM signing detected",
        "why": (
            "DKIM cryptographically signs outgoing mail, letting receivers "
            "verify that messages weren't modified in transit and were sent "
            "by an authorized server. Without DKIM, DMARC alignment is "
            "impossible and Gmail/Yahoo will reject bulk mail starting Feb 2024."
        ),
        "fix": (
            "Configure DKIM through your sending provider:\n\n"
            "1. Generate a DKIM key pair (your provider does this)\n"
            "2. Publish the public key as a TXT record at "
            "`<selector>._domainkey.{domain}`\n"
            "3. Configure the selector in your sender's DKIM settings\n\n"
            "Provider-specific guides:\n"
            "- Google Workspace: Admin Console → Apps → Gmail → Authenticate email\n"
            "- Microsoft 365: Defender Portal → Email & collaboration → DKIM\n"
            "- SendGrid: Settings → Sender Authentication → Domain Authentication\n"
            "- Mailgun: Sending → Domain settings → DNS records\n\n"
            "Use 2048-bit keys; 1024-bit is deprecated."
        ),
    },

    # ============================================================
    # DMARC
    # ============================================================
    "no_dmarc": {
        "title": "No DMARC record published",
        "why": (
            "DMARC tells receivers what to do with mail that fails SPF or DKIM "
            "and gives you visibility (via aggregate reports) into who is "
            "spoofing your domain. Required by Gmail and Yahoo for bulk senders."
        ),
        "fix": (
            "Publish a DMARC TXT record at `_dmarc.{domain}`:\n\n"
            "```\n"
            "_dmarc.{domain}.  IN  TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@{domain}; pct=100\"\n"
            "```\n\n"
            "**Phased rollout:**\n"
            "1. Start with `p=none` to collect data without affecting delivery\n"
            "2. After 2-4 weeks of aggregate reports, move to `p=quarantine`\n"
            "3. After confirming legitimate mail aligns, move to `p=reject`\n\n"
            "Use a DMARC aggregate report processor (Postmark, dmarcian, "
            "Valimail, EasyDMARC) to make the XML reports readable."
        ),
    },
    "dmarc_p_none": {
        "title": "DMARC policy is `p=none` (monitor only)",
        "why": (
            "`p=none` collects reports but does not protect against spoofing. "
            "Gmail and Yahoo's 2024 bulk sender requirements need at least "
            "`p=quarantine` for the largest senders."
        ),
        "fix": (
            "Once you've reviewed 2-4 weeks of aggregate reports and confirmed "
            "your legitimate sources are aligning correctly, escalate the policy:\n\n"
            "```\n"
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; pct=100\n"
            "```\n\n"
            "Then to `p=reject` once quarantine has been stable for 30 days."
        ),
    },
    "dmarc_no_rua": {
        "title": "DMARC has no aggregate reporting (`rua=`) configured",
        "why": (
            "Without `rua=`, you have no visibility into authentication failures "
            "or spoofing attempts targeting {domain}. You cannot tighten the "
            "policy safely without this data."
        ),
        "fix": (
            "Add a `rua=` tag with a mailbox that can receive XML aggregate "
            "reports:\n\n"
            "```\n"
            "v=DMARC1; p=none; rua=mailto:dmarc@{domain}\n"
            "```\n\n"
            "Aggregate reports are XML and noisy — route them to a processor:\n"
            "- [Postmark DMARC Digests](https://dmarc.postmarkapp.com/) (free)\n"
            "- [dmarcian](https://dmarcian.com/)\n"
            "- [Valimail Monitor](https://www.valimail.com/products/monitor/)\n"
            "- [EasyDMARC](https://easydmarc.com/)"
        ),
    },
    "dmarc_syntax_error": {
        "title": "DMARC record has syntax errors",
        "why": (
            "Malformed DMARC records are ignored by receivers, leaving "
            "{domain} effectively unprotected and unreported."
        ),
        "fix": (
            "Validate with the [dmarcian DMARC inspector]"
            "(https://dmarcian.com/dmarc-inspector/) and fix:\n\n"
            "- Tags must be `key=value` separated by `;`\n"
            "- `v=DMARC1` must be the first tag\n"
            "- `rua=` and `ruf=` URIs must include `mailto:`\n"
            "- Only one DMARC record is allowed at `_dmarc.{domain}`"
        ),
    },

    # ============================================================
    # MTA-STS / TLS-RPT
    # ============================================================
    "no_mta_sts": {
        "title": "MTA-STS not configured",
        "why": (
            "MTA-STS forces receiving MTAs to use TLS for inbound mail to "
            "{domain}. Without it, attackers on the path can downgrade or "
            "intercept mail in transit."
        ),
        "fix": (
            "MTA-STS requires three pieces:\n\n"
            "1. DNS TXT record at `_mta-sts.{domain}`:\n"
            "   ```\n"
            "   _mta-sts.{domain}.  IN  TXT  \"v=STSv1; id=20260101000000Z\"\n"
            "   ```\n\n"
            "2. HTTPS-served policy file at `https://mta-sts.{domain}/.well-known/mta-sts.txt`:\n"
            "   ```\n"
            "   version: STSv1\n"
            "   mode: enforce\n"
            "   mx: *.mail.{domain}\n"
            "   max_age: 604800\n"
            "   ```\n\n"
            "3. Valid TLS certificate on `mta-sts.{domain}` matching the policy host\n\n"
            "Start with `mode: testing` for 1-2 weeks to confirm no breakage, "
            "then switch to `mode: enforce`. Pair with TLS-RPT (below) to get "
            "visibility into failures."
        ),
    },
    "no_tls_rpt": {
        "title": "TLS Reporting (TLS-RPT) not configured",
        "why": (
            "Without TLS-RPT, you have no visibility into TLS delivery "
            "failures or MTA-STS policy violations. Operators that configure "
            "MTA-STS without TLS-RPT are flying blind to enforcement issues."
        ),
        "fix": (
            "Publish a TLS-RPT TXT record at `_smtp._tls.{domain}`:\n\n"
            "```\n"
            "_smtp._tls.{domain}.  IN  TXT  \"v=TLSRPTv1; rua=mailto:tls-rpt@{domain}\"\n"
            "```\n\n"
            "Receiving MTAs that fail to negotiate TLS will send aggregate "
            "JSON reports to that address. Use a processor (same vendors as "
            "DMARC) to make them readable."
        ),
    },

    # ============================================================
    # DANE
    # ============================================================
    "no_dane": {
        "title": "DANE / TLSA not configured",
        "why": (
            "DANE anchors TLS certificate validation in DNSSEC. It prevents "
            "downgrade attacks and lets you assert which CAs are allowed to "
            "issue certs for your MX hosts. Required by some EU governments "
            "for inbound mail."
        ),
        "fix": (
            "DANE prerequisites:\n\n"
            "1. **DNSSEC must be enabled** on your parent zone (DANE without "
            "DNSSEC is meaningless)\n"
            "2. Generate TLSA record(s) for each MX host\n"
            "3. Publish at `_25._tcp.<mx-host>`\n\n"
            "Example for `mx.{domain}`:\n\n"
            "```\n"
            "_25._tcp.mx.{domain}.  IN  TLSA  3 1 1 <SHA256-of-cert-public-key>\n"
            "```\n\n"
            "Generate with [Mailhardener TLSA generator]"
            "(https://www.mailhardener.com/tools/tlsa-generator) or:\n\n"
            "```bash\n"
            "openssl x509 -in cert.pem -pubkey -noout |\n"
            "  openssl pkey -pubin -outform DER |\n"
            "  openssl dgst -sha256 -hex\n"
            "```\n\n"
            "Rotate TLSA records 24-48 hours before cert renewal to prevent "
            "delivery failures."
        ),
    },

    # ============================================================
    # Infrastructure hygiene
    # ============================================================
    "no_https": {
        "title": "HTTPS not available",
        "why": (
            "Without HTTPS, traffic to {domain} is unencrypted and can be "
            "intercepted or modified. Browsers and security tools penalize "
            "non-HTTPS sites in ranking and flag them as insecure."
        ),
        "fix": (
            "Get a free certificate from [Let's Encrypt](https://letsencrypt.org/) "
            "via:\n\n"
            "- **certbot** (most servers): `certbot --nginx -d {domain}`\n"
            "- **Caddy** (auto-HTTPS): zero config, just point at the domain\n"
            "- **Cloudflare** (proxy mode): free Universal SSL\n\n"
            "After install, verify with [SSL Labs]"
            "(https://www.ssllabs.com/ssltest/analyze.html?d={domain}) and aim "
            "for grade A or A+."
        ),
    },
    "no_ptr": {
        "title": "No PTR record (reverse DNS)",
        "why": (
            "Mail receivers (especially Gmail, Yahoo, Microsoft) penalize or "
            "reject mail from sending IPs without a PTR record. PTR is a "
            "table-stakes deliverability requirement."
        ),
        "fix": (
            "Configure reverse DNS for your sending IP through your hosting "
            "provider's control panel. The PTR should resolve to a hostname "
            "that itself forward-resolves back to the same IP (forward-confirmed "
            "reverse DNS, FCrDNS):\n\n"
            "```\n"
            "<your-sending-ip>  →  mail.{domain}\n"
            "mail.{domain}      →  <your-sending-ip>\n"
            "```\n\n"
            "If you're sending through a relay (SendGrid, Mailgun, etc.) "
            "this is handled by the provider — make sure you're not sending "
            "directly from a generic cloud IP."
        ),
    },
    "ptr_mismatch": {
        "title": "PTR doesn't forward-confirm",
        "why": (
            "The PTR record points to a hostname, but that hostname doesn't "
            "resolve back to the same IP. This breaks FCrDNS and triggers "
            "deliverability penalties on major receivers."
        ),
        "fix": (
            "Make sure the forward A record matches the reverse PTR:\n\n"
            "```\n"
            "<sending-ip>     PTR   mail.{domain}\n"
            "mail.{domain}    A     <sending-ip>\n"
            "```\n\n"
            "Verify with `dig -x <sending-ip>` and `dig mail.{domain} A`."
        ),
    },
    "mx_mail_prefix": {
        "title": "MX uses the `mail.{domain}` template",
        "why": (
            "`mail.{domain}` as the MX hostname is the default Hostinger / cPanel / "
            "phishing-kit pattern. By itself this is not a violation, but combined "
            "with other signals it suggests minimal infrastructure investment."
        ),
        "fix": (
            "If you operate your own mail, this is fine — but consider whether "
            "you should be running mail at all. Most organizations are better "
            "served by a managed provider (Google Workspace, Microsoft 365, "
            "Fastmail, Migadu) which handles deliverability, anti-spam, and "
            "TLS for you."
        ),
    },
}


def get_remediation(signal_name: str, domain: str = "your-domain.com") -> dict:
    """
    Look up remediation guidance for a triggered signal.

    Returns a dict with title/why/fix, or None if no guidance exists for the
    signal. The {domain} placeholder is substituted in all fields.
    """
    entry = REMEDIATIONS.get(signal_name)
    if not entry:
        return None
    return {
        "title": entry["title"].format(domain=domain),
        "why": entry["why"].format(domain=domain),
        "fix": entry["fix"].format(domain=domain),
    }


def has_remediation(signal_name: str) -> bool:
    """True if we have copy-pasteable guidance for this signal."""
    return signal_name in REMEDIATIONS
