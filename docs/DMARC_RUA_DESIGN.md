# DMARC RUA Ingestion — Design

**Status:** Draft (foundation landed; ingestion path TBD)
**Owners:** Jenna Webb, Andy King
**Last updated:** 2026-04-25

---

## What problem we're solving

The lookalike Threat Surface UI has three placeholder rows that depend on
data SDAT doesn't currently have access to:

- **Display-Name Spoof Reports** — counts of mail with the analyzed
  domain's brand in the friendly name but a different envelope domain
- **Real Domain Spoofing** — counts of mail with the analyzed domain in
  `header-from` that fail SPF *and* DKIM (genuine spoofing attempts)
- **Free Webmail Impersonation** — counts of mail from free providers
  (gmail.com, yahoo.com, etc.) using the brand name as the local part

DMARC aggregate reports (RFC 7489 §7.2, "RUA") would populate the first
two of these for any domain the operator owns. The third — webmail
impersonation — needs a separate enumeration source and is out of scope
for this design.

## What DMARC RUA reports look like

Receivers (Google, Yahoo, Microsoft, Comcast, etc.) generate aggregate
reports daily, gzip them, and email them as attachments to the
`rua=mailto:...` address in the analyzed domain's DMARC record.

A typical day's reports for a moderately-sized sender:

- 5–50 individual reports (one per receiving organization)
- 100–10,000 records per report
- Each record: source IP + count + disposition + SPF/DKIM aligned booleans
- Compressed: ~5–500 KB per report, ~1–50 MB raw XML

Schema reference: <https://www.iana.org/assignments/dmarc-parameters/dmarc-parameters.xhtml>

## Two ingestion paths

### Path A: Read-only consumer of a DMARC processor

SDAT doesn't host its own report receiver. Instead, it queries a third-party
processor (Postmark Digests, dmarcian, Valimail Monitor, EasyDMARC) for the
analyzed domain's recent aggregate stats.

**Pros:**
- Zero infrastructure on our side
- Mature parsers, normalized data
- 24-hour rollups already computed

**Cons:**
- Customer must already use one of those processors
- Per-processor integration code — the API surface differs across vendors
- Only works for domains the customer has registered with the processor
- Free-tier rate limits at the processor

**Recommended starter:** Postmark Digests has a free tier and a
JSON API. Single integration, low setup friction.

### Path B: Self-hosted receiver

SDAT operates an SMTP inbox (or S3 + Lambda receiving via SES) that
receives DMARC aggregate reports directly. We unzip, parse, store
per-domain rollups in a database, and surface them at analysis time.

**Pros:**
- No third-party dependency
- Full control over retention, privacy, schema evolution
- Works for any domain whose DMARC `rua=` is pointed at our endpoint
- Can ingest historical data on demand

**Cons:**
- Real infrastructure: SMTP server, S3 bucket, parser job, database,
  retention policy, alerting
- Operational burden — DMARC traffic is constant, parser drift is real
- Customer must update their DMARC record to point at our endpoint
  (gating on us being a trusted recipient)

## Recommendation

**Start with Path A using Postmark Digests.** Time-to-value is days, not
weeks. The XML parser foundation built in this PR is reusable when we
later move to Path B.

The processor-API integration is a thin client that:

1. Reads an API key from env / secrets
2. For each analyzed domain, queries the processor's aggregate-stats endpoint
3. Maps the response into the same `DmarcAggregate` rollup struct the
   self-hosted parser produces
4. Surfaces the result in the Threat Surface UI

If OneSignal needs domain coverage beyond what customers register with
Postmark, *then* invest in Path B.

## Open product questions

1. **Whose reports?** SDAT can only see DMARC data for domains the
   operator has access to. Do we surface this as a customer-portal
   feature (only shows data for their own domains) or a vendor-side
   view (OneSignal centrally collects for all customers via shared
   `rua=`)? The latter is a much bigger commitment.

2. **Data retention?** DMARC reports include source IPs and recipient
   counts. Most processors retain 30–90 days. What's our policy?

3. **Display when no data?** Today the UI shows "⏳ Requires DMARC RUA
   ingestion." When ingestion is wired but a domain has no data,
   what do we show? "Not yet collecting" vs "No spoofing detected
   in last 30 days" carry different implications.

4. **Surface in admin or user view?** DMARC stats are operationally
   sensitive (they reveal who's sending mail "as" the domain). Probably
   admin-only, but worth confirming.

5. **Aggregation window?** Last 24h, 7d, 30d? Default 7d feels right —
   long enough for stable trends, short enough to be actionable.

## What's in this PR (foundation only)

- `dmarc_aggregate.py` — pure-Python parser for RUA aggregate reports
  - Accepts raw bytes (gzip / zip / plain XML auto-detected)
  - Returns `DmarcAggregate` (per-report) and `DmarcRecord` (per-row) dataclasses
  - `rollup_records()` aggregates records by source IP / disposition
- `tests/test_dmarc_aggregate.py` — fixture-based round-trip test
- This design doc

The parser is consumer-agnostic: whether ingestion comes from Path A
or Path B, the same struct ends up surfaced in the UI.

## What's *not* in this PR

- No ingestion path (no SMTP server, no Postmark API client, no S3 receiver)
- No storage layer (rollups are computed in-memory per analysis)
- No UI changes — Threat Surface placeholders stay as-is until ingestion
  is decided
- No DomainApprovalResult fields yet — added in a follow-up after the
  ingestion path is chosen

## Follow-up PRs (in suggested order)

1. **DMARC processor client** (Path A) — Postmark Digests API client,
   surfaces stats in Threat Surface UI. Replaces 2 of 3 placeholders.
2. **Customer-managed RUA token** — generate a unique `rua=mailto:` per
   customer if we go Path B, plus a configuration UI for the customer
   to update their DMARC record.
3. **SES → S3 → Lambda receiver** (Path B) — only if processor coverage
   isn't enough.
4. **Free webmail impersonation surveillance** — separate enumeration
   source (HIBP-style, or Google Postmaster Tools), populates the third
   placeholder row.
