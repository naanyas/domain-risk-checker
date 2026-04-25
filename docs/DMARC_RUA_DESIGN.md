# DMARC RUA Ingestion — Design

**Status:** Foundation + analyst MVP landed (manual ingestion). Automated receiver is the next follow-up.
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

## Decided architecture (2026-04-25)

After product discussion, the chosen approach is **vendor-aggregated
with analyst-facing UI**:

- **OneSignal centrally ingests** DMARC reports for any customer who
  points their `rua=` at an OneSignal-controlled mailbox / endpoint.
- **Storage is per-domain** — each customer's reports are scoped to
  their own domain. No cross-customer aggregation in the analyst UI.
- **Analyst-facing surfacing** — the data lives behind the admin
  password; analysts pull up a customer domain, see the rollup, and
  get prescriptive guidance for next-step recommendations.
- **Customer-actionable output** — every flagged finding ships with
  both an *analyst action checklist* and a *copy-pasteable customer
  message template* so the analyst can communicate the next step
  without composing one from scratch.
- **Path B will follow** — the long-term receiver is SES → S3 →
  Lambda. Until that lands, analysts can manually upload reports
  via the admin UI to start collecting data immediately.

## What's in this PR (analyst MVP)

- `dmarc_aggregate.py` — parser foundation (already in main from PR #6)
- `dmarc_store.py` — storage abstraction (`DmarcStore` protocol +
  `FileSystemDmarcStore` filesystem-backed implementation, JSON-on-disk,
  one file per ingested report). Designed so swapping the backend to
  SQLite / Postgres / S3 is a one-class change with zero consumer impact.
- `dmarc_remediations.py` — analyst-facing remediation registry. Each
  entry has `what_it_means` (impact assessment), `analyst_actions`
  (numbered checklist), and `customer_message` (template). `evaluate_rollup()`
  fires the entries whose detection rules match. Six entries cover:
  no_data, low/high spoofing volume, p=none with spoofing, misaligned
  legitimate sources, dominant source concentration.
- **Admin tab "📨 DMARC Analyst"** — manual upload form, domain picker,
  rollup metrics, top sources, reporting receivers, findings list with
  expanders, customer message templates ready to paste.
- **Inline summary in the per-domain analysis view** — when an analyst
  runs a normal domain analysis, if we have DMARC data for that domain
  a compact summary appears with a flagged-findings counter and a
  pointer to the full Analyst tab.
- 13 new tests in `tests/test_dmarc_store.py` covering store
  round-trips, multi-report aggregation, lookback windows, and every
  detection rule in the remediation evaluator.

## What's *still not* in this PR

These are the next concrete follow-ups, in suggested order:

1. **Automated receiver (SES → S3 → Lambda)** — replace manual upload.
   Receives DMARC aggregate emails at a single mailbox
   (`dmarc@onesignal.com` or per-customer tokens), writes to S3, Lambda
   parses + writes to the DmarcStore. Requires AWS infra setup.
2. **Per-customer `rua=` tokens** — if we want to disambiguate which
   customer a report is for without relying solely on the report's
   internal domain field, generate `dmarc-{customer-id}@onesignal.com`
   addresses. Useful when the same domain is owned by multiple
   customers (rare) or when we want to track ingest auth.
3. **DmarcStore Postgres backend** — the filesystem store is fine for
   small footprint and dev, but for production with many customers
   we'll want indexed queries and retention policies.
4. **Wire findings into Threat Surface table** — the lookalike
   surveillance UI has placeholder rows for "Display-Name Spoof
   Reports" and "Real Domain Spoofing." When automated ingestion
   lands, populate those from the rollup directly.
5. **Free webmail impersonation surveillance** — separate enumeration
   source for the third Threat Surface placeholder. Out of scope here.

## Open questions (now lower-priority, but worth deciding before #1)

- **Retention?** Reports contain source IPs and recipient counts.
  Recommend 90 days hot, then anonymize-and-archive. Confirm with
  legal/privacy.
- **Per-customer authentication?** The receiver should validate that
  inbound reports correspond to a known customer domain. Tokens
  (option 2 above) solve this elegantly.
- **Notification?** Should the analyst get a Slack message when a new
  high-severity finding fires for any monitored domain? Currently
  passive — analyst has to pull up the domain to see findings.
