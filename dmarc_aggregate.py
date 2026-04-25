"""
DMARC aggregate report (RUA) parser — RFC 7489 §7.2.

Pure-Python parser that takes the raw bytes of a DMARC aggregate report
(gzip / zip / plain XML — auto-detected) and returns structured records
the rest of SDAT can roll up and surface.

This module is intentionally consumer-agnostic. It does not know or care
where the bytes came from (SMTP attachment, S3 object, processor API
response, fixture in a test) — it only converts bytes → dataclass.

See docs/DMARC_RUA_DESIGN.md for the broader ingestion architecture
and the design questions still pending product input.

Schema reference:
  https://www.iana.org/assignments/dmarc-parameters/dmarc-parameters.xhtml
  https://datatracker.ietf.org/doc/html/rfc7489#section-7.2
"""

import gzip
import io
import zipfile
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional
from xml.etree import ElementTree as ET


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class DmarcReportMetadata:
    """The <report_metadata> block — who reported, what window, contact."""
    org_name: str = ""           # Reporting org (e.g. "google.com")
    email: str = ""              # Reporter contact
    report_id: str = ""          # Reporter's unique ID for the report
    date_range_begin: int = 0    # Unix timestamp
    date_range_end: int = 0      # Unix timestamp


@dataclass
class DmarcPolicyPublished:
    """The <policy_published> block — what the analyzed domain's DMARC said."""
    domain: str = ""             # Reported-on domain
    adkim: str = ""              # DKIM alignment mode (r/s)
    aspf: str = ""               # SPF alignment mode (r/s)
    p: str = ""                  # Policy (none/quarantine/reject)
    sp: str = ""                 # Subdomain policy
    pct: int = 100               # Sampling percentage


@dataclass
class DmarcAuthResult:
    """A single SPF or DKIM auth result row inside a <record>."""
    type: str = ""               # "spf" or "dkim"
    domain: str = ""             # Domain that signed / authenticated
    result: str = ""             # pass/fail/neutral/softfail/temperror/permerror
    selector: str = ""           # DKIM selector (DKIM only)


@dataclass
class DmarcRecord:
    """A single <record> — one per (source IP × auth result) combo."""
    source_ip: str = ""
    count: int = 0               # Message count for this record
    disposition: str = ""        # none / quarantine / reject (what receiver did)
    dkim_aligned: bool = False
    spf_aligned: bool = False
    header_from: str = ""        # Domain in From: header
    envelope_from: str = ""      # Domain in MAIL FROM
    envelope_to: str = ""        # Domain in RCPT TO
    auth_results: List[DmarcAuthResult] = field(default_factory=list)


@dataclass
class DmarcAggregate:
    """One full aggregate report — metadata + policy + N records."""
    metadata: DmarcReportMetadata = field(default_factory=DmarcReportMetadata)
    policy: DmarcPolicyPublished = field(default_factory=DmarcPolicyPublished)
    records: List[DmarcRecord] = field(default_factory=list)


# ============================================================================
# Decompression — gzip / zip / plain auto-detect
# ============================================================================

def _decompress(blob: bytes) -> bytes:
    """
    Return raw XML bytes from a possibly-compressed DMARC report.

    Supports:
      • gzip (.xml.gz — most common)
      • zip  (.xml.zip — older receivers, some Microsoft variants)
      • plain XML (no compression)

    Detection is by magic bytes; falls back to "treat as XML" if no
    compression signature is present.
    """
    # gzip magic: 1f 8b
    if len(blob) >= 2 and blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob)

    # zip magic: PK\x03\x04
    if len(blob) >= 4 and blob[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            names = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            if not names:
                # Fallback: take the first non-directory entry
                names = [n for n in zf.namelist() if not n.endswith("/")]
            if not names:
                raise ValueError("ZIP archive contains no readable entries")
            with zf.open(names[0]) as f:
                return f.read()

    # Assume plain XML
    return blob


# ============================================================================
# Element-tree helpers (XML namespace-tolerant)
# ============================================================================

def _localname(tag: str) -> str:
    """Strip namespace from an ElementTree tag — '{ns}foo' → 'foo'."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _findtext(elem: Optional[ET.Element], path: str, default: str = "") -> str:
    """Namespace-tolerant findtext via local-name walk."""
    if elem is None:
        return default
    for part in path.split("/"):
        if elem is None:
            return default
        for child in list(elem):
            if _localname(child.tag) == part:
                elem = child
                break
        else:
            return default
    return (elem.text or default).strip() if elem is not None else default


def _findall(elem: Optional[ET.Element], local_name: str) -> List[ET.Element]:
    """Find all direct children matching a local name (namespace-tolerant)."""
    if elem is None:
        return []
    return [c for c in list(elem) if _localname(c.tag) == local_name]


def _find(elem: Optional[ET.Element], local_name: str) -> Optional[ET.Element]:
    """Find first direct child matching a local name."""
    if elem is None:
        return None
    for c in list(elem):
        if _localname(c.tag) == local_name:
            return c
    return None


# ============================================================================
# Parser
# ============================================================================

def parse_aggregate_report(blob: bytes) -> DmarcAggregate:
    """
    Parse a DMARC aggregate report from raw bytes.

    Accepts gzip, zip, or plain XML. Returns a populated DmarcAggregate.

    Raises ValueError on malformed input.
    """
    xml_bytes = _decompress(blob)

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"Malformed DMARC aggregate XML: {exc}") from exc

    if _localname(root.tag) != "feedback":
        raise ValueError(
            f"Expected <feedback> root element, got <{_localname(root.tag)}>"
        )

    aggregate = DmarcAggregate()

    # --- Metadata ---
    meta_elem = _find(root, "report_metadata")
    if meta_elem is not None:
        aggregate.metadata.org_name = _findtext(meta_elem, "org_name")
        aggregate.metadata.email = _findtext(meta_elem, "email")
        aggregate.metadata.report_id = _findtext(meta_elem, "report_id")
        date_range = _find(meta_elem, "date_range")
        if date_range is not None:
            try:
                aggregate.metadata.date_range_begin = int(_findtext(date_range, "begin", "0"))
                aggregate.metadata.date_range_end = int(_findtext(date_range, "end", "0"))
            except ValueError:
                pass

    # --- Policy published ---
    pol_elem = _find(root, "policy_published")
    if pol_elem is not None:
        aggregate.policy.domain = _findtext(pol_elem, "domain")
        aggregate.policy.adkim = _findtext(pol_elem, "adkim")
        aggregate.policy.aspf = _findtext(pol_elem, "aspf")
        aggregate.policy.p = _findtext(pol_elem, "p")
        aggregate.policy.sp = _findtext(pol_elem, "sp")
        try:
            aggregate.policy.pct = int(_findtext(pol_elem, "pct", "100"))
        except ValueError:
            aggregate.policy.pct = 100

    # --- Records ---
    for rec_elem in _findall(root, "record"):
        record = DmarcRecord()
        row = _find(rec_elem, "row")
        if row is not None:
            record.source_ip = _findtext(row, "source_ip")
            try:
                record.count = int(_findtext(row, "count", "0"))
            except ValueError:
                record.count = 0
            policy_eval = _find(row, "policy_evaluated")
            if policy_eval is not None:
                record.disposition = _findtext(policy_eval, "disposition")
                record.dkim_aligned = _findtext(policy_eval, "dkim").lower() == "pass"
                record.spf_aligned = _findtext(policy_eval, "spf").lower() == "pass"

        identifiers = _find(rec_elem, "identifiers")
        if identifiers is not None:
            record.header_from = _findtext(identifiers, "header_from")
            record.envelope_from = _findtext(identifiers, "envelope_from")
            record.envelope_to = _findtext(identifiers, "envelope_to")

        auth_results = _find(rec_elem, "auth_results")
        if auth_results is not None:
            for spf_elem in _findall(auth_results, "spf"):
                record.auth_results.append(DmarcAuthResult(
                    type="spf",
                    domain=_findtext(spf_elem, "domain"),
                    result=_findtext(spf_elem, "result"),
                ))
            for dkim_elem in _findall(auth_results, "dkim"):
                record.auth_results.append(DmarcAuthResult(
                    type="dkim",
                    domain=_findtext(dkim_elem, "domain"),
                    result=_findtext(dkim_elem, "result"),
                    selector=_findtext(dkim_elem, "selector"),
                ))

        aggregate.records.append(record)

    return aggregate


# ============================================================================
# Rollups — what we surface in the UI
# ============================================================================

@dataclass
class DmarcRollup:
    """
    Summarized stats across one or more aggregate reports.

    These are the numbers that feed the Threat Surface table:
      total_messages              — overall volume
      aligned_messages            — passed DMARC (legitimate)
      real_domain_spoofing        — failed both SPF and DKIM (genuine spoof)
      misaligned_messages         — passed one but not aligned (config drift
                                    OR display-name spoof attempt)
      sources                     — top source IPs by volume
      reporting_orgs              — set of receivers that submitted reports
      window_begin / window_end   — time range covered (Unix timestamps)
    """
    domain: str = ""
    total_messages: int = 0
    aligned_messages: int = 0
    real_domain_spoofing: int = 0
    misaligned_messages: int = 0
    quarantined: int = 0
    rejected: int = 0
    sources: Dict[str, int] = field(default_factory=dict)  # ip → count
    reporting_orgs: List[str] = field(default_factory=list)
    window_begin: int = 0
    window_end: int = 0


def rollup_records(reports: Iterable[DmarcAggregate]) -> DmarcRollup:
    """
    Aggregate one or more DmarcAggregate reports into a single rollup.

    The rollup is what we display — individual reports are noise.
    """
    rollup = DmarcRollup()
    domains_seen = set()
    orgs_seen = set()

    for report in reports:
        if report.policy.domain:
            domains_seen.add(report.policy.domain.lower())
        if report.metadata.org_name:
            orgs_seen.add(report.metadata.org_name)

        # Track widest time window across all reports
        if report.metadata.date_range_begin and (
            rollup.window_begin == 0
            or report.metadata.date_range_begin < rollup.window_begin
        ):
            rollup.window_begin = report.metadata.date_range_begin
        if report.metadata.date_range_end > rollup.window_end:
            rollup.window_end = report.metadata.date_range_end

        for record in report.records:
            rollup.total_messages += record.count

            if record.dkim_aligned or record.spf_aligned:
                if record.dkim_aligned and record.spf_aligned:
                    rollup.aligned_messages += record.count
                else:
                    rollup.misaligned_messages += record.count
            else:
                # Both failed — genuine domain spoofing attempt
                rollup.real_domain_spoofing += record.count

            if record.disposition == "quarantine":
                rollup.quarantined += record.count
            elif record.disposition == "reject":
                rollup.rejected += record.count

            if record.source_ip:
                rollup.sources[record.source_ip] = (
                    rollup.sources.get(record.source_ip, 0) + record.count
                )

    # If all reports cover the same domain, surface it on the rollup
    if len(domains_seen) == 1:
        rollup.domain = next(iter(domains_seen))
    rollup.reporting_orgs = sorted(orgs_seen)
    return rollup


def top_sources(rollup: DmarcRollup, limit: int = 10) -> List[Dict]:
    """Return the top N source IPs by message count, formatted for display."""
    items = sorted(rollup.sources.items(), key=lambda kv: kv[1], reverse=True)
    return [{"source_ip": ip, "count": count} for ip, count in items[:limit]]
