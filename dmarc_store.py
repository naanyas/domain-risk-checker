"""
DMARC report storage abstraction.

Pluggable interface so the storage backend can evolve without touching
consumers. The MVP backend is FileSystemDmarcStore — JSON-on-disk, one
file per ingested report, keyed by domain + ingestion timestamp.

Successor backends (SQLite, Postgres, S3) only need to satisfy the
DmarcStore protocol below.

Usage:
    store = FileSystemDmarcStore("data/dmarc")
    store.add_report(report_bytes, source="manual-upload")
    rollup = store.get_rollup("example.com", days_back=7)
"""

import json
import os
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, List, Optional, Protocol

from dmarc_aggregate import (
    DmarcAggregate,
    DmarcRecord,
    DmarcReportMetadata,
    DmarcPolicyPublished,
    DmarcAuthResult,
    DmarcRollup,
    parse_aggregate_report,
    rollup_records,
)


# ============================================================================
# Storage protocol
# ============================================================================

class DmarcStore(Protocol):
    """
    Minimal interface every backend must satisfy. Anything more elaborate
    (per-customer auth, retention policies, archival) is a backend concern.
    """

    def add_report(self, raw_bytes: bytes, source: str = "") -> str:
        """
        Parse `raw_bytes` and persist the report. Returns a storage ID
        (filename / DB key / etc.) the caller can use for audit logging.
        """
        ...

    def list_domains(self) -> List[str]:
        """All domains we have reports for."""
        ...

    def get_rollup(self, domain: str, days_back: int = 7) -> DmarcRollup:
        """
        Aggregate reports for `domain` whose time window overlaps the last
        `days_back` days. Returns an empty rollup if no matching reports.
        """
        ...

    def get_recent_report_count(self, domain: str, days_back: int = 7) -> int:
        """Number of distinct reports stored for the domain within the window."""
        ...


# ============================================================================
# Reconstruction helpers — JSON ↔ DmarcAggregate
# ============================================================================

def _aggregate_to_dict(report: DmarcAggregate) -> dict:
    """asdict() handles the dataclass tree natively."""
    return asdict(report)


def _aggregate_from_dict(d: dict) -> DmarcAggregate:
    """Reverse of asdict — required because asdict drops the type info."""
    meta_d = d.get("metadata", {}) or {}
    pol_d = d.get("policy", {}) or {}
    metadata = DmarcReportMetadata(**meta_d)
    policy = DmarcPolicyPublished(**pol_d)
    records: List[DmarcRecord] = []
    for r in d.get("records", []) or []:
        auth = [DmarcAuthResult(**a) for a in r.get("auth_results", []) or []]
        records.append(DmarcRecord(
            source_ip=r.get("source_ip", ""),
            count=r.get("count", 0),
            disposition=r.get("disposition", ""),
            dkim_aligned=r.get("dkim_aligned", False),
            spf_aligned=r.get("spf_aligned", False),
            header_from=r.get("header_from", ""),
            envelope_from=r.get("envelope_from", ""),
            envelope_to=r.get("envelope_to", ""),
            auth_results=auth,
        ))
    return DmarcAggregate(metadata=metadata, policy=policy, records=records)


# ============================================================================
# Filesystem backend (MVP)
# ============================================================================

class FileSystemDmarcStore:
    """
    Stores parsed reports as JSON under <root>/<domain>/<storage_id>.json.

    Layout:
        data/dmarc/
            example.com/
                2026-04-25T10-15-22-abc123.json
                2026-04-25T11-02-08-def456.json
            other.com/
                ...

    Each JSON file contains the parsed DmarcAggregate plus an ingestion
    envelope:
        {
          "ingested_at": <unix_ts>,
          "source": "manual-upload" / "smtp-receiver" / etc.,
          "report": <DmarcAggregate as dict>
        }

    Concurrency: file-per-report avoids the lost-update problem. Two
    analysts uploading simultaneously each get their own file.
    """

    def __init__(self, root: str = "data/dmarc"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # --------- ingestion ---------

    def add_report(self, raw_bytes: bytes, source: str = "") -> str:
        report = parse_aggregate_report(raw_bytes)
        domain = (report.policy.domain or "unknown").lower().rstrip(".")
        domain_dir = self.root / self._safe_domain(domain)
        domain_dir.mkdir(parents=True, exist_ok=True)

        ingest_ts = int(time.time())
        # Filename: ISO-ish timestamp + short uuid for uniqueness under load
        ts_part = time.strftime("%Y-%m-%dT%H-%M-%S", time.gmtime(ingest_ts))
        storage_id = f"{ts_part}-{uuid.uuid4().hex[:8]}.json"
        filepath = domain_dir / storage_id

        envelope = {
            "ingested_at": ingest_ts,
            "source": source or "unknown",
            "report": _aggregate_to_dict(report),
        }
        # Atomic write: write to .tmp then rename
        tmp = filepath.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(envelope, indent=2))
        tmp.rename(filepath)
        return str(filepath.relative_to(self.root))

    # --------- queries ---------

    def list_domains(self) -> List[str]:
        if not self.root.exists():
            return []
        return sorted(
            self._unsafe_domain(p.name)
            for p in self.root.iterdir()
            if p.is_dir() and any(p.iterdir())
        )

    def get_rollup(self, domain: str, days_back: int = 7) -> DmarcRollup:
        cutoff = int(time.time()) - (days_back * 86400)
        reports = list(self._iter_reports(domain, cutoff))
        if not reports:
            empty = DmarcRollup(domain=domain.lower().rstrip("."))
            return empty
        return rollup_records(reports)

    def get_recent_report_count(self, domain: str, days_back: int = 7) -> int:
        cutoff = int(time.time()) - (days_back * 86400)
        return sum(1 for _ in self._iter_reports(domain, cutoff))

    # --------- internal ---------

    def _iter_reports(self, domain: str, cutoff_ts: int) -> Iterable[DmarcAggregate]:
        domain_dir = self.root / self._safe_domain(domain.lower().rstrip("."))
        if not domain_dir.exists():
            return
        for filepath in sorted(domain_dir.glob("*.json")):
            try:
                envelope = json.loads(filepath.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            # Filter on either ingest time OR report time-window end —
            # whichever is later (some receivers send reports days after
            # the window closes).
            ingest_ts = envelope.get("ingested_at", 0) or 0
            report_dict = envelope.get("report", {}) or {}
            window_end = (
                report_dict.get("metadata", {}) or {}
            ).get("date_range_end", 0) or 0
            most_recent = max(ingest_ts, window_end)
            if most_recent < cutoff_ts:
                continue
            yield _aggregate_from_dict(report_dict)

    @staticmethod
    def _safe_domain(domain: str) -> str:
        """Replace path separators / problematic chars in directory names."""
        return domain.replace("/", "_").replace("\\", "_")

    @staticmethod
    def _unsafe_domain(safe: str) -> str:
        """Inverse of _safe_domain — no-op today, hook for future encoding."""
        return safe
