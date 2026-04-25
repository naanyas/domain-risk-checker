"""
DMARC aggregate parser tests.

Run from the repo root:
    python -m unittest tests/test_dmarc_aggregate.py

Or just:
    python tests/test_dmarc_aggregate.py
"""

import gzip
import io
import sys
import unittest
import zipfile
from pathlib import Path

# Make the repo root importable when running tests directly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dmarc_aggregate import (
    DmarcAggregate,
    DmarcRecord,
    parse_aggregate_report,
    rollup_records,
    top_sources,
)


FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class ParseAggregateReportTests(unittest.TestCase):

    def test_parses_plain_xml(self):
        report = parse_aggregate_report(_fixture_bytes("sample_dmarc_aggregate.xml"))
        self.assertEqual(report.metadata.org_name, "google.com")
        self.assertEqual(report.metadata.email, "noreply-dmarc-support@google.com")
        self.assertEqual(report.metadata.report_id, "example-001-1714000000")
        self.assertEqual(report.metadata.date_range_begin, 1713999600)
        self.assertEqual(report.policy.domain, "example.com")
        self.assertEqual(report.policy.p, "quarantine")
        self.assertEqual(len(report.records), 4)

    def test_parses_gzipped_xml(self):
        raw = _fixture_bytes("sample_dmarc_aggregate.xml")
        compressed = gzip.compress(raw)
        report = parse_aggregate_report(compressed)
        self.assertEqual(len(report.records), 4)
        self.assertEqual(report.policy.domain, "example.com")

    def test_parses_zipped_xml(self):
        raw = _fixture_bytes("sample_dmarc_aggregate.xml")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("report.xml", raw)
        report = parse_aggregate_report(buf.getvalue())
        self.assertEqual(len(report.records), 4)

    def test_record_fields_populated(self):
        report = parse_aggregate_report(_fixture_bytes("sample_dmarc_aggregate.xml"))
        # First record: aligned legitimate mail
        first = report.records[0]
        self.assertEqual(first.source_ip, "209.85.220.41")
        self.assertEqual(first.count, 120)
        self.assertTrue(first.dkim_aligned)
        self.assertTrue(first.spf_aligned)
        self.assertEqual(first.disposition, "none")
        # Auth results captured
        self.assertEqual(len(first.auth_results), 2)
        dkim = next(r for r in first.auth_results if r.type == "dkim")
        self.assertEqual(dkim.selector, "google")

    def test_rejects_malformed_xml(self):
        with self.assertRaises(ValueError):
            parse_aggregate_report(b"<not really xml at all")

    def test_rejects_wrong_root_element(self):
        with self.assertRaises(ValueError):
            parse_aggregate_report(b"<?xml version='1.0'?><wrong_root/>")


class RollupTests(unittest.TestCase):

    def setUp(self):
        self.report = parse_aggregate_report(
            _fixture_bytes("sample_dmarc_aggregate.xml")
        )

    def test_rollup_counts(self):
        rollup = rollup_records([self.report])
        # 120 (aligned) + 15 (misaligned) + 42 (spoof) + 8 (spoof) = 185
        self.assertEqual(rollup.total_messages, 185)
        self.assertEqual(rollup.aligned_messages, 120)
        self.assertEqual(rollup.misaligned_messages, 15)
        # Both 42 and 8 had dkim_aligned=False AND spf_aligned=False
        self.assertEqual(rollup.real_domain_spoofing, 50)
        self.assertEqual(rollup.quarantined, 42)
        self.assertEqual(rollup.rejected, 8)
        self.assertEqual(rollup.domain, "example.com")
        self.assertEqual(rollup.reporting_orgs, ["google.com"])

    def test_rollup_window(self):
        rollup = rollup_records([self.report])
        self.assertEqual(rollup.window_begin, 1713999600)
        self.assertEqual(rollup.window_end, 1714086000)

    def test_rollup_combines_multiple_reports(self):
        rollup = rollup_records([self.report, self.report])
        # Doubled
        self.assertEqual(rollup.total_messages, 370)
        self.assertEqual(rollup.real_domain_spoofing, 100)

    def test_top_sources(self):
        rollup = rollup_records([self.report])
        top = top_sources(rollup, limit=3)
        # Sorted by count: 120, 42, 15, 8 → top 3 are 120/42/15
        self.assertEqual(len(top), 3)
        self.assertEqual(top[0]["source_ip"], "209.85.220.41")
        self.assertEqual(top[0]["count"], 120)
        self.assertEqual(top[1]["source_ip"], "185.220.101.45")
        self.assertEqual(top[1]["count"], 42)


if __name__ == "__main__":
    unittest.main()
