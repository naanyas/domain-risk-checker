"""
Tests for dmarc_store and dmarc_remediations.

Run from the repo root:
    python -m unittest tests/test_dmarc_store.py
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dmarc_aggregate import DmarcAggregate, DmarcRecord, DmarcRollup
from dmarc_store import FileSystemDmarcStore
from dmarc_remediations import evaluate_rollup, render_no_data


FIXTURES = Path(__file__).parent / "fixtures"


class FileSystemDmarcStoreTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dmarc-store-test-")
        self.store = FileSystemDmarcStore(self.tmp)
        self.fixture = (FIXTURES / "sample_dmarc_aggregate.xml").read_bytes()

    def tearDown(self):
        # Clean up the temp directory
        for root, dirs, files in os.walk(self.tmp, topdown=False):
            for f in files:
                os.remove(os.path.join(root, f))
            for d in dirs:
                os.rmdir(os.path.join(root, d))
        os.rmdir(self.tmp)

    def test_add_and_list(self):
        storage_id = self.store.add_report(self.fixture, source="manual-upload")
        self.assertTrue(storage_id.startswith("example.com/"))
        self.assertIn("example.com", self.store.list_domains())

    def test_rollup_round_trip(self):
        # Force the report to look recent so the days_back filter passes.
        # Our fixture has window_end at 1714086000 (April 2024) which is
        # > 7d ago. We'll bypass that by storing at the current time.
        self.store.add_report(self.fixture, source="test")
        # We use days_back large enough to capture the fixture's window
        rollup = self.store.get_rollup("example.com", days_back=10000)
        self.assertEqual(rollup.total_messages, 185)
        self.assertEqual(rollup.real_domain_spoofing, 50)
        self.assertEqual(rollup.aligned_messages, 120)

    def test_rollup_empty_for_unknown_domain(self):
        rollup = self.store.get_rollup("nothing-here.com", days_back=7)
        self.assertEqual(rollup.total_messages, 0)
        self.assertEqual(rollup.real_domain_spoofing, 0)

    def test_recent_report_count(self):
        self.assertEqual(self.store.get_recent_report_count("example.com"), 0)
        self.store.add_report(self.fixture, source="test")
        # The fixture's window is too old to count under default days_back=7,
        # but it was just ingested so the ingestion-time path qualifies it.
        self.assertEqual(
            self.store.get_recent_report_count("example.com", days_back=7),
            1,
        )

    def test_multiple_reports_for_same_domain(self):
        self.store.add_report(self.fixture, source="upload-1")
        self.store.add_report(self.fixture, source="upload-2")
        rollup = self.store.get_rollup("example.com", days_back=10000)
        # Two copies of the same fixture → doubled counts
        self.assertEqual(rollup.total_messages, 370)
        self.assertEqual(rollup.real_domain_spoofing, 100)
        self.assertEqual(self.store.get_recent_report_count("example.com"), 2)


class EvaluateRollupTests(unittest.TestCase):
    """Detection logic — given a rollup, which remediations fire?"""

    def _rollup(self, **kwargs) -> DmarcRollup:
        defaults = dict(
            domain="example.com",
            total_messages=1000,
            aligned_messages=900,
            misaligned_messages=0,
            real_domain_spoofing=0,
            quarantined=0,
            rejected=0,
            sources={},
        )
        defaults.update(kwargs)
        return DmarcRollup(**defaults)

    def test_no_data_returns_empty(self):
        rollup = self._rollup(total_messages=0, aligned_messages=0)
        self.assertEqual(evaluate_rollup(rollup), [])

    def test_low_grade_spoofing_fires(self):
        rollup = self._rollup(real_domain_spoofing=50)
        names = [r["name"] for r in evaluate_rollup(rollup)]
        self.assertIn("low_grade_spoofing", names)
        self.assertNotIn("high_spoofing_volume", names)

    def test_high_spoofing_volume_fires(self):
        rollup = self._rollup(
            real_domain_spoofing=2000,
            quarantined=2000,
            total_messages=3000,
            aligned_messages=900,
        )
        names = [r["name"] for r in evaluate_rollup(rollup)]
        self.assertIn("high_spoofing_volume", names)
        self.assertNotIn("low_grade_spoofing", names)

    def test_p_none_heuristic_fires_when_enforcement_weak(self):
        # 500 spoofs, 0 rejected → enforcement is clearly p=none / weak
        rollup = self._rollup(
            real_domain_spoofing=500,
            quarantined=0,
            rejected=0,
        )
        names = [r["name"] for r in evaluate_rollup(rollup)]
        self.assertIn("p_none_with_spoofing", names)

    def test_p_none_heuristic_does_not_fire_when_rejecting(self):
        # 500 spoofs, 400 rejected → enforcement is active
        rollup = self._rollup(
            real_domain_spoofing=500,
            rejected=400,
        )
        names = [r["name"] for r in evaluate_rollup(rollup)]
        self.assertNotIn("p_none_with_spoofing", names)

    def test_misaligned_threshold(self):
        # 5% misaligned should fire
        rollup = self._rollup(
            total_messages=1000,
            misaligned_messages=50,
            aligned_messages=950,
        )
        names = [r["name"] for r in evaluate_rollup(rollup)]
        self.assertIn("misaligned_legitimate_sources", names)

        # 1% misaligned should not
        rollup = self._rollup(
            total_messages=1000,
            misaligned_messages=10,
            aligned_messages=990,
        )
        names = [r["name"] for r in evaluate_rollup(rollup)]
        self.assertNotIn("misaligned_legitimate_sources", names)

    def test_dominant_source_concentration(self):
        rollup = self._rollup(
            total_messages=1000,
            aligned_messages=900,
            sources={"1.2.3.4": 950, "5.6.7.8": 50},
        )
        rendered = evaluate_rollup(rollup)
        names = [r["name"] for r in rendered]
        self.assertIn("dominant_source_concentration", names)
        # Variable substitution worked
        dom_entry = next(r for r in rendered if r["name"] == "dominant_source_concentration")
        self.assertIn("1.2.3.4", dom_entry["what_it_means"])
        self.assertIn("95.0%", dom_entry["what_it_means"])

    def test_no_data_renderer(self):
        rendered = render_no_data("acme.com")
        self.assertEqual(rendered["name"], "no_data")
        self.assertIn("acme.com", rendered["what_it_means"])
        self.assertIn("rua=mailto:dmarc@onesignal.com", rendered["customer_message"])


if __name__ == "__main__":
    unittest.main()
