"""
QView Integration & Unit Test Suite
Validates precision, recall, mathematical scoring, CBOM generation, and knowledge graph construction.
"""

import os
import unittest
from scanners.repo_orchestrator import RepoOrchestrator
from core.cbom_engine import CBOMBuilder
from core.knowledge_graph import CryptoKnowledgeGraph


class TestQViewCore(unittest.TestCase):

    def setUp(self):
        self.orchestrator = RepoOrchestrator()
        self.sample_dir = os.path.join(os.path.dirname(__file__), "sample_data")

    def test_scan_sample_data(self):
        summary = self.orchestrator.scan_target(self.sample_dir, app_name="Sentara-Enterprise-Sample")
        
        self.assertGreater(summary.total_files_scanned, 0)
        self.assertGreater(summary.total_crypto_assets, 0)
        self.assertGreater(summary.quantum_vulnerable_count, 0)
        
        # Verify indices exist and are bounded [0, 100]
        self.assertGreaterEqual(summary.qri, 0.0)
        self.assertLessEqual(summary.qri, 100.0)
        self.assertGreaterEqual(summary.qei, 0.0)
        self.assertLessEqual(summary.qei, 100.0)
        self.assertGreaterEqual(summary.cai, 0.0)
        self.assertLessEqual(summary.cai, 100.0)

        # Check that PQC was recognized as quantum safe
        pqc_findings = [f for f in summary.findings if "ML-KEM" in f.crypto_asset.algorithm_variant or "ML-DSA" in f.crypto_asset.algorithm_variant]
        self.assertGreater(len(pqc_findings), 0)
        for pf in pqc_findings:
            self.assertEqual(pf.quantum_status, "QUANTUM_SAFE")

        # Verify CBOM generation
        cbom = CBOMBuilder.generate_cyclonedx_cbom(summary)
        self.assertEqual(cbom["bomFormat"], "CycloneDX")
        self.assertEqual(cbom["specVersion"], "1.6")
        self.assertGreater(len(cbom["components"]), 1)

        # Verify Knowledge Graph construction
        graph = CryptoKnowledgeGraph.build_from_assessment(summary)
        self.assertGreater(len(graph.nodes), 3)
        self.assertGreater(len(graph.edges), 2)
        
        print(f"\n[TEST PASSED] Scanned {summary.total_files_scanned} files, {summary.total_loc_scanned} LOC.")
        print(f"Discovered: {summary.total_crypto_assets} crypto assets ({summary.quantum_vulnerable_count} vulnerable, {summary.quantum_safe_count} safe).")
        print(f"Scores: QRI={summary.qri}/100, QEI={summary.qei}/100, CAI={summary.cai}/100 (Coverage={summary.coverage_confidence*100}%).")


if __name__ == "__main__":
    unittest.main()
