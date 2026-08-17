"""
QView Assessment Orchestrator v2
Coordinates asset discovery, multi-scanner execution (code, cert, dependency,
secrets, network), finding deduplication, compliance mapping, PQC wave planning,
and mathematical score calculation (QEI, QRI, CAI, Mosca's Inequality).
"""

import os
import zipfile
import tempfile
import shutil
import json
from typing import List, Optional
from core.models import AssessmentSummary, CryptoFinding
from core.scoring_engine import ScoringEngine
from core.migration_planner import MigrationPlanner
from core.compliance_engine import ComplianceEngine
from scanners.code_scanner import CodeScanner
from scanners.certificate_scanner import CertificateScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.secrets_scanner import SecretsScanner
from scanners.network_scanner import NetworkScanner
from scanners.cloud_scanner import CloudCryptoScanner


class RepoOrchestrator:
    """Master orchestrator: discovers targets, runs all scanners, scores and reports."""

    IGNORE_DIRS = {
        ".git", ".svn", ".hg", "node_modules", "vendor",
        "venv", ".venv", "env", "__pycache__", ".idea",
        ".vscode", "target", "build", "dist", ".gradle",
        ".next", ".nuxt", "coverage", ".cache"
    }

    def __init__(self):
        self.code_scanner    = CodeScanner()
        self.cert_scanner    = CertificateScanner()
        self.dep_scanner     = DependencyScanner()
        self.secrets_scanner = SecretsScanner()
        self.net_scanner     = NetworkScanner()
        self.cloud_scanner   = CloudCryptoScanner()

    def scan_target(
        self,
        target_path: str,
        app_name: Optional[str] = None,
        tls_endpoints: Optional[List[str]] = None,
        coverage_pct: float = 0.92,
    ) -> AssessmentSummary:
        """
        Scan a file, directory, or ZIP archive.
        Optionally probe TLS endpoints.
        Returns a fully scored AssessmentSummary.
        """
        target_path = os.path.abspath(target_path)
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        name = app_name or os.path.basename(target_path)
        summary = AssessmentSummary(target_name=name, target_path=target_path)

        temp_dir = None
        scan_root = target_path

        # ── Handle ZIP archives ──────────────────────────────────────────────
        if os.path.isfile(target_path) and target_path.lower().endswith(".zip"):
            temp_dir = tempfile.mkdtemp(prefix="qview_scan_")
            with zipfile.ZipFile(target_path, 'r') as zf:
                # Security: prevent path traversal in ZIP extraction
                for member in zf.infolist():
                    member_path = os.path.realpath(os.path.join(temp_dir, member.filename))
                    if not member_path.startswith(os.path.realpath(temp_dir)):
                        continue  # Skip path traversal attempts
                zf.extractall(temp_dir)
            scan_root = temp_dir

        try:
            findings: List[CryptoFinding] = []
            file_count = 0
            loc_count = 0

            # ── Filesystem scan ──────────────────────────────────────────────
            if os.path.isfile(scan_root):
                file_count = 1
                loc_count = self._count_lines(scan_root)
                findings.extend(self._scan_single_file(scan_root, name))
            else:
                for root, dirs, files in os.walk(scan_root):
                    dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS]
                    for fn in files:
                        full_path = os.path.join(root, fn)
                        file_count += 1
                        loc_count += self._count_lines(full_path)
                        findings.extend(self._scan_single_file(full_path, name))

            # ── TLS Endpoint probing ─────────────────────────────────────────
            if tls_endpoints:
                for endpoint in tls_endpoints:
                    try:
                        host, _, port_str = endpoint.rpartition(":")
                        port = int(port_str) if port_str.isdigit() else 443
                        ep_findings = self.net_scanner.scan_tls_endpoint(host, port, app_name=name)
                        findings.extend(ep_findings)
                    except Exception:
                        pass

            # ── Assign assessment_id and app metadata to all findings ────────
            for f in findings:
                f.assessment_id = summary.assessment_id
                if not f.app_name or f.app_name == "Default Application":
                    f.app_name = name

            # ── Deduplication (file + line + algorithm) ──────────────────────
            unique_findings: List[CryptoFinding] = []
            seen = set()
            for f in findings:
                key = (
                    f.evidence.file_path,
                    f.evidence.start_line,
                    (f.crypto_asset.algorithm_variant or f.crypto_asset.algorithm_family or "").upper()
                )
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(f)

            # ── PQC Migration Wave Planning ───────────────────────────────────
            planned_findings = MigrationPlanner.plan_recommendations(unique_findings)

            # ── Compliance Mapping ────────────────────────────────────────────
            compliance_report = ComplianceEngine.generate_compliance_report(planned_findings)
            summary.compliance_report = compliance_report

            # ── Aggregate metrics ─────────────────────────────────────────────
            summary.findings = planned_findings
            summary.total_files_scanned = file_count
            summary.total_loc_scanned = loc_count

            # ── Mathematical Scoring (QEI / QRI / CAI / Mosca) ───────────────
            summary = ScoringEngine.score_assessment(summary, coverage_pct=coverage_pct)

            return summary

        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _scan_single_file(self, file_path: str, app_name: str) -> List[CryptoFinding]:
        """Run all applicable scanners against a single file."""
        results: List[CryptoFinding] = []
        results.extend(self.code_scanner.scan_file(file_path))
        results.extend(self.cert_scanner.scan_file(file_path))
        results.extend(self.dep_scanner.scan_file(file_path))
        results.extend(self.secrets_scanner.scan_file(file_path))
        results.extend(self.net_scanner.scan_file(file_path))
        results.extend(self.cloud_scanner.scan_file(file_path))
        return results

    @staticmethod
    def _count_lines(file_path: str) -> int:
        try:
            with open(file_path, "rb") as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
