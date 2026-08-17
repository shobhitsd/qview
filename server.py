"""
QView API & Web Application Server v2
Serves the interactive Quantum Readiness Command Center dashboard and
provides REST endpoints for all 6 dashboard tabs.
"""

import os
import json
import http.server
import socketserver
import urllib.parse
from typing import Dict, Any, Optional
from scanners.repo_orchestrator import RepoOrchestrator
from core.cbom_engine import CBOMBuilder
from core.knowledge_graph import CryptoKnowledgeGraph
from core.compliance_engine import ComplianceEngine

PORT = 8765
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR  = os.path.join(BASE_DIR, "web")
SAMPLE_DIR = os.path.join(BASE_DIR, "sample_data")

orchestrator: RepoOrchestrator = RepoOrchestrator()
latest_assessment = None


# ── Boot-time sample scan ─────────────────────────────────────────────────────
try:
    print("[QView] Starting initial sample scan...")
    latest_assessment = orchestrator.scan_target(
        SAMPLE_DIR,
        app_name="Sentara-Enterprise-Sample",
        coverage_pct=0.92
    )
    n = len(latest_assessment.findings)
    q = latest_assessment.quantum_vulnerable_count
    print(f"[QView] Initial scan complete: {n} findings, {q} quantum-vulnerable. "
          f"QRI={latest_assessment.qri}")
except Exception as e:
    print(f"[WARN] Initial sample scan error: {e}")
    import traceback; traceback.print_exc()


class QViewHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP Handler for QView static assets and REST API."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def log_message(self, fmt, *args):
        # Suppress verbose access logs; only show API calls
        if '/api/' in fmt % args:
            super().log_message(fmt, *args)

    def do_OPTIONS(self):
        """CORS preflight support."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        # ── GET /api/assessment/latest ─────────────────────────────────────
        if path == "/api/assessment/latest":
            self.send_json_response(self._get_assessment_data())

        # ── GET /api/cbom ──────────────────────────────────────────────────
        elif path == "/api/cbom":
            if latest_assessment:
                cbom = CBOMBuilder.generate_cyclonedx_cbom(latest_assessment)
                self.send_json_response(cbom)
            else:
                self.send_json_response({"error": "No assessment available"}, status=404)

        # ── GET /api/knowledge-graph ───────────────────────────────────────
        elif path == "/api/knowledge-graph":
            if latest_assessment:
                graph = CryptoKnowledgeGraph.build_from_assessment(latest_assessment)
                self.send_json_response(graph.to_dict())
            else:
                self.send_json_response({"error": "No assessment available"}, status=404)

        # ── GET /api/findings ─────────────────────────────────────────────
        elif path == "/api/findings":
            if not latest_assessment:
                self.send_json_response({"findings": [], "total": 0})
                return
            status_filter = params.get("status", [None])[0]
            prim_filter   = params.get("primitive", [None])[0]
            findings = latest_assessment.findings
            if status_filter:
                findings = [f for f in findings if f.quantum_status == status_filter]
            if prim_filter:
                findings = [f for f in findings if (f.crypto_asset.primitive or '') == prim_filter]
            self.send_json_response({
                "findings": [f.to_dict() for f in findings],
                "total": len(findings)
            })

        # ── GET /api/findings/<id> ─────────────────────────────────────────
        elif path.startswith("/api/findings/"):
            fid = path.replace("/api/findings/", "")
            if latest_assessment:
                match = next((f for f in latest_assessment.findings if f.finding_id == fid), None)
                if match:
                    # Enrich with compliance violations before sending
                    violations = ComplianceEngine.evaluate_finding(match)
                    d = match.to_dict()
                    d["compliance_violations"] = violations
                    self.send_json_response(d)
                else:
                    self.send_json_response({"error": "Finding not found"}, status=404)
            else:
                self.send_json_response({"error": "No assessment"}, status=404)

        # ── GET /api/migration-plan ────────────────────────────────────────
        elif path == "/api/migration-plan":
            if not latest_assessment:
                self.send_json_response({"error": "No assessment available"}, status=404)
                return
            waves: Dict[str, list] = {"0": [], "1": [], "2": [], "3": [], "4": []}
            for f in latest_assessment.findings:
                wave = f.pqc_recommendation.migration_wave if f.pqc_recommendation else "WAVE_4"
                key  = "1" if "1" in wave else "2" if "2" in wave else "3" if "3" in wave else "0" if "0" in wave else "4"
                waves[key].append({
                    "finding_id": f.finding_id,
                    "algorithm":  f.crypto_asset.algorithm_variant or f.crypto_asset.algorithm_family,
                    "file":       f.evidence.file_path,
                    "line":       f.evidence.start_line,
                    "qei_score":  f.qei_score,
                    "target":     f.pqc_recommendation.target_algorithm if f.pqc_recommendation else "",
                    "effort":     f.pqc_recommendation.effort_estimate if f.pqc_recommendation else "",
                    "hndl_risk":  f.hndl_risk,
                    "mosca_flag": f.mosca_flag,
                })
            self.send_json_response({
                "waves": waves,
                "wave_counts": {k: len(v) for k, v in waves.items()},
                "total": len(latest_assessment.findings),
            })

        # ── GET /api/heatmap ───────────────────────────────────────────────
        elif path == "/api/heatmap":
            if not latest_assessment:
                self.send_json_response({"matrix": [], "metadata": {}})
                return
            # Build 4x4 matrix [exposure_level][biz_criticality]
            matrix = [[{"count": 0, "finding_ids": []} for _ in range(4)] for _ in range(4)]
            for f in latest_assessment.findings:
                qei = f.qei_score or 0
                biz = f.business_criticality or 2
                biz_idx = 0 if biz <= 2 else 1 if biz == 3 else 2 if biz == 4 else 3
                exp_idx = 0 if qei >= 90 else 1 if qei >= 60 else 2 if qei >= 40 else 3
                matrix[exp_idx][biz_idx]["count"] += 1
                matrix[exp_idx][biz_idx]["finding_ids"].append(f.finding_id)
            self.send_json_response({
                "matrix": matrix,
                "metadata": {
                    "x_axis": ["Low (1-2)", "Medium (3)", "High (4)", "Critical (5)"],
                    "y_axis": ["Critical (90-100)", "High (60-89)", "Medium (40-59)", "Low (0-39)"],
                }
            })

        # ── GET /api/compliance ────────────────────────────────────────────
        elif path == "/api/compliance":
            if latest_assessment:
                self.send_json_response(latest_assessment.compliance_report)
            else:
                self.send_json_response({"error": "No assessment"}, status=404)

        # ── GET /api/health ────────────────────────────────────────────────
        elif path == "/api/health":
            self.send_json_response({
                "status": "ok",
                "version": "2.0.0",
                "assessment_ready": latest_assessment is not None,
                "findings_count": len(latest_assessment.findings) if latest_assessment else 0,
            })

        # ── Static files ───────────────────────────────────────────────────
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path

        content_len = int(self.headers.get('Content-Length', 0))
        post_body   = self.rfile.read(content_len).decode('utf-8') if content_len else ''
        try:
            data = json.loads(post_body) if post_body else {}
        except json.JSONDecodeError:
            self.send_json_response({"error": "Invalid JSON"}, status=400)
            return

        # ── POST /api/scan ──────────────────────────────────────────────────
        if path == "/api/scan":
            try:
                global latest_assessment
                target_path = data.get("target_path", SAMPLE_DIR)
                app_name    = data.get("app_name", "Target-Application")
                coverage    = float(data.get("coverage_pct", 0.92))
                tls_endpoints = data.get("tls_endpoints", [])

                print(f"[QView] Scan requested: {target_path}")
                latest_assessment = orchestrator.scan_target(
                    target_path, app_name=app_name,
                    tls_endpoints=tls_endpoints, coverage_pct=coverage
                )
                print(f"[QView] Scan complete: {len(latest_assessment.findings)} findings")
                self.send_json_response(self._get_assessment_data())
            except FileNotFoundError as e:
                self.send_json_response({"error": f"Target not found: {e}"}, status=400)
            except Exception as e:
                self.send_json_response({"error": str(e)}, status=500)

        else:
            self.send_json_response({"error": "Endpoint not found"}, status=404)

    def _get_assessment_data(self) -> Dict[str, Any]:
        global latest_assessment
        if not latest_assessment:
            latest_assessment = orchestrator.scan_target(
                SAMPLE_DIR,
                app_name="Sentara-Enterprise-Sample",
                coverage_pct=0.92
            )
        summary_dict = latest_assessment.to_dict()
        graph = CryptoKnowledgeGraph.build_from_assessment(latest_assessment)
        cbom  = CBOMBuilder.generate_cyclonedx_cbom(latest_assessment)
        return {
            "summary": summary_dict,
            "graph": graph.to_dict(),
            "cbom": cbom
        }

    def send_json_response(self, data: Any, status: int = 200):
        body = json.dumps(data, default=str, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(port: int = PORT):
    os.chdir(BASE_DIR)  # Ensure relative paths resolve correctly
    with socketserver.ThreadingTCPServer(("", port), QViewHandler) as httpd:
        print(f"\n{'='*55}")
        print(f"  QView — Quantum Readiness Intelligence Platform v2")
        print(f"  Dashboard:  http://localhost:{port}")
        print(f"  API Health: http://localhost:{port}/api/health")
        print(f"{'='*55}\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[QView] Server stopped.")


if __name__ == "__main__":
    run_server()
