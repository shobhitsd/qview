"""
QView Unified Command Line Interface (CLI)
Provides commands for scanning, CBOM export, and launching the interactive UI.
"""

import sys
import os
import argparse
from scanners.repo_orchestrator import RepoOrchestrator
from core.cbom_engine import CBOMBuilder


def main():
    parser = argparse.ArgumentParser(
        description="QView - Enterprise Quantum Readiness & CBOM Intelligence Platform"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a file, directory, or ZIP archive")
    scan_parser.add_argument("target", help="Path to repository, folder, file, or ZIP")
    scan_parser.add_argument("--name", "-n", default=None, help="Target application name")
    scan_parser.add_argument("--output-cbom", "-o", default=None, help="Export CycloneDX 1.6 CBOM to JSON file")

    # Export CBOM command
    cbom_parser = subparsers.add_parser("export-cbom", help="Generate and export CycloneDX CBOM")
    cbom_parser.add_argument("target", help="Path to repository, folder, file, or ZIP")
    cbom_parser.add_argument("output", help="Output JSON file path")

    # UI command
    ui_parser = subparsers.add_parser("ui", help="Launch the interactive web application dashboard")
    ui_parser.add_argument("--port", "-p", type=int, default=8765, help="Port to listen on (default: 8765)")

    args = parser.parse_args()

    if not args.command or args.command == "scan":
        target = getattr(args, "target", None)
        if not target:
            # Default to sample_data if none provided
            target = os.path.join(os.path.dirname(__file__), "sample_data")
            print(f"[*] No target specified, scanning sample dataset: {target}")

        orchestrator = RepoOrchestrator()
        print(f"\n[*] Initiating QView Quantum Readiness Discovery on: {target} ...")
        summary = orchestrator.scan_target(target, app_name=args.name if hasattr(args, "name") else None)

        print("\n" + "="*70)
        print("  QVIEW QUANTUM READINESS ASSESSMENT REPORT")
        print("="*70)
        print(f"Target Name:            {summary.target_name}")
        print(f"Files Scanned:          {summary.total_files_scanned} ({summary.total_loc_scanned} Lines of Code)")
        print(f"Total Crypto Assets:    {summary.total_crypto_assets}")
        print(f"Quantum Vulnerable:     {summary.quantum_vulnerable_count} (Shor's / Grover's Risk)")
        print(f"Medium Risk / Legacy:   {summary.medium_risk_count}")
        print(f"Quantum Safe (PQC):     {summary.quantum_safe_count}")
        print("-" * 70)
        print(f"Quantum Readiness (QRI): {summary.qri} / 100  (Confidence: {int(summary.coverage_confidence*100)}%)")
        print(f"Quantum Exposure (QEI):  {summary.qei} / 100  [Higher = Worse Risk]")
        print(f"Crypto Agility (CAI):    {summary.cai} / 100  [Higher = More Agile]")
        print("="*70)

        print("\n[!] Top Identified Vulnerabilities & Evidence:")
        for idx, f in enumerate(summary.findings[:10], 1):
            status_tag = f"[{f.quantum_status}]"
            print(f" {idx}. {status_tag} {f.crypto_asset.algorithm_variant or f.crypto_asset.algorithm_family} ({f.crypto_asset.primitive})")
            print(f"    Location:   {f.evidence.file_path}:{f.evidence.start_line} ({f.evidence.function_name or 'global'})")
            print(f"    Threat:     {f.threat_vector}")
            print(f"    PQC Target: {f.pqc_recommendation.target_algorithm} [{f.pqc_recommendation.migration_wave}]")
            print(f"    Evidence:   {f.evidence.evidence_id} (Confidence: {int(f.confidence*100)}%)\n")

        if hasattr(args, "output_cbom") and args.output_cbom:
            CBOMBuilder.export_to_json(summary, args.output_cbom)
            print(f"[+] CycloneDX 1.6 CBOM exported successfully to: {args.output_cbom}")

    elif args.command == "export-cbom":
        orchestrator = RepoOrchestrator()
        summary = orchestrator.scan_target(args.target)
        CBOMBuilder.export_to_json(summary, args.output)
        print(f"[+] CycloneDX 1.6 CBOM exported successfully to: {args.output}")

    elif args.command == "ui":
        from server import run_server
        run_server(port=args.port)


if __name__ == "__main__":
    main()
