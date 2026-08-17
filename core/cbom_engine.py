"""
QView CycloneDX 1.6 CBOM Engine
Generates official CycloneDX 1.6 Cryptography Bill of Materials (CBOM) JSON specifications.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from core.models import AssessmentSummary, CryptoFinding


class CBOMBuilder:
    """Builder for generating official CycloneDX 1.6 CBOM documents."""

    @staticmethod
    def generate_cyclonedx_cbom(summary: AssessmentSummary) -> Dict[str, Any]:
        """
        Produce a valid CycloneDX 1.6 JSON representation of the cryptographic assets.
        """
        bom_serial = f"urn:uuid:{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        components: List[Dict[str, Any]] = []
        dependencies: List[Dict[str, Any]] = []

        # Root application component
        root_ref = f"pkg:generic/{summary.target_name or 'target-application'}@1.0.0"
        root_component = {
            "type": "application",
            "bom-ref": root_ref,
            "name": summary.target_name or "Target Application",
            "version": "1.0.0",
            "description": f"Analyzed repository / filesystem target: {summary.target_path}",
            "properties": [
                {"name": "qview:qri_score", "value": str(summary.qri)},
                {"name": "qview:qei_score", "value": str(summary.qei)},
                {"name": "qview:cai_score", "value": str(summary.cai)},
                {"name": "qview:coverage_confidence", "value": str(summary.coverage_confidence)},
                {"name": "qview:quantum_vulnerable_count", "value": str(summary.quantum_vulnerable_count)}
            ]
        }
        components.append(root_component)

        crypto_refs = []

        for finding in summary.findings:
            crypto_ref = f"crypto:{finding.finding_id}"
            crypto_refs.append(crypto_ref)

            crypto_comp: Dict[str, Any] = {
                "type": "cryptographic-asset",
                "bom-ref": crypto_ref,
                "name": finding.crypto_asset.algorithm_variant or finding.crypto_asset.algorithm_family,
                "description": f"Detected in {finding.evidence.file_path}:{finding.evidence.start_line} ({finding.evidence.function_name or 'global'})",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "family": finding.crypto_asset.algorithm_family,
                        "variant": finding.crypto_asset.algorithm_variant,
                        "primitive": finding.crypto_asset.primitive,
                        "parameterSetIdentifier": str(finding.crypto_asset.key_size) if finding.crypto_asset.key_size else None,
                        "curve": finding.crypto_asset.curve,
                        "executionEnvironment": "software-plain",
                        "implementationPlatform": finding.crypto_asset.library_name or "native",
                        "certificationLevel": ["none"],
                        "mode": finding.crypto_asset.mode,
                        "classicalSecurityLevel": finding.classical_security_bits,
                        "nistQuantumSecurityLevel": 0 if finding.quantum_status == "CRITICAL_VULNERABLE" else 5
                    },
                    "oid": finding.crypto_asset.oid
                },
                "evidence": {
                    "occurrences": [
                        {
                            "location": finding.evidence.file_path,
                            "line": finding.evidence.start_line,
                            "offset": finding.evidence.column,
                            "symbol": finding.evidence.function_name,
                            "additionalContext": finding.evidence.code_snippet
                        }
                    ]
                },
                "properties": [
                    {"name": "qview:quantum_status", "value": finding.quantum_status},
                    {"name": "qview:threat_vector", "value": finding.threat_vector},
                    {"name": "qview:nist_status", "value": finding.nist_status},
                    {"name": "qview:pqc_target", "value": finding.pqc_recommendation.target_algorithm},
                    {"name": "qview:pqc_migration_wave", "value": finding.pqc_recommendation.migration_wave},
                    {"name": "qview:finding_qei", "value": str(finding.qei_score)},
                    {"name": "qview:finding_cai", "value": str(finding.cai_score)},
                    {"name": "qview:rule_id", "value": finding.evidence.rule_id or "RULE-AST-01"},
                    {"name": "qview:confidence", "value": str(finding.confidence)}
                ]
            }
            components.append(crypto_comp)

        # Root dependency mapping
        dependencies.append({
            "ref": root_ref,
            "dependsOn": crypto_refs
        })

        cbom_doc: Dict[str, Any] = {
            "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": bom_serial,
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "QView Quantum Readiness & CBOM Platform",
                            "version": "1.0.0",
                            "vendor": "SD Sol / Antigravity"
                        }
                    ]
                },
                "component": root_component
            },
            "components": components,
            "dependencies": dependencies
        }

        return cbom_doc

    @classmethod
    def export_to_json(cls, summary: AssessmentSummary, file_path: str) -> None:
        """Serialize CycloneDX CBOM to a JSON file."""
        cbom = cls.generate_cyclonedx_cbom(summary)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(cbom, f, indent=2)
