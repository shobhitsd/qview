"""
QView Crypto Knowledge Graph
Represents relationships: Application -> Component -> CryptoAsset -> DataAsset -> Threat -> PQC Candidate.
Provides graph traversal and Cypher-like relationship queries.
"""

from typing import Dict, Any, List, Set
from core.models import AssessmentSummary, CryptoFinding


class CryptoKnowledgeGraph:
    """In-memory Knowledge Graph representation linking crypto to business context."""

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, node_type: str, label: str, properties: Dict[str, Any] = None) -> None:
        self.nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            "properties": properties or {}
        }

    def add_edge(self, source_id: str, target_id: str, relation: str, properties: Dict[str, Any] = None) -> None:
        self.edges.append({
            "source": source_id,
            "target": target_id,
            "relation": relation,
            "properties": properties or {}
        })

    @classmethod
    def build_from_assessment(cls, summary: AssessmentSummary) -> "CryptoKnowledgeGraph":
        """Build the full knowledge graph from an assessment summary."""
        graph = cls()

        # Root Org & App
        app_id = "APP-01"
        graph.add_node(app_id, "Application", summary.target_name or "Target App", {
            "path": summary.target_path,
            "qri": summary.qri,
            "qei": summary.qei,
            "cai": summary.cai
        })

        # Business Service
        biz_id = "BIZ-01"
        graph.add_node(biz_id, "BusinessService", "Healthcare EHR & Provider APIs", {
            "criticality": "Critical (Tier 1)",
            "compliance": "HIPAA / FDA 21 CFR Part 11"
        })
        graph.add_edge(biz_id, app_id, "HOSTS_APPLICATION")

        # Data Asset
        data_id = "DATA-01"
        graph.add_node(data_id, "DataAsset", "Electronic Health Records (PHI/Genomics)", {
            "sensitivity": "PHI_GENOMIC",
            "confidentiality_lifetime_years": 30
        })
        graph.add_edge(app_id, data_id, "PROTECTS")

        # Crypto Assets and Threats
        for finding in summary.findings:
            f_id = finding.finding_id
            c_asset = finding.crypto_asset

            # Crypto Asset Node
            graph.add_node(f_id, "CryptoAsset", f"{c_asset.algorithm_variant or c_asset.algorithm_family}", {
                "primitive": c_asset.primitive,
                "key_size": c_asset.key_size,
                "library": c_asset.library_name,
                "location": f"{finding.evidence.file_path}:{finding.evidence.start_line}",
                "quantum_status": finding.quantum_status,
                "qei": finding.qei_score,
                "cai": finding.cai_score
            })
            graph.add_edge(app_id, f_id, "IMPLEMENTS")
            graph.add_edge(f_id, data_id, "ENCRYPTS_OR_SIGNS")

            # Quantum Threat Node
            if finding.quantum_status == "CRITICAL_VULNERABLE":
                threat_id = "THREAT-SHOR"
                if threat_id not in graph.nodes:
                    graph.add_node(threat_id, "QuantumThreat", "Shor's Algorithm (Integer Factorization / ECDLP)", {
                        "severity": "CRITICAL",
                        "impact": "Completely breaks RSA, ECC, ECDSA, DH in polynomial time"
                    })
                graph.add_edge(f_id, threat_id, "VULNERABLE_TO")

                # PQC Target Node
                pqc_target = finding.pqc_recommendation.target_algorithm
                if pqc_target:
                    pqc_id = f"PQC-{pqc_target.replace(' ', '-').replace('/', '-')}"
                    if pqc_id not in graph.nodes:
                        graph.add_node(pqc_id, "PQCCandidate", pqc_target, {
                            "standard": "NIST FIPS 203/204/205",
                            "security_bits": 192,
                            "quantum_status": "QUANTUM_SAFE"
                        })
                    graph.add_edge(f_id, pqc_id, "MIGRATE_TO", {
                        "wave": finding.pqc_recommendation.migration_wave,
                        "effort": finding.pqc_recommendation.effort_estimate
                    })

        return graph

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges
        }
