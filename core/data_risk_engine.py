"""
QView Data Risk & Longevity Engine (V1 Agent 10)
Calculates data confidentiality lifetime (X), Harvest Now Decrypt Later (HNDL) vulnerability window,
and data classification severity across healthcare PHI, financial PCI, PII, and intellectual property.
"""

from typing import Dict, Any
from core.models import CryptoFinding, QuantumRiskLevel


class DataRiskEngine:
    """Evaluates data sensitivity, retention lifetime, and HNDL priority."""

    # Domain Data Longevity Profiles (in Years)
    DATA_DOMAINS = {
        "HEALTHCARE_GENOMICS": {
            "name": "Genomic & Pediatric Health Records",
            "longevity_years": 75,
            "classification": "RESTRICTED_PHI",
            "hndl_urgency": "EXTREME",
            "description": "Patient lifetime genomic and biometric health data subject to HIPAA / GDPR."
        },
        "HEALTHCARE_EHR": {
            "name": "Electronic Health Records (EHR) & Clinical Notes",
            "longevity_years": 25,
            "classification": "REGULATED_PHI",
            "hndl_urgency": "CRITICAL",
            "description": "Hospital medical histories, diagnoses, and prescription signatures."
        },
        "FINANCIAL_CORE": {
            "name": "Cardholder Data & Banking Transaction Master",
            "longevity_years": 10,
            "classification": "REGULATED_PCI",
            "hndl_urgency": "HIGH",
            "description": "PCI-DSS regulated cardholder data, banking credentials, and settlement logs."
        },
        "IDENTITY_KYC": {
            "name": "Citizen ID, Passports & Biometrics",
            "longevity_years": 15,
            "classification": "CONFIDENTIAL_PII",
            "hndl_urgency": "CRITICAL",
            "description": "National ID, SSN/PAN credentials, and KYC identity verification records."
        },
        "IP_TRADE_SECRETS": {
            "name": "Proprietary IP & Algorithmic Models",
            "longevity_years": 20,
            "classification": "RESTRICTED_IP",
            "hndl_urgency": "HIGH",
            "description": "Core algorithms, chemical patents, and architectural blueprints."
        },
        "SESSION_EPHEMERAL": {
            "name": "Ephemeral Session Tokens & Cache",
            "longevity_years": 0.1,
            "classification": "INTERNAL",
            "hndl_urgency": "LOW",
            "description": "Short-lived session keys and temporary caching."
        }
    }

    @classmethod
    def evaluate_finding_data_risk(cls, finding: CryptoFinding, context_hint: str = "") -> Dict[str, Any]:
        """
        Classify the data longevity and HNDL risk multiplier for a finding based on
        file path, usage context, and application purpose.
        """
        path_lower = (finding.file_path + " " + finding.usage_context + " " + context_hint).lower()

        if any(w in path_lower for w in ["patient", "health", "ehr", "clinical", "genom", "medical", "hipaa"]):
            domain = cls.DATA_DOMAINS["HEALTHCARE_EHR"]
        elif any(w in path_lower for w in ["card", "payment", "pci", "billing", "bank", "settle", "wallet"]):
            domain = cls.DATA_DOMAINS["FINANCIAL_CORE"]
        elif any(w in path_lower for w in ["auth", "identity", "jwt", "user", "token", "kyc", "session", "sso"]):
            domain = cls.DATA_DOMAINS["IDENTITY_KYC"]
        elif any(w in path_lower for w in ["key", "secret", "vault", "kms", "master"]):
            domain = cls.DATA_DOMAINS["IP_TRADE_SECRETS"]
        else:
            domain = cls.DATA_DOMAINS["IDENTITY_KYC"]  # Enterprise default baseline

        # Check Mosca inequality against default quantum timeline Z = 7 years and migration Y = 3 years
        x_shelf_life = domain["longevity_years"]
        y_migration = 3.0
        z_threat = 7.0
        is_hndl_vulnerable = (x_shelf_life + y_migration) > z_threat and finding.quantum_risk in [
            QuantumRiskLevel.CRITICAL, QuantumRiskLevel.HIGH
        ]

        return {
            "domain_name": domain["name"],
            "classification": domain["classification"],
            "shelf_life_years": x_shelf_life,
            "hndl_urgency": domain["hndl_urgency"] if is_hndl_vulnerable else "LOW",
            "is_hndl_vulnerable": is_hndl_vulnerable,
            "description": domain["description"]
        }
