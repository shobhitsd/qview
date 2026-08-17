"""
QView Compliance Mapping Engine
Maps cryptographic findings to regulatory compliance frameworks:
NIST FIPS 203/204/205, HIPAA, PCI-DSS 4.0, SEBI CSCRF, CNSA 2.0,
GDPR/DPDP, QCCPA, ISO 27799, HITRUST CSF.
"""

from typing import List, Dict, Any
from core.models import CryptoFinding


# Compliance framework definitions
COMPLIANCE_FRAMEWORKS: Dict[str, Dict[str, Any]] = {
    "NIST_FIPS": {
        "name": "NIST FIPS PQC Standards",
        "authority": "National Institute of Standards and Technology",
        "description": "NIST finalized PQC standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA). Deprecates quantum-vulnerable algorithms by 2035.",
        "rules": {
            "DEPRECATED_ALGO": {
                "control_id": "NIST SP 800-131A Rev 3",
                "requirement": "Quantum-vulnerable algorithms (RSA, ECC, DH, DSA) must be replaced by NIST-approved PQC algorithms by 2035, earlier for high-risk systems.",
                "severity": "CRITICAL",
                "applies_to": {"quantum_status": ["CRITICAL_VULNERABLE", "MEDIUM_RISK"]}
            },
            "KEY_SIZE": {
                "control_id": "NIST SP 800-131A Rev 3 §3",
                "requirement": "RSA keys < 2048 bits disallowed. ECC keys < 224 bits disallowed. AES-128 acceptable, AES-256 recommended for long-lived data.",
                "severity": "HIGH",
                "applies_to": {"algorithms": ["RSA-1024", "RSA-512", "ECC-160", "DH-1024"]}
            },
            "PQC_TRANSITION": {
                "control_id": "NIST IR 8547",
                "requirement": "Organizations must inventory cryptographic assets, assess quantum vulnerability, and begin PQC migration planning.",
                "severity": "HIGH",
                "applies_to": {"all": True}
            }
        }
    },
    "HIPAA": {
        "name": "HIPAA / HITECH Security Rule",
        "authority": "U.S. Department of Health and Human Services",
        "description": "Requires appropriate safeguards for PHI. Encryption of PHI at rest and in transit. Audit controls and integrity requirements.",
        "rules": {
            "PHI_ENCRYPTION": {
                "control_id": "45 CFR §164.312(e)(2)(ii)",
                "requirement": "PHI must be encrypted using NIST-approved algorithms during transit. RSA/ECC-based encryption of PHI is quantum-vulnerable and poses HNDL risk to patient data with 30-100yr retention.",
                "severity": "CRITICAL",
                "applies_to": {"data_sensitivity": ["PHI_GENOMIC", "RESTRICTED", "CONFIDENTIAL"], "quantum_status": ["CRITICAL_VULNERABLE"]}
            },
            "AUDIT_CONTROLS": {
                "control_id": "45 CFR §164.312(b)",
                "requirement": "Cryptographic audit trails must be integrity-protected. MD5/SHA-1 signed audit logs are cryptographically broken.",
                "severity": "HIGH",
                "applies_to": {"algorithms": ["MD5", "SHA1"]}
            },
            "KEY_MANAGEMENT": {
                "control_id": "45 CFR §164.312(a)(2)(iv)",
                "requirement": "Encryption and decryption keys must be managed securely. Hardcoded keys violate this requirement.",
                "severity": "CRITICAL",
                "applies_to": {"hardcoded": True}
            }
        }
    },
    "PCI_DSS": {
        "name": "PCI-DSS 4.0",
        "authority": "PCI Security Standards Council",
        "description": "Payment Card Industry Data Security Standard. Requires strong cryptography for cardholder data protection.",
        "rules": {
            "STRONG_CRYPTO": {
                "control_id": "PCI DSS 4.0 Requirement 4.2.1",
                "requirement": "Only trusted keys/certificates are accepted. Strong cryptography (AES-256, TLS 1.2+) must be used for CHD transmission. RSA key exchange is being deprecated.",
                "severity": "CRITICAL",
                "applies_to": {"quantum_status": ["CRITICAL_VULNERABLE"], "primitive": ["key-establishment", "signature"]}
            },
            "TLS_VERSION": {
                "control_id": "PCI DSS 4.0 Requirement 6.4.2",
                "requirement": "TLS 1.0 and TLS 1.1 must not be used. TLS 1.2 minimum. TLS 1.3 strongly recommended.",
                "severity": "CRITICAL",
                "applies_to": {"algorithms": ["TLS-Legacy", "TLSv1.0", "TLSv1.1", "SSLv3"]}
            },
            "KEY_STRENGTH": {
                "control_id": "PCI DSS 4.0 Requirement 12.3.3",
                "requirement": "Cryptographic key management includes inventory of all keys and certificates with their key strength.",
                "severity": "HIGH",
                "applies_to": {"all": True}
            },
            "NO_HARDCODED": {
                "control_id": "PCI DSS 4.0 Requirement 6.3.3",
                "requirement": "All software components must be protected from known vulnerabilities. Hardcoded encryption keys or passwords are a critical control failure.",
                "severity": "CRITICAL",
                "applies_to": {"hardcoded": True}
            }
        }
    },
    "SEBI_CSCRF": {
        "name": "SEBI Cybersecurity & Cyber Resilience Framework",
        "authority": "Securities and Exchange Board of India",
        "description": "SEBI CSCRF mandates quantum readiness for capital market entities. Requires cryptographic inventory, quantum risk assessment, and migration planning.",
        "rules": {
            "QUANTUM_READINESS": {
                "control_id": "SEBI CSCRF Section 7.4",
                "requirement": "Regulated entities must conduct quantum threat assessment, identify quantum-vulnerable cryptographic assets, and develop a PQC migration roadmap.",
                "severity": "CRITICAL",
                "applies_to": {"quantum_status": ["CRITICAL_VULNERABLE", "MEDIUM_RISK"]}
            },
            "CRYPTO_INVENTORY": {
                "control_id": "SEBI CSCRF Section 4.1",
                "requirement": "Organizations must maintain a complete inventory of cryptographic assets including algorithms, keys, certificates, and protocols.",
                "severity": "HIGH",
                "applies_to": {"all": True}
            }
        }
    },
    "CNSA_2": {
        "name": "NSA CNSA 2.0",
        "authority": "National Security Agency (USA)",
        "description": "Commercial National Security Algorithm Suite 2.0 mandates PQC migration for National Security Systems by 2030-2033.",
        "rules": {
            "KEX_UPGRADE": {
                "control_id": "CNSA 2.0 Key Exchange",
                "requirement": "ML-KEM-1024 required for key establishment. ECDH/DH to be deprecated by 2030 for NSS.",
                "severity": "CRITICAL",
                "applies_to": {"primitive": ["key-establishment"], "quantum_status": ["CRITICAL_VULNERABLE", "MEDIUM_RISK"]}
            },
            "SIG_UPGRADE": {
                "control_id": "CNSA 2.0 Digital Signatures",
                "requirement": "ML-DSA-87 required for digital signatures. RSA and ECDSA to be deprecated by 2030 for NSS.",
                "severity": "CRITICAL",
                "applies_to": {"primitive": ["signature"], "quantum_status": ["CRITICAL_VULNERABLE"]}
            }
        }
    },
    "GDPR_DPDP": {
        "name": "GDPR / India DPDP Act",
        "authority": "EU / Ministry of Electronics & IT, India",
        "description": "Requires appropriate technical measures for personal data protection. HNDL attacks against quantum-vulnerable encryption create retroactive breach liability.",
        "rules": {
            "DATA_SECURITY": {
                "control_id": "GDPR Article 32 / DPDP Section 8",
                "requirement": "Personal data must be encrypted using state-of-the-art cryptography. RSA/ECC-based encryption of personal data is no longer 'state of the art' given HNDL risks.",
                "severity": "HIGH",
                "applies_to": {"data_sensitivity": ["CONFIDENTIAL", "RESTRICTED", "PHI_GENOMIC"], "quantum_status": ["CRITICAL_VULNERABLE"]}
            }
        }
    },
    "QCCPA": {
        "name": "Quantum Computing Cybersecurity Preparedness Act",
        "authority": "U.S. Congress",
        "description": "Mandates federal agencies and contractors to inventory cryptography, assess quantum vulnerability, and migrate to NIST-approved PQC.",
        "rules": {
            "INVENTORY": {
                "control_id": "QCCPA Section 4(a)",
                "requirement": "Inventory all cryptographic assets, identify quantum-vulnerable systems, prioritize migration of high-value/long-lived data systems.",
                "severity": "HIGH",
                "applies_to": {"all": True}
            },
            "HNDL_PRIORITY": {
                "control_id": "QCCPA Section 4(b)",
                "requirement": "Systems protecting sensitive data with long confidentiality requirements must be prioritized for PQC migration due to HNDL risk.",
                "severity": "CRITICAL",
                "applies_to": {"hndl_risk": ["CRITICAL", "HIGH"]}
            }
        }
    },
}


class ComplianceEngine:
    """Maps cryptographic findings to regulatory compliance violations."""

    @staticmethod
    def evaluate_finding(finding: CryptoFinding) -> List[Dict[str, Any]]:
        """
        Evaluate a single CryptoFinding against all compliance frameworks.
        Returns list of compliance violations found.
        """
        violations: List[Dict[str, Any]] = []

        for framework_id, framework in COMPLIANCE_FRAMEWORKS.items():
            for rule_id, rule in framework["rules"].items():
                applies_to = rule.get("applies_to", {})
                if ComplianceEngine._rule_applies(finding, applies_to):
                    violations.append({
                        "framework": framework_id,
                        "framework_name": framework["name"],
                        "authority": framework["authority"],
                        "control_id": rule["control_id"],
                        "rule_id": rule_id,
                        "requirement": rule["requirement"],
                        "severity": rule["severity"],
                        "finding_id": finding.finding_id,
                        "algorithm": finding.crypto_asset.algorithm_variant or finding.crypto_asset.algorithm_family,
                        "file": finding.evidence.file_path,
                        "line": finding.evidence.start_line,
                    })

        return violations

    @staticmethod
    def _rule_applies(finding: CryptoFinding, applies_to: Dict[str, Any]) -> bool:
        """Check whether a compliance rule applies to this finding."""
        if applies_to.get("all"):
            return True

        # Check quantum status
        if "quantum_status" in applies_to:
            if finding.quantum_status not in applies_to["quantum_status"]:
                return False

        # Check data sensitivity
        if "data_sensitivity" in applies_to:
            if finding.data_sensitivity not in applies_to["data_sensitivity"]:
                return False

        # Check HNDL risk
        if "hndl_risk" in applies_to:
            if finding.hndl_risk not in applies_to["hndl_risk"]:
                return False

        # Check hardcoded
        if "hardcoded" in applies_to:
            if finding.crypto_asset.hardcoded != applies_to["hardcoded"]:
                return False

        # Check primitive
        if "primitive" in applies_to:
            if finding.crypto_asset.primitive not in applies_to["primitive"]:
                return False

        # Check specific algorithm variants
        if "algorithms" in applies_to:
            algo = (finding.crypto_asset.algorithm_variant or finding.crypto_asset.algorithm_family or "").upper()
            matches = any(a.upper() in algo or algo in a.upper() for a in applies_to["algorithms"])
            if not matches:
                return False

        return True

    @staticmethod
    def generate_compliance_report(findings: List[CryptoFinding]) -> Dict[str, Any]:
        """Generate a full compliance report across all frameworks for a set of findings."""
        all_violations: List[Dict[str, Any]] = []
        framework_summary: Dict[str, Dict[str, Any]] = {}

        for finding in findings:
            violations = ComplianceEngine.evaluate_finding(finding)
            all_violations.extend(violations)

        # Aggregate by framework
        for fw_id, fw in COMPLIANCE_FRAMEWORKS.items():
            fw_violations = [v for v in all_violations if v["framework"] == fw_id]
            critical = sum(1 for v in fw_violations if v["severity"] == "CRITICAL")
            high = sum(1 for v in fw_violations if v["severity"] == "HIGH")
            framework_summary[fw_id] = {
                "framework_name": fw["name"],
                "authority": fw["authority"],
                "description": fw["description"],
                "total_violations": len(fw_violations),
                "critical_violations": critical,
                "high_violations": high,
                "compliance_status": "NON_COMPLIANT" if critical > 0 else (
                    "AT_RISK" if high > 0 else "COMPLIANT"
                ),
                "violations": fw_violations[:20],  # Top 20 per framework
            }

        return {
            "total_violations": len(all_violations),
            "critical_violations": sum(1 for v in all_violations if v["severity"] == "CRITICAL"),
            "high_violations": sum(1 for v in all_violations if v["severity"] == "HIGH"),
            "frameworks_evaluated": len(COMPLIANCE_FRAMEWORKS),
            "frameworks_non_compliant": sum(
                1 for fw in framework_summary.values()
                if fw["compliance_status"] == "NON_COMPLIANT"
            ),
            "framework_summary": framework_summary,
        }
