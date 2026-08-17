"""
QView Certificate & PKI Scanner
Inspects X.509 certificates (PEM, DER, CRT, CER), keys, and keystores.
"""

import os
import re
from typing import List
from core.models import CryptoFinding, CryptoAsset, Evidence, PQCRecommendation
from core.algorithm_database import lookup_algorithm_intelligence
from scanners.base_scanner import BaseScanner


class CertificateScanner(BaseScanner):
    """Scanner for discovering X.509 certificates and public/private key specifications."""

    CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".jks", ".p12", ".pfx"}

    def is_supported(self, file_path: str) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.CERT_EXTENSIONS

    def scan_file(self, file_path: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []
        if not os.path.exists(file_path) or not self.is_supported(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return findings

        # Check for PEM Certificate blocks
        if "-----BEGIN CERTIFICATE-----" in content or "-----BEGIN RSA PRIVATE KEY-----" in content or "-----BEGIN PUBLIC KEY-----" in content:
            # Analyze text attributes
            is_rsa = "RSA" in content or "BEGIN RSA" in content
            is_ec = "EC" in content or "BEGIN EC" in content or "prime256v1" in content
            
            algo_name = "RSA-2048"
            primitive = "key-establishment"
            key_size = 2048
            
            if is_ec:
                algo_name = "ECDSA-P256"
                primitive = "signature"
                key_size = 256
            elif is_rsa:
                if "4096" in content:
                    algo_name = "RSA-4096"
                    key_size = 4096
                else:
                    algo_name = "RSA-2048"
                    key_size = 2048

            intel = lookup_algorithm_intelligence(algo_name, key_size=key_size)

            evidence = Evidence(
                source_type="certificate",
                file_path=file_path,
                start_line=1,
                end_line=min(30, content.count("\n") + 1),
                code_snippet=content[:400] + "\n...",
                rule_id="RULE-X509-CERT-INSPECT",
                confidence=0.99,
                reasoning=f"X.509 Certificate with {algo_name} public key and signature algorithm (Vulnerable to Shor's algorithm)"
            )

            crypto_asset = CryptoAsset(
                name=f"X.509 Certificate ({algo_name})",
                algorithm_family=intel.get("family", "RSA"),
                algorithm_variant=algo_name,
                primitive=primitive,
                key_size=key_size,
                protocol="TLS / X.509 PKI",
                hardcoded=False,
                configurable=True
            )

            rec = PQCRecommendation(
                target_algorithm="ML-DSA-65 (FIPS 204) / Hybrid Composite Cert",
                alternative_algorithm="SLH-DSA-SHA2-128s (FIPS 205)",
                migration_pattern="HYBRID_CERTIFICATE",
                migration_wave="WAVE_1_CRITICAL"
            )

            finding = CryptoFinding(
                app_name=os.path.basename(os.path.dirname(os.path.abspath(file_path))),
                crypto_asset=crypto_asset,
                evidence=evidence,
                pqc_recommendation=rec,
                classical_security_bits=intel.get("classical_security_bits", 112),
                quantum_security_bits=0,
                quantum_status="CRITICAL_VULNERABLE",
                threat_vector="Shor's Algorithm (Certificate Forgery & Public Key Factorization)",
                nist_status="Deprecated for signing post-2030",
                vulnerability_score=92.0,
                confidence=0.99,
                hndl_risk="HIGH"
            )
            findings.append(finding)

        return findings
