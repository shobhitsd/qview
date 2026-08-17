"""
QView Cloud Crypto & IaC Scanner (V1 Agent 9)
Discovers and evaluates cryptographic configurations in Cloud Infrastructure as Code (IaC),
Terraform, CloudFormation, Kubernetes Helm, AWS KMS, Azure Key Vault, and GCP KMS configurations.
"""

import re
import os
from typing import List
from core.models import CryptoFinding, CryptoAsset, Evidence, PQCRecommendation
from scanners.base_scanner import BaseScanner


class CloudCryptoScanner(BaseScanner):
    """Scans Terraform (.tf), CloudFormation (.json, .yaml), and Cloud configs for crypto parameters."""

    SUPPORTED_EXTENSIONS = {".tf", ".tfvars", ".template", ".cfn", ".json", ".yaml", ".yml"}

    # Cloud IaC Cryptographic Patterns
    PATTERNS = [
        # AWS KMS Key Specs
        {
            "id": "RULE-CLOUD-AWS-KMS-RSA",
            "name": "AWS KMS RSA Key",
            "regex": re.compile(r'customer_master_key_spec\s*=\s*["\'](RSA_\d+|RSA_2048|RSA_3072|RSA_4096)["\']', re.IGNORECASE),
            "algorithm": "RSA",
            "provider": "AWS KMS",
            "primitive": "key-establishment",
            "quantum_status": "CRITICAL_VULNERABLE",
            "pqc_target": "ML-KEM-768",
            "description": "AWS KMS customer managed asymmetric key configured with quantum-vulnerable RSA key spec."
        },
        {
            "id": "RULE-CLOUD-AWS-KMS-ECC",
            "name": "AWS KMS ECC Curve",
            "regex": re.compile(r'customer_master_key_spec\s*=\s*["\'](ECC_NIST_P256|ECC_NIST_P384|ECC_NIST_P521|ECC_SECG_P256K1)["\']', re.IGNORECASE),
            "algorithm": "ECDSA",
            "provider": "AWS KMS",
            "primitive": "signature",
            "quantum_status": "CRITICAL_VULNERABLE",
            "pqc_target": "ML-DSA-65",
            "description": "AWS KMS customer managed key using elliptic curve cryptography vulnerable to Shor's algorithm."
        },
        {
            "id": "RULE-CLOUD-AWS-S3-SSE",
            "name": "AWS S3 Server-Side Encryption AES-256",
            "regex": re.compile(r'sse_algorithm\s*=\s*["\'](AES256|aws:kms)["\']', re.IGNORECASE),
            "algorithm": "AES-256",
            "provider": "AWS S3",
            "primitive": "symmetric-encryption",
            "quantum_status": "QUANTUM_SAFE",
            "pqc_target": "AES-256-GCM (Maintain)",
            "description": "AWS S3 bucket encryption with AES-256 (Quantum Resistant against Grover search)."
        },
        # Azure Key Vault Key Specs
        {
            "id": "RULE-CLOUD-AZURE-KV-RSA",
            "name": "Azure Key Vault RSA Key",
            "regex": re.compile(r'key_type\s*=\s*["\']RSA["\'].*?key_size\s*=\s*(\d+)', re.IGNORECASE | re.DOTALL),
            "algorithm": "RSA",
            "provider": "Azure Key Vault",
            "primitive": "key-establishment",
            "quantum_status": "CRITICAL_VULNERABLE",
            "pqc_target": "ML-KEM-768",
            "description": "Azure Key Vault Managed HSM/Key object provisioned with RSA key."
        },
        {
            "id": "RULE-CLOUD-AZURE-KV-EC",
            "name": "Azure Key Vault EC Key",
            "regex": re.compile(r'key_type\s*=\s*["\']EC["\'].*?curve\s*=\s*["\'](P-256|P-384|P-521|SECP256K1)["\']', re.IGNORECASE | re.DOTALL),
            "algorithm": "ECDSA",
            "provider": "Azure Key Vault",
            "primitive": "signature",
            "quantum_status": "CRITICAL_VULNERABLE",
            "pqc_target": "ML-DSA-65",
            "description": "Azure Key Vault Elliptic Curve key susceptible to quantum discrete log attacks."
        },
        # GCP Cloud KMS Key Specs
        {
            "id": "RULE-CLOUD-GCP-KMS-RSA",
            "name": "GCP Cloud KMS Asymmetric RSA",
            "regex": re.compile(r'algorithm\s*=\s*["\'](RSA_SIGN_PSS_\d+_SHA\d+|RSA_DECRYPT_OAEP_\d+_SHA\d+)["\']', re.IGNORECASE),
            "algorithm": "RSA",
            "provider": "GCP Cloud KMS",
            "primitive": "signature",
            "quantum_status": "CRITICAL_VULNERABLE",
            "pqc_target": "ML-DSA-65",
            "description": "Google Cloud KMS key version template configured with quantum-vulnerable RSA algorithm."
        }
    ]

    def scan_file(self, file_path: str, app_name: str = "Enterprise Cloud") -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS and not os.path.basename(file_path).startswith("Dockerfile"):
            return findings

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        for p in self.PATTERNS:
            for match in p["regex"].finditer(content):
                # Line number
                start_pos = match.start()
                line_no = content.count('\n', 0, start_pos) + 1
                snippet = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else match.group(0)

                matched_val = match.group(1) if match.groups() else ""
                key_size = 2048
                if "4096" in matched_val:
                    key_size = 4096
                elif "3072" in matched_val:
                    key_size = 3072
                elif "P256" in matched_val or "P-256" in matched_val:
                    key_size = 256
                elif "P384" in matched_val or "P-384" in matched_val:
                    key_size = 384
                elif "P521" in matched_val or "P-521" in matched_val:
                    key_size = 521

                algo_name = p["algorithm"]
                is_vuln = p["quantum_status"] == "CRITICAL_VULNERABLE"

                evidence = Evidence(
                    source_type="config",
                    file_path=file_path,
                    start_line=line_no,
                    end_line=line_no,
                    code_snippet=snippet[:180],
                    rule_id=p["id"],
                    detection_method="CLOUD_IAC_STATIC_ANALYSIS",
                    confidence=0.95,
                    reasoning=p["description"]
                )

                crypto_asset = CryptoAsset(
                    name=f"{algo_name}-{key_size}" if is_vuln else algo_name,
                    algorithm_family=algo_name,
                    algorithm_variant=f"{algo_name}-{key_size}",
                    primitive=p["primitive"],
                    key_size=key_size,
                    library_name=p["provider"],
                    provider=p["provider"],
                    hardcoded=True,
                    configurable=True
                )

                recommendation = PQCRecommendation(
                    target_algorithm=p["pqc_target"],
                    migration_pattern="HYBRID_TRANSITION" if is_vuln else "MAINTAIN"
                )

                finding = CryptoFinding(
                    app_name=app_name,
                    crypto_asset=crypto_asset,
                    evidence=evidence,
                    pqc_recommendation=recommendation,
                    classical_security_bits=112 if key_size >= 2048 else 80,
                    quantum_security_bits=0 if is_vuln else 256,
                    quantum_status=p["quantum_status"],
                    threat_vector="Shor's Algorithm (KMS/Vault Compromise)" if is_vuln else "Grover Resilient",
                    nist_status="Deprecated by 2030-2035 (NIST SP 800-131A)" if is_vuln else "NIST Approved",
                    vulnerability_score=90.0 if is_vuln else 10.0,
                    confidence=0.95,
                    hndl_risk="HIGH" if is_vuln else "LOW"
                )
                findings.append(finding)

        return findings
