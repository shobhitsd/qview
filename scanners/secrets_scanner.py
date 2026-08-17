"""
QView Secrets & Configuration Scanner
Detects hardcoded cryptographic keys, certificates, weak cipher configurations,
and cryptographic misconfigurations in YAML, ENV, JSON, .properties, IaC, Dockerfile, etc.
"""

import re
import os
from typing import List, Dict, Any
from core.models import CryptoFinding, CryptoAsset, Evidence, PQCRecommendation
from core.algorithm_database import lookup_algorithm_intelligence
from scanners.base_scanner import BaseScanner


class SecretsScanner(BaseScanner):
    """Detects hardcoded secrets, cryptographic keys, and weak crypto configurations."""

    SUPPORTED_EXTENSIONS = {
        ".yaml", ".yml", ".json", ".env", ".properties", ".ini", ".cfg",
        ".conf", ".config", ".toml", ".tf", ".tfvars", ".hcl",
        ".dockerfile", "", ".sh", ".bash", ".xml", ".pem", ".key",
        ".p12", ".pfx", ".jks", ".pkcs12"
    }

    # Regex patterns for secrets & crypto config detection
    RULES: List[Dict[str, Any]] = [
        # ── Hardcoded PEM private keys ──────────────────────────────────────
        {
            "id": "SECRET-PEM-RSA-PRIVATE",
            "pattern": r'-----BEGIN RSA PRIVATE KEY-----',
            "algo": "RSA", "variant": "RSA-Private-Key",
            "primitive": "private-key", "quantum_status": "CRITICAL_VULNERABLE",
            "confidence": 1.0, "severity": "CRITICAL",
            "description": "Hardcoded RSA private key material detected in plaintext. "
                           "Immediate rotation required. Vulnerable to Shor's algorithm.",
            "hndl_risk": "CRITICAL",
            "pqc_target": "ML-KEM-768 (FIPS 203) — Generate new PQC key pair, never hardcode.",
        },
        {
            "id": "SECRET-PEM-EC-PRIVATE",
            "pattern": r'-----BEGIN EC PRIVATE KEY-----',
            "algo": "ECC", "variant": "EC-Private-Key",
            "primitive": "private-key", "quantum_status": "CRITICAL_VULNERABLE",
            "confidence": 1.0, "severity": "CRITICAL",
            "description": "Hardcoded EC private key detected in plaintext. Vulnerable to Shor's algorithm.",
            "hndl_risk": "CRITICAL",
            "pqc_target": "ML-DSA-65 (FIPS 204) — Generate new PQC key pair.",
        },
        {
            "id": "SECRET-PEM-PRIVATE-KEY",
            "pattern": r'-----BEGIN PRIVATE KEY-----',
            "algo": "PKCS8-Private-Key", "variant": "PKCS8-Private-Key",
            "primitive": "private-key", "quantum_status": "CRITICAL_VULNERABLE",
            "confidence": 1.0, "severity": "CRITICAL",
            "description": "Hardcoded PKCS#8 private key detected. Likely RSA or ECC. Vulnerable.",
            "hndl_risk": "CRITICAL",
            "pqc_target": "ML-KEM-768 or ML-DSA-65 (FIPS 203/204)",
        },
        # ── Hardcoded symmetric keys / passwords ───────────────────────────
        {
            "id": "SECRET-HARDCODED-AES-KEY",
            "pattern": r'(?:aes[_\-]?key|encryption[_\-]?key|secret[_\-]?key|crypto[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/=]{16,})["\']',
            "algo": "AES", "variant": "AES-Hardcoded-Key",
            "primitive": "symmetric-encryption", "quantum_status": "MEDIUM_RISK",
            "confidence": 0.90, "severity": "HIGH",
            "description": "Hardcoded AES encryption key detected. Keys must be managed via secrets vault, not embedded in code or config.",
            "hndl_risk": "HIGH",
            "pqc_target": "AES-256 via HashiCorp Vault / AWS KMS. Never hardcode symmetric keys.",
        },
        {
            "id": "SECRET-HARDCODED-JWT-SECRET",
            "pattern": r'(?:jwt[_\-]?secret|token[_\-]?secret|signing[_\-]?key|jwt[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9@#$!%^&*()_+=\-]{8,})["\']',
            "algo": "JWT-HMAC", "variant": "JWT-Hardcoded-Secret",
            "primitive": "mac", "quantum_status": "MEDIUM_RISK",
            "confidence": 0.85, "severity": "HIGH",
            "description": "Hardcoded JWT signing secret. If algorithm is RS256/ES256/PS256, also quantum-vulnerable. Move to PQC ML-DSA for production.",
            "hndl_risk": "MEDIUM",
            "pqc_target": "ML-DSA-65 (FIPS 204) for JWT if using asymmetric signing.",
        },
        # ── Weak TLS/SSL configuration ──────────────────────────────────────
        {
            "id": "SECRET-WEAK-TLS-VERSION",
            "pattern": r'(?:tls[_\-]?version|ssl[_\-]?version|min[_\-]?tls|protocol[_\-]?version)\s*[=:]\s*["\']?(TLS1\.0|TLS1\.1|TLSv1\.0|TLSv1\.1|SSLv2|SSLv3)["\']?',
            "algo": "TLS", "variant": "TLS-Legacy",
            "primitive": "protocol", "quantum_status": "MEDIUM_RISK",
            "confidence": 0.97, "severity": "HIGH",
            "description": "Legacy TLS 1.0/1.1 configured. These protocols are deprecated (RFC 8996), support weak cipher suites, and must be disabled. Minimum: TLS 1.2, Recommended: TLS 1.3.",
            "hndl_risk": "MEDIUM",
            "pqc_target": "Upgrade to TLS 1.3 with Hybrid ML-KEM-768 key exchange.",
        },
        {
            "id": "SECRET-WEAK-CIPHER-CONFIG",
            "pattern": r'(?:cipher[_\-]?suite|ciphers|ssl[_\-]?ciphers)\s*[=:]\s*["\']([^"\']*(?:RC4|DES|3DES|MD5|NULL|EXPORT|anon|NULL-SHA)[^"\']*)["\']',
            "algo": "Weak-Cipher", "variant": "Weak-TLS-Cipher-Suite",
            "primitive": "symmetric-encryption", "quantum_status": "CRITICAL_VULNERABLE",
            "confidence": 0.95, "severity": "CRITICAL",
            "description": "Broken or weak cipher suite explicitly configured (RC4, DES, 3DES, EXPORT, NULL, anon). Immediately remove these from cipher suite list.",
            "hndl_risk": "CRITICAL",
            "pqc_target": "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3 only)",
        },
        # ── Weak algorithm configs in YAML/ENV ──────────────────────────────
        {
            "id": "SECRET-WEAK-ALGO-RSA1024",
            "pattern": r'(?:key[_\-]?size|rsa[_\-]?bits|key[_\-]?bits)\s*[=:]\s*["\']?(?:512|768|1024)["\']?',
            "algo": "RSA", "variant": "RSA-1024",
            "primitive": "key-establishment", "quantum_status": "CRITICAL_VULNERABLE",
            "confidence": 0.95, "severity": "CRITICAL",
            "description": "RSA key size configured below 2048 bits. RSA-1024 is classically broken (NIST deprecated since 2013) AND quantum-vulnerable. Must be upgraded to ML-KEM.",
            "hndl_risk": "CRITICAL",
            "pqc_target": "ML-KEM-768 (FIPS 203)",
        },
        {
            "id": "SECRET-WEAK-HASH-MD5",
            "pattern": r'(?:hash[_\-]?algorithm|digest[_\-]?algorithm|checksum[_\-]?type)\s*[=:]\s*["\']?(MD5|md5|SHA1|sha1|SHA-1|sha-1)["\']?',
            "algo": "MD5-SHA1", "variant": "Broken-Hash",
            "primitive": "hash", "quantum_status": "CRITICAL_VULNERABLE",
            "confidence": 0.97, "severity": "CRITICAL",
            "description": "Broken hash algorithm (MD5 or SHA-1) explicitly configured. MD5 is collision-broken, SHA-1 deprecated by NIST since 2015. Both inadequate for integrity and authentication.",
            "hndl_risk": "HIGH",
            "pqc_target": "SHA-256 minimum, SHA-512 / SHA-3-512 recommended for long-lived data.",
        },
        # ── Disabled certificate validation ─────────────────────────────────
        {
            "id": "SECRET-DISABLED-TLS-VERIFY",
            "pattern": r'(?:verify[_\-]?ssl|verify[_\-]?cert|ssl[_\-]?verify|tls[_\-]?verify|check[_\-]?cert)\s*[=:]\s*(?:false|False|FALSE|0|no|No|NO|"false"|\'false\')',
            "algo": "TLS-Disabled-Verify", "variant": "TLS-Certificate-Validation-Disabled",
            "primitive": "protocol", "quantum_status": "CRITICAL_VULNERABLE",
            "confidence": 0.99, "severity": "CRITICAL",
            "description": "TLS certificate verification explicitly disabled. This makes ALL encryption useless against MITM attacks. This is a critical misuse of cryptography regardless of algorithm used.",
            "hndl_risk": "CRITICAL",
            "pqc_target": "Re-enable certificate validation. Use proper CA trust chains.",
        },
        # ── AWS/Cloud crypto misconfigs ──────────────────────────────────────
        {
            "id": "SECRET-AWS-ACCESS-KEY",
            "pattern": r'(?:aws[_\-]?access[_\-]?key[_\-]?id|AWS_ACCESS_KEY_ID)\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})["\']?',
            "algo": "AWS-IAM-Credential", "variant": "Hardcoded-AWS-Key",
            "primitive": "credential", "quantum_status": "MEDIUM_RISK",
            "confidence": 0.99, "severity": "CRITICAL",
            "description": "Hardcoded AWS Access Key ID detected. If exposed, grants unauthorized access to AWS KMS and cryptographic resources. Rotate immediately via IAM.",
            "hndl_risk": "HIGH",
            "pqc_target": "Use IAM Roles/Instance Profiles. Never hardcode credentials.",
        },
        {
            "id": "SECRET-KMS-KEY-UNROTATED",
            "pattern": r'(?:enable[_\-]?key[_\-]?rotation|key[_\-]?rotation[_\-]?enabled)\s*[=:]\s*(?:false|False|FALSE|0)',
            "algo": "KMS-Key", "variant": "KMS-No-Rotation",
            "primitive": "key-management", "quantum_status": "MEDIUM_RISK",
            "confidence": 0.88, "severity": "HIGH",
            "description": "KMS key rotation explicitly disabled. Symmetric keys should be auto-rotated annually at minimum. Static long-lived keys increase HNDL exposure.",
            "hndl_risk": "MEDIUM",
            "pqc_target": "Enable KMS key rotation. Plan migration to PQC-capable HSM.",
        },
        # ── Weak SSH configs ─────────────────────────────────────────────────
        {
            "id": "SECRET-WEAK-SSH-KEX",
            "pattern": r'(?:KexAlgorithms|kex[_\-]?algorithms)\s*[=:]\s*["\']?([^\n"\']*(?:diffie-hellman-group1|diffie-hellman-group14)[^\n"\']*)["\']?',
            "algo": "DH", "variant": "SSH-Weak-KEX",
            "primitive": "key-establishment", "quantum_status": "CRITICAL_VULNERABLE",
            "confidence": 0.95, "severity": "CRITICAL",
            "description": "Weak SSH key exchange algorithm configured (DH Group 1/14). These use small DH parameters vulnerable to both classical and Shor's algorithm attacks.",
            "hndl_risk": "HIGH",
            "pqc_target": "Use curve25519-sha256 or sntrup761x25519-sha512@openssh.com (hybrid PQC KEX).",
        },
        # ── IaC / Terraform misconfigs ───────────────────────────────────────
        {
            "id": "SECRET-TF-UNENCRYPTED-STORAGE",
            "pattern": r'(?:encrypted|server_side_encryption)\s*=\s*(?:false|False|FALSE)',
            "algo": "Storage-Encryption", "variant": "Unencrypted-Storage",
            "primitive": "symmetric-encryption", "quantum_status": "MEDIUM_RISK",
            "confidence": 0.85, "severity": "HIGH",
            "description": "Cloud storage encryption explicitly disabled in IaC. Data at rest is unprotected. Enable AES-256 server-side encryption immediately.",
            "hndl_risk": "HIGH",
            "pqc_target": "Enable AES-256 SSE. Plan migration to PQC-capable KMS keys.",
        },
        # ── Hardcoded passwords used as crypto material ─────────────────────
        {
            "id": "SECRET-HARDCODED-KEYSTORE-PASSWORD",
            "pattern": r'(?:keystore[_\-]?password|truststore[_\-]?password|key[_\-]?pass|storepass)\s*[=:]\s*["\']([^"\']{4,})["\']',
            "algo": "JKS-Keystore", "variant": "Keystore-Hardcoded-Password",
            "primitive": "key-management", "quantum_status": "MEDIUM_RISK",
            "confidence": 0.90, "severity": "HIGH",
            "description": "Hardcoded Java keystore password. Keystores containing RSA/ECC keys are HNDL targets. Rotate keystore contents to ML-DSA / ML-KEM.",
            "hndl_risk": "HIGH",
            "pqc_target": "Externalize passwords to vault. Migrate keystore keys to ML-DSA-65 (FIPS 204).",
        },
    ]

    def scan_file(self, file_path: str) -> List[CryptoFinding]:
        """Scan a configuration/secrets file for cryptographic misconfigurations."""
        ext = os.path.splitext(file_path)[1].lower()
        basename = os.path.basename(file_path).lower()

        # Check supported extensions or known config filenames
        known_names = {
            ".env", "dockerfile", ".dockerignore", "makefile", "jenkinsfile",
            ".gitignore", "terraform.tfvars", "application.properties",
            "application.yml", "application.yaml", "bootstrap.yml",
            "logback.xml", "log4j.properties", "nginx.conf", "apache.conf",
            "sshd_config", "ssh_config", "openssl.cnf"
        }
        if ext not in self.SUPPORTED_EXTENSIONS and basename not in known_names:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
                lines = content.splitlines()
        except Exception:
            return []

        findings: List[CryptoFinding] = []

        for rule in self.RULES:
            pattern = rule["pattern"]
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                    # Find line number of match
                    start_pos = match.start()
                    line_num = content[:start_pos].count("\n") + 1
                    snippet = lines[line_num - 1].strip() if line_num <= len(lines) else match.group(0)

                    # Redact actual secret values in snippets for safety
                    redacted_snippet = re.sub(
                        r'([=:]\s*["\']?)([A-Za-z0-9+/=]{20,})(["\']?)',
                        r'\1[REDACTED]\3', snippet
                    )

                    algo_info = lookup_algorithm_intelligence(rule["algo"])
                    classical_bits = algo_info.get("classical_security_bits", 0) if algo_info else 0
                    quantum_bits = algo_info.get("quantum_security_bits", 0) if algo_info else 0

                    evidence = Evidence(
                        source_type="config-secret",
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        code_snippet=redacted_snippet,
                        rule_id=rule["id"],
                        matched_pattern=pattern[:80],
                        detection_method="REGEX_CONFIG_ANALYSIS",
                        confidence=rule["confidence"],
                        reasoning=rule["description"],
                    )

                    pqc_rec = PQCRecommendation(
                        target_algorithm=rule.get("pqc_target", "See NIST FIPS 203/204/205"),
                        migration_pattern="DIRECT_REPLACEMENT",
                        migration_wave="WAVE_1_CRITICAL" if rule["severity"] == "CRITICAL" else "WAVE_2_HIGH",
                        effort_estimate="LOW",
                        remediation_steps=[
                            f"Identified Issue: {rule['description']}",
                            f"Immediate Action: Remove hardcoded value, rotate any exposed material",
                            f"PQC Target: {rule.get('pqc_target', 'Consult NIST PQC migration guide')}",
                            "Reference: NIST SP 800-131A Rev 3, NIST SP 800-208",
                        ]
                    )

                    asset = CryptoAsset(
                        name=f"{rule['variant']} @ {os.path.basename(file_path)}:{line_num}",
                        algorithm_family=rule["algo"],
                        algorithm_variant=rule["variant"],
                        primitive=rule["primitive"],
                        hardcoded=True,
                        configurable=False,
                    )

                    finding = CryptoFinding(
                        assessment_id="",
                        crypto_asset=asset,
                        evidence=evidence,
                        pqc_recommendation=pqc_rec,
                        quantum_status=rule["quantum_status"],
                        threat_vector="Configuration Misconfiguration / Secrets Exposure",
                        nist_status="Non-compliant — See NIST SP 800-131A Rev 3",
                        classical_security_bits=classical_bits,
                        quantum_security_bits=quantum_bits,
                        vulnerability_score=95.0 if rule["severity"] == "CRITICAL" else 75.0,
                        qei_score=90.0 if rule["severity"] == "CRITICAL" else 70.0,
                        cai_score=10.0,  # Hardcoded = zero agility
                        confidence=rule["confidence"],
                        hndl_risk=rule.get("hndl_risk", "HIGH"),
                    )
                    findings.append(finding)

            except re.error:
                continue

        return findings
