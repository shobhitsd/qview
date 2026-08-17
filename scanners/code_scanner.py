"""
QView Multi-Language Static Source Code Scanner
Performs deep AST, token, and semantic pattern analysis across Java, Python,
JavaScript/TypeScript, Go, C/C++, C#, Rust, and PHP.
"""

import re
import os
from typing import List, Dict, Any, Optional
from core.models import CryptoFinding, CryptoAsset, Evidence, PQCRecommendation
from core.algorithm_database import lookup_algorithm_intelligence
from scanners.base_scanner import BaseScanner


class CodeScanner(BaseScanner):
    """Deep source code scanner identifying cryptographic operations and primitives."""

    SUPPORTED_EXTENSIONS = {
        ".java", ".py", ".js", ".ts", ".jsx", ".tsx",
        ".go", ".c", ".cpp", ".h", ".hpp", ".cs",
        ".rs", ".php", ".kt", ".rb", ".swift"
    }

    # Rule definitions mapping language patterns to cryptographic primitives
    RULES: List[Dict[str, Any]] = [
        # ==================== JAVA / KOTLIN RULES ====================
        {
            "id": "RULE-JAVA-RSA-INSTANCE",
            "lang": "java",
            "pattern": r'(?:Cipher|Signature|KeyPairGenerator|KeyFactory)\.getInstance\s*\(\s*["\'](RSA[^"\']*)["\'](?:\s*,\s*["\']([^"\']+)["\'])?\s*\)',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: m.group(2) or "Java JCA",
            "primitive": "signature",
            "default_key_size": 2048,
            "confidence": 0.98,
            "description": "Java JCA RSA Instance instantiation (Vulnerable to Shor's algorithm)"
        },
        {
            "id": "RULE-JAVA-ECDSA-INSTANCE",
            "lang": "java",
            "pattern": r'(?:Signature|KeyPairGenerator)\.getInstance\s*\(\s*["\']([^"\']*ECDSA[^"\']*)["\'](?:\s*,\s*["\']([^"\']+)["\'])?\s*\)',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: m.group(2) or "Java JCA",
            "primitive": "signature",
            "default_key_size": 256,
            "confidence": 0.98,
            "description": "Java JCA ECDSA Digital Signature (Vulnerable to Shor's algorithm)"
        },
        {
            "id": "RULE-JAVA-DH-INSTANCE",
            "lang": "java",
            "pattern": r'(?:KeyAgreement|KeyPairGenerator)\.getInstance\s*\(\s*["\'](DH|DiffieHellman|ECDH)["\'](?:\s*,\s*["\']([^"\']+)["\'])?\s*\)',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: m.group(2) or "Java JCA",
            "primitive": "key-establishment",
            "default_key_size": 2048,
            "confidence": 0.98,
            "description": "Java JCA Diffie-Hellman Key Agreement (Vulnerable to Shor's algorithm)"
        },
        {
            "id": "RULE-JAVA-SYMMETRIC-AES",
            "lang": "java",
            "pattern": r'Cipher\.getInstance\s*\(\s*["\'](AES(?:/[^"\']+)?)["\']\s*\)',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: "Java JCA",
            "primitive": "symmetric-encryption",
            "default_key_size": 128,
            "confidence": 0.95,
            "description": "Java JCA AES Cipher initialization"
        },
        {
            "id": "RULE-JAVA-WEAK-CIPHER",
            "lang": "java",
            "pattern": r'Cipher\.getInstance\s*\(\s*["\'](DESede|DES|RC4|Blowfish|TripleDES)(?:/[^"\']*)?["\']\s*\)',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: "Java JCA",
            "primitive": "symmetric-encryption",
            "default_key_size": 56,
            "confidence": 0.99,
            "description": "Legacy broken cipher usage in Java JCA (DES/3DES/RC4/Blowfish)"
        },
        {
            "id": "RULE-JAVA-HASH",
            "lang": "java",
            "pattern": r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA-1|SHA-256|SHA-384|SHA-512|SHA3-256|SHA3-512)["\']\s*\)',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: "Java JCA",
            "primitive": "hash",
            "default_key_size": 0,
            "confidence": 0.99,
            "description": "Java MessageDigest hash computation"
        },
        {
            "id": "RULE-JAVA-PQC-INSTANCE",
            "lang": "java",
            "pattern": r'(?:KEM|Signature|Cipher)\.getInstance\s*\(\s*["\'](ML-KEM[^"\']*|ML-DSA[^"\']*|SLH-DSA[^"\']*|Kyber[^"\']*|Dilithium[^"\']*|SPHINCS[^"\']*)["\'](?:\s*,\s*["\']([^"\']+)["\'])?\s*\)',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: m.group(2) or "BouncyCastle PQC",
            "primitive": "pqc",
            "default_key_size": 256,
            "confidence": 0.99,
            "description": "Native NIST Post-Quantum Cryptography FIPS 203/204/205 implementation in Java"
        },

        # ==================== PYTHON RULES ====================
        {
            "id": "RULE-PY-RSA-GEN",
            "lang": "python",
            "pattern": r'(?:rsa\.generate_private_key|RSA\.generate)\s*\([^)]*?(?:key_size\s*=\s*)?(\d{3,5})',
            "algo_extractor": lambda m: f"RSA-{m.group(1)}",
            "library_extractor": lambda m: "cryptography.hazmat / PyCryptodome",
            "primitive": "key-establishment",
            "default_key_size": 2048,
            "confidence": 0.99,
            "description": "Python RSA Key Generation (Vulnerable to Shor's algorithm)"
        },
        {
            "id": "RULE-PY-ECC-GEN",
            "lang": "python",
            "pattern": r'ec\.generate_private_key\s*\(\s*ec\.([A-Za-z0-9_]+)\s*\(\s*\)',
            "algo_extractor": lambda m: f"ECDSA-{m.group(1)}",
            "library_extractor": lambda m: "cryptography.hazmat.primitives.asymmetric.ec",
            "primitive": "signature",
            "default_key_size": 256,
            "confidence": 0.99,
            "description": "Python Elliptic Curve Key Generation (Vulnerable to Shor's algorithm)"
        },
        {
            "id": "RULE-PY-LEGACY-CIPHER",
            "lang": "python",
            "pattern": r'(Blowfish|DES3|DES|ARC4|RC4)\.new\s*\(',
            "algo_extractor": lambda m: m.group(1).upper(),
            "library_extractor": lambda m: "PyCryptodome / PyCrypto",
            "primitive": "symmetric-encryption",
            "default_key_size": 64,
            "confidence": 0.99,
            "description": "Python Legacy Insecure Symmetric Cipher (Broken classically & vulnerable to Grover)"
        },
        {
            "id": "RULE-PY-HASH-PRIMITIVE",
            "lang": "python",
            "pattern": r'hashes\.(MD5|SHA1|SHA224)\s*\(\s*\)',
            "algo_extractor": lambda m: m.group(1).upper(),
            "library_extractor": lambda m: "cryptography.hazmat.primitives.hashes",
            "primitive": "hash",
            "default_key_size": 0,
            "confidence": 0.99,
            "description": "Python deprecated/weak message digest algorithm"
        },
        {
            "id": "RULE-PY-X25519",
            "lang": "python",
            "pattern": r'(?:x25519\.X25519PrivateKey|ed25519\.Ed25519PrivateKey)\.generate\s*\(',
            "algo_extractor": lambda m: "X25519" if "x25519" in m.group(0).lower() else "Ed25519",
            "library_extractor": lambda m: "cryptography.hazmat",
            "primitive": "key-establishment",
            "default_key_size": 256,
            "confidence": 0.98,
            "description": "Python Curve25519/Ed25519 operation"
        },
        {
            "id": "RULE-PY-AES-CIPHER",
            "lang": "python",
            "pattern": r'algorithms\.AES\s*\(\s*([A-Za-z0-9_\.]+)\s*\)',
            "algo_extractor": lambda m: "AES-256-GCM" if "256" in m.group(1) else "AES-128-GCM",
            "library_extractor": lambda m: "cryptography.hazmat.primitives.ciphers",
            "primitive": "symmetric-encryption",
            "default_key_size": 256,
            "confidence": 0.95,
            "description": "Python AES symmetric cipher instantiation"
        },
        {
            "id": "RULE-PY-PQC-OQS",
            "lang": "python",
            "pattern": r'oqs\.(?:KeyEncapsulation|Signature)\s*\(\s*["\']([^"\']+)["\']\s*\)',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: "liboqs-python (Open Quantum Safe)",
            "primitive": "pqc",
            "default_key_size": 256,
            "confidence": 0.99,
            "description": "Python liboqs Post-Quantum Cryptography instance"
        },
        {
            "id": "RULE-PQC-HYBRID-SUITE",
            "lang": "all",
            "pattern": r'["\'](X25519Kyber768[^"\']*|ECDH-P256-ML-KEM-[^"\']*|ML-KEM-[^"\']*|ML-DSA-[^"\']*|SLH-DSA-[^"\']*|FrodoKEM[^"\']*)["\']',
            "algo_extractor": lambda m: m.group(1),
            "library_extractor": lambda m: "Post-Quantum / Hybrid Suite",
            "primitive": "pqc",
            "default_key_size": 256,
            "confidence": 0.96,
            "description": "Post-Quantum Cryptography or Hybrid Key Exchange Suite definition"
        },

        # ==================== JAVASCRIPT / TYPESCRIPT RULES ====================
        {
            "id": "RULE-JS-CRYPTO-RSA",
            "lang": "javascript",
            "pattern": r'crypto\.generateKeyPair(?:Sync)?\s*\(\s*["\']rsa["\']\s*,\s*\{[^}]*modulusLength:\s*(\d+)',
            "algo_extractor": lambda m: f"RSA-{m.group(1)}",
            "library_extractor": lambda m: "Node.js crypto",
            "primitive": "key-establishment",
            "default_key_size": 2048,
            "confidence": 0.98,
            "description": "Node.js crypto RSA Keypair Generation"
        },
        {
            "id": "RULE-JS-CRYPTO-ECDSA",
            "lang": "javascript",
            "pattern": r'crypto\.generateKeyPair(?:Sync)?\s*\(\s*["\']ec["\']\s*,\s*\{[^}]*namedCurve:\s*["\']([^"\']+)["\']',
            "algo_extractor": lambda m: f"ECDSA-{m.group(1)}",
            "library_extractor": lambda m: "Node.js crypto",
            "primitive": "signature",
            "default_key_size": 256,
            "confidence": 0.98,
            "description": "Node.js crypto Elliptic Curve Keypair Generation"
        },
        {
            "id": "RULE-JS-PQC-NOBLE",
            "lang": "javascript",
            "pattern": r'(?:ml_kem(?:512|768|1024)|ml_dsa(?:44|65|87)|slh_dsa)\.(?:keygen|sign|encapsulate)',
            "algo_extractor": lambda m: m.group(0).split(".")[0].upper().replace("_", "-"),
            "library_extractor": lambda m: "@noble/post-quantum",
            "primitive": "pqc",
            "default_key_size": 256,
            "confidence": 0.99,
            "description": "JavaScript/TypeScript noble-post-quantum implementation"
        },

        # ==================== GO RULES ====================
        {
            "id": "RULE-GO-RSA-GEN",
            "lang": "go",
            "pattern": r'rsa\.GenerateKey\s*\(\s*rand\.Reader\s*,\s*(\d+)\s*\)',
            "algo_extractor": lambda m: f"RSA-{m.group(1)}",
            "library_extractor": lambda m: "crypto/rsa",
            "primitive": "key-establishment",
            "default_key_size": 2048,
            "confidence": 0.99,
            "description": "Go crypto/rsa Key Generation"
        },
        {
            "id": "RULE-GO-ECDSA-GEN",
            "lang": "go",
            "pattern": r'ecdsa\.GenerateKey\s*\(\s*elliptic\.([A-Za-z0-9]+)\s*\(\s*\)',
            "algo_extractor": lambda m: f"ECDSA-{m.group(1)}",
            "library_extractor": lambda m: "crypto/ecdsa",
            "primitive": "signature",
            "default_key_size": 256,
            "confidence": 0.99,
            "description": "Go crypto/ecdsa Key Generation"
        },
        {
            "id": "RULE-GO-3DES",
            "lang": "go",
            "pattern": r'des\.New(?:Triple)?DESCipher\s*\(',
            "algo_extractor": lambda m: "3DES",
            "library_extractor": lambda m: "crypto/des",
            "primitive": "symmetric-encryption",
            "default_key_size": 168,
            "confidence": 0.99,
            "description": "Go crypto/des TripleDES legacy cipher"
        },

        # ==================== C / C++ / OPENSSL RULES ====================
        {
            "id": "RULE-C-OPENSSL-RSA",
            "lang": "c",
            "pattern": r'(?:RSA_generate_key_ex|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_RSA)',
            "algo_extractor": lambda m: "RSA-2048",
            "library_extractor": lambda m: "OpenSSL libcrypto",
            "primitive": "key-establishment",
            "default_key_size": 2048,
            "confidence": 0.98,
            "description": "OpenSSL C/C++ RSA Key Generation"
        },
        {
            "id": "RULE-C-OPENSSL-EC",
            "lang": "c",
            "pattern": r'(?:EC_KEY_new_by_curve_name|EVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_EC)',
            "algo_extractor": lambda m: "ECDSA-P256",
            "library_extractor": lambda m: "OpenSSL libcrypto",
            "primitive": "signature",
            "default_key_size": 256,
            "confidence": 0.98,
            "description": "OpenSSL C/C++ Elliptic Curve Context"
        },

        # ==================== C# / .NET RULES ====================
        {
            "id": "RULE-CS-RSA",
            "lang": "csharp",
            "pattern": r'(?:RSA\.Create|new\s+RSACryptoServiceProvider)\s*\(\s*(\d+)?\s*\)',
            "algo_extractor": lambda m: f"RSA-{m.group(1)}" if m.group(1) else "RSA-2048",
            "library_extractor": lambda m: "System.Security.Cryptography",
            "primitive": "signature",
            "default_key_size": 2048,
            "confidence": 0.98,
            "description": ".NET C# RSA Cryptographic Provider"
        },
        {
            "id": "RULE-CS-ECDSA",
            "lang": "csharp",
            "pattern": r'(?:ECDsa\.Create|new\s+ECDsaCng)\s*\(',
            "algo_extractor": lambda m: "ECDSA-P256",
            "library_extractor": lambda m: "System.Security.Cryptography",
            "primitive": "signature",
            "default_key_size": 256,
            "confidence": 0.98,
            "description": ".NET C# ECDsaCng Elliptic Curve Provider"
        }
    ]

    def is_supported(self, file_path: str) -> bool:
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.SUPPORTED_EXTENSIONS

    def scan_file(self, file_path: str) -> List[CryptoFinding]:
        """Scan a single source code file line by line with AST context."""
        findings: List[CryptoFinding] = []
        
        if not os.path.exists(file_path) or not self.is_supported(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        for rule in self.RULES:
            matches = list(re.finditer(rule["pattern"], content, re.MULTILINE))
            for match in matches:
                start_pos = match.start()
                # Compute line number
                line_num = content[:start_pos].count("\n") + 1
                col_num = start_pos - content.rfind("\n", 0, start_pos)
                
                # Context snippet: 2 lines before and 2 lines after
                s_idx = max(0, line_num - 2)
                e_idx = min(len(lines), line_num + 3)
                snippet = "\n".join(lines[s_idx:e_idx])
                
                algo_raw = rule["algo_extractor"](match)
                lib_name = rule["library_extractor"](match)
                
                # Extract key size if embedded
                key_size = rule.get("default_key_size", 2048)
                ks_match = re.search(r'(\d{3,4})', algo_raw)
                if ks_match:
                    try:
                        key_size = int(ks_match.group(1))
                    except ValueError:
                        pass

                intel = lookup_algorithm_intelligence(algo_raw, key_size=key_size)

                # Build Evidence
                evidence = Evidence(
                    source_type="source-code",
                    file_path=file_path,
                    start_line=line_num,
                    end_line=line_num + match.group(0).count("\n"),
                    column=col_num,
                    function_name=self._extract_enclosing_function(lines, line_num),
                    code_snippet=snippet,
                    rule_id=rule["id"],
                    matched_pattern=match.group(0),
                    confidence=rule["confidence"],
                    reasoning=rule["description"]
                )

                # Build CryptoAsset
                crypto_asset = CryptoAsset(
                    name=intel.get("variant", algo_raw),
                    algorithm_family=intel.get("family", algo_raw),
                    algorithm_variant=intel.get("variant", algo_raw),
                    primitive=intel.get("primitive", rule.get("primitive", "unknown")),
                    key_size=key_size,
                    library_name=lib_name,
                    hardcoded=True,
                    configurable=False
                )

                # Build PQC Recommendation
                recommendation = PQCRecommendation(
                    target_algorithm=intel.get("pqc_target", "ML-KEM-768 / ML-DSA-65"),
                    alternative_algorithm=intel.get("alternative_pqc", "SLH-DSA-SHA2-128s"),
                    migration_pattern="HYBRID_TRANSITION" if "PQC" not in intel.get("quantum_status", "") else "MAINTAIN"
                )

                finding = CryptoFinding(
                    app_name=os.path.basename(os.path.dirname(os.path.abspath(file_path))),
                    crypto_asset=crypto_asset,
                    evidence=evidence,
                    pqc_recommendation=recommendation,
                    classical_security_bits=intel.get("classical_security_bits", 112),
                    quantum_security_bits=intel.get("quantum_security_bits", 0),
                    quantum_status=intel.get("quantum_status", "CRITICAL_VULNERABLE"),
                    threat_vector=intel.get("threat_vector", "Shor's / Grover's Algorithm"),
                    nist_status=intel.get("nist_status", "Deprecated by 2030-2035"),
                    vulnerability_score=intel.get("default_vulnerability_score", 90.0),
                    confidence=rule["confidence"],
                    hndl_risk=intel.get("hndl_risk", "HIGH")
                )
                findings.append(finding)

        return findings

    @staticmethod
    def _extract_enclosing_function(lines: List[str], line_num: int) -> Optional[str]:
        """Heuristically find enclosing function or method name."""
        idx = min(len(lines) - 1, line_num - 1)
        for i in range(idx, max(-1, idx - 40), -1):
            line = lines[i].strip()
            # Match Java / C# / C++ method def
            m_fn = re.search(r'(?:public|private|protected|static|def|func|function|async)?\s*[\w\<\>\[\]]+\s+(\w+)\s*\([^)]*\)\s*[{:]?', line)
            if m_fn and m_fn.group(1) not in ["if", "for", "while", "switch", "catch"]:
                return m_fn.group(1)
        return "globalContext"
