"""
QView PQC Migration Planner
Generates structured Post-Quantum Cryptography migration roadmaps and code remediation recipes.
"""

from typing import List, Dict, Any
from core.models import CryptoFinding, PQCRecommendation


class MigrationPlanner:
    """Classifies findings into migration waves and generates actionable engineering work items."""

    @staticmethod
    def generate_code_snippet(finding: CryptoFinding) -> str:
        """Generate language-specific code remediation recipes."""
        fam = finding.crypto_asset.algorithm_family.upper()
        lang = "JAVA"
        if finding.evidence.file_path:
            fp = finding.evidence.file_path.lower()
            if fp.endswith(".py"):
                lang = "PYTHON"
            elif fp.endswith(".js") or fp.endswith(".ts"):
                lang = "JAVASCRIPT"
            elif fp.endswith(".go"):
                lang = "GO"
            elif fp.endswith(".cs"):
                lang = "CSHARP"
            elif fp.endswith(".cpp") or fp.endswith(".c") or fp.endswith(".h"):
                lang = "CPP"
            elif fp.endswith(".rs"):
                lang = "RUST"

        if "RSA" in fam or "ECDSA" in fam or "ED25519" in fam or "DSA" in fam:
            if lang == "JAVA":
                return (
                    "// [PQC Migration: NIST FIPS 204 ML-DSA-65 / BouncyCastle PQC]\n"
                    "// Replace legacy RSA/ECDSA signature with quantum-safe ML-DSA:\n"
                    "import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;\n"
                    "Security.addProvider(new BouncyCastlePQCProvider());\n\n"
                    "// Instantiate ML-DSA-65 Signature:\n"
                    "Signature sig = Signature.getInstance(\"ML-DSA-65\", \"BCPQC\");\n"
                    "sig.initSign(pqcPrivateKey);\n"
                    "sig.update(dataToSign);\n"
                    "byte[] signatureBytes = sig.sign();"
                )
            elif lang == "PYTHON":
                return (
                    "# [PQC Migration: NIST FIPS 204 ML-DSA / liboqs-python or PQClean]\n"
                    "import oqs\n\n"
                    "# Sign with quantum-safe ML-DSA-65:\n"
                    "with oqs.Signature('ML-DSA-65') as signer:\n"
                    "    signer.generate_keypair()\n"
                    "    signature = signer.sign(message)\n"
                    "    is_valid = signer.verify(message, signature, signer.export_public_key())"
                )
            elif lang == "JAVASCRIPT":
                return (
                    "// [PQC Migration: NIST FIPS 204 ML-DSA via @noble/post-quantum]\n"
                    "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';\n\n"
                    "// Generate keys and sign message:\n"
                    "const keys = ml_dsa65.keygen();\n"
                    "const signature = ml_dsa65.sign(keys.secretKey, messageBytes);\n"
                    "const isValid = ml_dsa65.verify(signature, messageBytes, keys.publicKey);"
                )
            elif lang == "GO":
                return (
                    "// [PQC Migration: NIST FIPS 204 ML-DSA in Go via circl/mldsa]\n"
                    "import \"github.com/cloudflare/circl/sign/mldsa/mldsa65\"\n\n"
                    "pk, sk, err := mldsa65.GenerateKey(rand.Reader)\n"
                    "sig := mldsa65.Sign(sk, messageBytes)\n"
                    "isValid := mldsa65.Verify(pk, messageBytes, sig)"
                )
            elif lang == "CSHARP":
                return (
                    "// [PQC Migration: C# / BouncyCastle.Cryptography.Pqc]\n"
                    "using Org.BouncyCastle.Pqc.Crypto.MlDsa;\n\n"
                    "var keyGen = new MlDsaKeyPairGenerator();\n"
                    "keyGen.Init(new MlDsaKeyGenerationParameters(new SecureRandom(), MlDsaParameters.ml_dsa_65));\n"
                    "var keyPair = keyGen.GenerateKeyPair();"
                )

        if "ECDH" in fam or "DH" in fam or "X25519" in fam or ("RSA" in fam and finding.crypto_asset.primitive == "key-establishment"):
            if lang == "JAVA":
                return (
                    "// [PQC Migration: NIST FIPS 203 ML-KEM-768 / Hybrid TLS 1.3]\n"
                    "// Key Encapsulation Mechanism (KEM) replacement:\n"
                    "KEM kem = KEM.getInstance(\"ML-KEM-768\", \"BCPQC\");\n"
                    "KEM.Encapsulator enc = kem.newEncapsulator(pqcPublicKey);\n"
                    "KEM.Encapsulated encRes = enc.encapsulate();\n"
                    "SecretKey sharedSecret = encRes.getKey();"
                )
            elif lang == "PYTHON":
                return (
                    "# [PQC Migration: NIST FIPS 203 ML-KEM-768]\n"
                    "import oqs\n\n"
                    "with oqs.KeyEncapsulation('ML-KEM-768') as server_kem:\n"
                    "    public_key = server_kem.generate_keypair()\n"
                    "    # Client encapsulates:\n"
                    "    ciphertext, client_secret = client_kem.encap_secret(public_key)\n"
                    "    # Server decapsulates:\n"
                    "    server_secret = server_kem.decap_secret(ciphertext)"
                )
            elif lang == "JAVASCRIPT":
                return (
                    "// [PQC Migration: NIST FIPS 203 ML-KEM-768 via @noble/post-quantum]\n"
                    "import { ml_kem768 } from '@noble/post-quantum/ml-kem';\n\n"
                    "const aliceKeys = ml_kem768.keygen();\n"
                    "const { cipherText, sharedSecret: bobSecret } = ml_kem768.encapsulate(aliceKeys.publicKey);\n"
                    "const aliceSecret = ml_kem768.decapsulate(cipherText, aliceKeys.secretKey);"
                )
            elif lang == "GO":
                return (
                    "// [PQC Migration: NIST FIPS 203 ML-KEM-768 in Go via circl/kem/kyber]\n"
                    "import \"github.com/cloudflare/circl/kem/kyber/kyber768\"\n\n"
                    "scheme := kyber768.Scheme()\n"
                    "pk, sk, _ := scheme.GenerateKeyPair()\n"
                    "ct, ssClient, _ := scheme.Encapsulate(pk)\n"
                    "ssServer, _ := scheme.Decapsulate(sk, ct)"
                )

        if "3DES" in fam or "DES" in fam or "RC4" in fam or "BLOWFISH" in fam or "AES-128" in fam:
            return (
                "// [Symmetric Upgrade: Migrate to AES-256-GCM / 256-bit Quantum-Resilient AEAD]\n"
                "// Replace weak cipher with authenticated AES-256-GCM:\n"
                "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                "GCMParameterSpec spec = new GCMParameterSpec(128, iv);\n"
                "cipher.init(Cipher.ENCRYPT_MODE, aes256SecretKey, spec);"
            )

        if "MD5" in fam or "SHA-1" in fam:
            return (
                "// [Hash Upgrade: Replace broken MD5/SHA-1 with SHA-256 or SHA-384]\n"
                "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");\n"
                "byte[] hash = digest.digest(inputBytes);"
            )

        return "// Apply crypto agility provider and upgrade to NIST FIPS 203/204/205 approved algorithms."

    @classmethod
    def assign_migration_wave(cls, finding: CryptoFinding) -> str:
        """Assign wave based on business criticality, longevity, and vulnerability."""
        if finding.quantum_status == "UNKNOWN_RISK" or not finding.crypto_asset.name:
            return "WAVE_0_DISCOVERY"
            
        if finding.business_criticality >= 4 and finding.quantum_status == "CRITICAL_VULNERABLE":
            return "WAVE_1_CRITICAL"
            
        if finding.quantum_status == "CRITICAL_VULNERABLE" or (finding.quantum_status == "MEDIUM_RISK" and finding.business_criticality >= 3):
            return "WAVE_2_HIGH"
            
        if finding.quantum_status == "MEDIUM_RISK" or finding.crypto_asset.hardcoded:
            return "WAVE_3_STANDARD"
            
        return "WAVE_4_LEGACY"

    @classmethod
    def plan_recommendations(cls, findings: List[CryptoFinding]) -> List[CryptoFinding]:
        """Enrich all findings with concrete migration waves, recipes, and recommendations."""
        for f in findings:
            wave = cls.assign_migration_wave(f)
            code_snippet = cls.generate_code_snippet(f)
            
            f.pqc_recommendation.migration_wave = wave
            f.pqc_recommendation.suggested_code_snippet = code_snippet
            
            if wave == "WAVE_1_CRITICAL":
                f.pqc_recommendation.effort_estimate = "HIGH"
                f.pqc_recommendation.remediation_steps = [
                    "Isolate internet-facing endpoints and verify TLS 1.3 hybrid support (X25519MLKEM768).",
                    "Upgrade underlying crypto library provider to BouncyCastle 1.78+ / OpenSSL 3.2+ PQC.",
                    "Generate and deploy ML-DSA-65 signature certificates or hybrid composite certs.",
                    "Execute regression testing with automated crypto agility test harness."
                ]
            elif wave == "WAVE_2_HIGH":
                f.pqc_recommendation.effort_estimate = "MEDIUM"
                f.pqc_recommendation.remediation_steps = [
                    "Replace internal asymmetric key exchange with ML-KEM-768.",
                    "Update configuration parameters to negotiate PQC cipher suites.",
                    "Deploy upgraded service to staging environment and benchmark handshake latency."
                ]
            elif wave == "WAVE_3_STANDARD":
                f.pqc_recommendation.effort_estimate = "MEDIUM"
                f.pqc_recommendation.remediation_steps = [
                    "Extract hardcoded algorithm identifiers to centralized environment configuration.",
                    "Upgrade symmetric encryption to AES-256-GCM AEAD mode.",
                    "Decommission legacy hash functions (MD5 / SHA-1) in favor of SHA-256."
                ]
            else:
                f.pqc_recommendation.effort_estimate = "LOW"
                f.pqc_recommendation.remediation_steps = [
                    "Catalogue unmapped crypto dependencies in inventory.",
                    "Monitor upstream vendor roadmaps for PQC compliance commitments."
                ]
                
        return findings
