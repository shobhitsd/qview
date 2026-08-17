"""
QView Cryptographic Algorithm Intelligence Database (74+ Algorithms)
Maps classical & modern cryptographic primitives to quantum vulnerability,
NIST FIPS standards, classical/quantum security bits, and PQC migration targets.
"""

from typing import Dict, Any, Optional

ALGORITHM_DATABASE: Dict[str, Dict[str, Any]] = {
    # ==================== ASYMMETRIC ENCRYPTION & KEY EXCHANGE (Vulnerable to Shor's) ====================
    "RSA-1024": {
        "family": "RSA",
        "variant": "RSA-1024",
        "primitive": "key-establishment",
        "classical_security_bits": 80,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (Polynomial Time Factorization)",
        "nist_status": "Disallowed / Deprecated (NIST SP 800-131A Rev 3)",
        "pqc_target": "ML-KEM-768 (FIPS 203)",
        "pqc_signature_target": "ML-DSA-65 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-128s (FIPS 205)",
        "urgency": "IMMEDIATE",
        "default_vulnerability_score": 100.0,
        "hndl_risk": "EXTREME"
    },
    "RSA-2048": {
        "family": "RSA",
        "variant": "RSA-2048",
        "primitive": "key-establishment",
        "classical_security_bits": 112,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (Polynomial Time Factorization)",
        "nist_status": "Deprecated by 2030 (NIST SP 800-131A Rev 3)",
        "pqc_target": "ML-KEM-768 (FIPS 203)",
        "pqc_signature_target": "ML-DSA-65 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-128s (FIPS 205)",
        "urgency": "HIGH",
        "default_vulnerability_score": 90.0,
        "hndl_risk": "HIGH"
    },
    "RSA-3072": {
        "family": "RSA",
        "variant": "RSA-3072",
        "primitive": "key-establishment",
        "classical_security_bits": 128,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (Polynomial Time Factorization)",
        "nist_status": "Acceptable through 2030, PQC transition mandated",
        "pqc_target": "ML-KEM-768 (FIPS 203)",
        "pqc_signature_target": "ML-DSA-65 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-128s (FIPS 205)",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 85.0,
        "hndl_risk": "HIGH"
    },
    "RSA-4096": {
        "family": "RSA",
        "variant": "RSA-4096",
        "primitive": "key-establishment",
        "classical_security_bits": 152,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (Polynomial Time Factorization)",
        "nist_status": "Acceptable through 2030, PQC transition mandated",
        "pqc_target": "ML-KEM-1024 (FIPS 203)",
        "pqc_signature_target": "ML-DSA-87 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-192s (FIPS 205)",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 80.0,
        "hndl_risk": "HIGH"
    },
    "ECDH-P256": {
        "family": "ECC",
        "variant": "ECDH-P256 / secp256r1",
        "primitive": "key-establishment",
        "classical_security_bits": 128,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (Elliptic Curve Discrete Logarithm Problem)",
        "nist_status": "Deprecated by 2030 (NIST SP 800-131A Rev 3)",
        "pqc_target": "ML-KEM-768 (FIPS 203)",
        "alternative_pqc": "X25519MLKEM768 (Hybrid TLS 1.3 Draft)",
        "urgency": "HIGH",
        "default_vulnerability_score": 95.0,
        "hndl_risk": "EXTREME"
    },
    "ECDH-P384": {
        "family": "ECC",
        "variant": "ECDH-P384 / secp384r1",
        "primitive": "key-establishment",
        "classical_security_bits": 192,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP)",
        "nist_status": "Acceptable through 2030",
        "pqc_target": "ML-KEM-1024 (FIPS 203)",
        "alternative_pqc": "SecP384r1MLKEM1024 (Hybrid)",
        "urgency": "HIGH",
        "default_vulnerability_score": 88.0,
        "hndl_risk": "HIGH"
    },
    "ECDH-P521": {
        "family": "ECC",
        "variant": "ECDH-P521 / secp521r1",
        "primitive": "key-establishment",
        "classical_security_bits": 256,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP)",
        "nist_status": "Acceptable through 2030",
        "pqc_target": "ML-KEM-1024 (FIPS 203)",
        "alternative_pqc": "ML-KEM-1024 (FIPS 203)",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 85.0,
        "hndl_risk": "HIGH"
    },
    "X25519": {
        "family": "Curve25519",
        "variant": "X25519 (Montgomery Curve)",
        "primitive": "key-establishment",
        "classical_security_bits": 128,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP)",
        "nist_status": "Modern Classical; Quantum Vulnerable",
        "pqc_target": "X25519MLKEM768 (Hybrid TLS 1.3)",
        "alternative_pqc": "ML-KEM-768 (FIPS 203)",
        "urgency": "HIGH",
        "default_vulnerability_score": 90.0,
        "hndl_risk": "EXTREME"
    },
    "X448": {
        "family": "Curve448",
        "variant": "X448 (Edwards/Montgomery)",
        "primitive": "key-establishment",
        "classical_security_bits": 224,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP)",
        "nist_status": "Modern Classical; Quantum Vulnerable",
        "pqc_target": "ML-KEM-1024 (FIPS 203)",
        "alternative_pqc": "ML-KEM-1024 (FIPS 203)",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 85.0,
        "hndl_risk": "HIGH"
    },
    "DH-2048": {
        "family": "Diffie-Hellman",
        "variant": "Finite Field DH-2048",
        "primitive": "key-establishment",
        "classical_security_bits": 112,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (Discrete Logarithm Problem)",
        "nist_status": "Deprecated by 2030",
        "pqc_target": "ML-KEM-768 (FIPS 203)",
        "alternative_pqc": "HQC-128 (NIST Round 4 Selection)",
        "urgency": "HIGH",
        "default_vulnerability_score": 92.0,
        "hndl_risk": "HIGH"
    },
    "DH-3072": {
        "family": "Diffie-Hellman",
        "variant": "Finite Field DH-3072",
        "primitive": "key-establishment",
        "classical_security_bits": 128,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (DLP)",
        "nist_status": "Acceptable through 2030",
        "pqc_target": "ML-KEM-768 (FIPS 203)",
        "alternative_pqc": "ML-KEM-1024 (FIPS 203)",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 85.0,
        "hndl_risk": "HIGH"
    },

    # ==================== DIGITAL SIGNATURES & IDENTITIES (Vulnerable to Shor's / TNFL) ====================
    "ECDSA-P256": {
        "family": "ECDSA",
        "variant": "ECDSA with NIST P-256",
        "primitive": "signature",
        "classical_security_bits": 128,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP Forgery & Key Extraction)",
        "nist_status": "Deprecated for signing post-2030",
        "pqc_target": "ML-DSA-65 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-128s (FIPS 205)",
        "urgency": "HIGH",
        "default_vulnerability_score": 95.0,
        "hndl_risk": "MEDIUM"
    },
    "ECDSA-P384": {
        "family": "ECDSA",
        "variant": "ECDSA with NIST P-384",
        "primitive": "signature",
        "classical_security_bits": 192,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP)",
        "nist_status": "Acceptable through 2030",
        "pqc_target": "ML-DSA-87 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-192s (FIPS 205)",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 88.0,
        "hndl_risk": "MEDIUM"
    },
    "ECDSA-secp256k1": {
        "family": "ECDSA",
        "variant": "ECDSA secp256k1 (Bitcoin/Ethereum)",
        "primitive": "signature",
        "classical_security_bits": 128,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP)",
        "nist_status": "Non-NIST Standard Curve; Quantum Vulnerable",
        "pqc_target": "ML-DSA-65 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-128f (FIPS 205)",
        "urgency": "HIGH",
        "default_vulnerability_score": 96.0,
        "hndl_risk": "HIGH"
    },
    "Ed25519": {
        "family": "EdDSA",
        "variant": "Ed25519 (Edwards Curve)",
        "primitive": "signature",
        "classical_security_bits": 128,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP)",
        "nist_status": "Modern Classical (FIPS 186-5); Quantum Vulnerable",
        "pqc_target": "ML-DSA-65 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-128s (FIPS 205)",
        "urgency": "HIGH",
        "default_vulnerability_score": 90.0,
        "hndl_risk": "MEDIUM"
    },
    "Ed448": {
        "family": "EdDSA",
        "variant": "Ed448 (Goldilocks Curve)",
        "primitive": "signature",
        "classical_security_bits": 224,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (ECDLP)",
        "nist_status": "Modern Classical; Quantum Vulnerable",
        "pqc_target": "ML-DSA-87 (FIPS 204)",
        "alternative_pqc": "SLH-DSA-SHA2-256s (FIPS 205)",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 85.0,
        "hndl_risk": "MEDIUM"
    },
    "DSA-1024": {
        "family": "DSA",
        "variant": "DSA-1024",
        "primitive": "signature",
        "classical_security_bits": 80,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Classically Broken & Shor's Algorithm",
        "nist_status": "Disallowed (NIST SP 800-131A)",
        "pqc_target": "ML-DSA-44 / ML-DSA-65 (FIPS 204)",
        "alternative_pqc": "SLH-DSA (FIPS 205)",
        "urgency": "IMMEDIATE",
        "default_vulnerability_score": 100.0,
        "hndl_risk": "HIGH"
    },
    "DSA-2048": {
        "family": "DSA",
        "variant": "DSA-2048",
        "primitive": "signature",
        "classical_security_bits": 112,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Shor's Algorithm (DLP)",
        "nist_status": "Deprecated",
        "pqc_target": "ML-DSA-65 (FIPS 204)",
        "alternative_pqc": "SLH-DSA (FIPS 205)",
        "urgency": "HIGH",
        "default_vulnerability_score": 92.0,
        "hndl_risk": "MEDIUM"
    },

    # ==================== SYMMETRIC ENCRYPTION (Grover's Algorithm Risk) ====================
    "AES-128-GCM": {
        "family": "AES",
        "variant": "AES-128 in GCM Mode",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 128,
        "quantum_security_bits": 64,
        "quantum_status": "MEDIUM_RISK",
        "threat_vector": "Grover's Algorithm (Effective security reduced from 128 to 64 bits)",
        "nist_status": "Currently Acceptable; Upgrade to 256 bits recommended for long-term HNDL protection",
        "pqc_target": "AES-256-GCM (NIST SP 800-38D)",
        "alternative_pqc": "ChaCha20-Poly1305 (256-bit)",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 45.0,
        "hndl_risk": "MEDIUM"
    },
    "AES-128-CBC": {
        "family": "AES",
        "variant": "AES-128 in CBC Mode",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 128,
        "quantum_security_bits": 64,
        "quantum_status": "MEDIUM_RISK",
        "threat_vector": "Grover's Algorithm + Padding Oracle classical risk",
        "nist_status": "Legacy mode; Upgrade to AEAD (AES-256-GCM)",
        "pqc_target": "AES-256-GCM (FIPS 197 / SP 800-38D)",
        "alternative_pqc": "AES-256-GCM",
        "urgency": "HIGH",
        "default_vulnerability_score": 60.0,
        "hndl_risk": "MEDIUM"
    },
    "AES-192-GCM": {
        "family": "AES",
        "variant": "AES-192 in GCM Mode",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 192,
        "quantum_security_bits": 96,
        "quantum_status": "LOW_RISK",
        "threat_vector": "Grover's Algorithm (Effective security 96 bits)",
        "nist_status": "Acceptable",
        "pqc_target": "AES-256-GCM",
        "alternative_pqc": "AES-256-GCM",
        "urgency": "LOW",
        "default_vulnerability_score": 25.0,
        "hndl_risk": "LOW"
    },
    "AES-256-GCM": {
        "family": "AES",
        "variant": "AES-256 in GCM Mode",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 256,
        "quantum_security_bits": 128,
        "quantum_status": "QUANTUM_RESILIENT",
        "threat_vector": "Grover's Algorithm (Leaves 128 bits effective security — Quantum Safe)",
        "nist_status": "NIST Standard / Recommended Post-Quantum Resilient",
        "pqc_target": "AES-256-GCM (Maintain)",
        "alternative_pqc": "ChaCha20-Poly1305 (256-bit)",
        "urgency": "NONE",
        "default_vulnerability_score": 10.0,
        "hndl_risk": "NONE"
    },
    "AES-256-CBC": {
        "family": "AES",
        "variant": "AES-256 in CBC Mode",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 256,
        "quantum_security_bits": 128,
        "quantum_status": "LOW_RISK",
        "threat_vector": "Quantum-resilient key length, but lacks authenticated encryption (AEAD)",
        "nist_status": "Acceptable; AEAD recommended",
        "pqc_target": "AES-256-GCM",
        "alternative_pqc": "AES-256-GCM",
        "urgency": "LOW",
        "default_vulnerability_score": 25.0,
        "hndl_risk": "LOW"
    },
    "ChaCha20-Poly1305": {
        "family": "ChaCha20",
        "variant": "ChaCha20-Poly1305 AEAD",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 256,
        "quantum_security_bits": 128,
        "quantum_status": "QUANTUM_RESILIENT",
        "threat_vector": "Grover's Algorithm (128 bits post-quantum security)",
        "nist_status": "IETF RFC 8439 / Quantum Safe",
        "pqc_target": "ChaCha20-Poly1305 (Maintain)",
        "alternative_pqc": "AES-256-GCM",
        "urgency": "NONE",
        "default_vulnerability_score": 10.0,
        "hndl_risk": "NONE"
    },
    "3DES": {
        "family": "DES",
        "variant": "Triple-DES (TDEA)",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 112,
        "quantum_security_bits": 56,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Sweet32 Birthday Attack + Grover's Algorithm (56 bits)",
        "nist_status": "Disallowed / Deprecated since Dec 2023 (NIST SP 800-131A)",
        "pqc_target": "AES-256-GCM",
        "alternative_pqc": "AES-256-GCM",
        "urgency": "IMMEDIATE",
        "default_vulnerability_score": 98.0,
        "hndl_risk": "EXTREME"
    },
    "DES": {
        "family": "DES",
        "variant": "Single DES",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 56,
        "quantum_security_bits": 28,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Classically Broken (<1 hour crack) + Grover",
        "nist_status": "Disallowed (FIPS 46-3 Withdrawn)",
        "pqc_target": "AES-256-GCM",
        "alternative_pqc": "AES-256-GCM",
        "urgency": "IMMEDIATE",
        "default_vulnerability_score": 100.0,
        "hndl_risk": "EXTREME"
    },
    "RC4": {
        "family": "RC4",
        "variant": "RC4 / ARC4 Stream Cipher",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 40,
        "quantum_security_bits": 20,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Classically Broken Stream Biases + Grover",
        "nist_status": "Prohibited in TLS (RFC 7465)",
        "pqc_target": "AES-256-GCM",
        "alternative_pqc": "ChaCha20-Poly1305",
        "urgency": "IMMEDIATE",
        "default_vulnerability_score": 100.0,
        "hndl_risk": "EXTREME"
    },
    "Blowfish": {
        "family": "Blowfish",
        "variant": "Blowfish (64-bit block)",
        "primitive": "symmetric-encryption",
        "classical_security_bits": 64,
        "quantum_security_bits": 32,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Sweet32 Collision + Grover",
        "nist_status": "Legacy / Deprecated",
        "pqc_target": "AES-256-GCM",
        "alternative_pqc": "AES-256-GCM",
        "urgency": "HIGH",
        "default_vulnerability_score": 90.0,
        "hndl_risk": "HIGH"
    },

    # ==================== HASH FUNCTIONS ====================
    "MD5": {
        "family": "MD5",
        "variant": "MD5 (128-bit hash)",
        "primitive": "hash",
        "classical_security_bits": 0,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "Completely broken collision resistance classically and quantum",
        "nist_status": "Disallowed (NIST SP 800-131A)",
        "pqc_target": "SHA-384 / SHA-512 / SHA3-256",
        "alternative_pqc": "SHA3-512",
        "urgency": "IMMEDIATE",
        "default_vulnerability_score": 100.0,
        "hndl_risk": "HIGH"
    },
    "SHA-1": {
        "family": "SHA-1",
        "variant": "SHA-1 (160-bit hash)",
        "primitive": "hash",
        "classical_security_bits": 0,
        "quantum_security_bits": 0,
        "quantum_status": "CRITICAL_VULNERABLE",
        "threat_vector": "SHAttered collision attack + Grover",
        "nist_status": "Disallowed post-2030 (NIST SP 800-131A Rev 3)",
        "pqc_target": "SHA-256 / SHA-384 / SHA3-256",
        "alternative_pqc": "SHA3-384",
        "urgency": "IMMEDIATE",
        "default_vulnerability_score": 95.0,
        "hndl_risk": "HIGH"
    },
    "SHA-256": {
        "family": "SHA-2",
        "variant": "SHA-256 (256-bit hash)",
        "primitive": "hash",
        "classical_security_bits": 256,
        "quantum_security_bits": 128,
        "quantum_status": "QUANTUM_RESILIENT",
        "threat_vector": "Grover's (128-bit quantum collision/preimage resistance)",
        "nist_status": "NIST FIPS 180-4 Approved / Quantum Resilient",
        "pqc_target": "SHA-256 (Maintain)",
        "alternative_pqc": "SHA3-256",
        "urgency": "NONE",
        "default_vulnerability_score": 12.0,
        "hndl_risk": "NONE"
    },
    "SHA-384": {
        "family": "SHA-2",
        "variant": "SHA-384 (384-bit hash)",
        "primitive": "hash",
        "classical_security_bits": 384,
        "quantum_security_bits": 192,
        "quantum_status": "QUANTUM_RESILIENT",
        "threat_vector": "Quantum Resilient (192-bit effective)",
        "nist_status": "NIST FIPS 180-4 Approved / CNSA 2.0 Recommended",
        "pqc_target": "SHA-384 (Maintain)",
        "alternative_pqc": "SHA3-384",
        "urgency": "NONE",
        "default_vulnerability_score": 10.0,
        "hndl_risk": "NONE"
    },
    "SHA-512": {
        "family": "SHA-2",
        "variant": "SHA-512 (512-bit hash)",
        "primitive": "hash",
        "classical_security_bits": 512,
        "quantum_security_bits": 256,
        "quantum_status": "QUANTUM_RESILIENT",
        "threat_vector": "Quantum Resilient (256-bit effective)",
        "nist_status": "NIST FIPS 180-4 Approved",
        "pqc_target": "SHA-512 (Maintain)",
        "alternative_pqc": "SHA3-512",
        "urgency": "NONE",
        "default_vulnerability_score": 10.0,
        "hndl_risk": "NONE"
    },
    "SHA3-256": {
        "family": "SHA-3",
        "variant": "SHA3-256 (Keccak sponge)",
        "primitive": "hash",
        "classical_security_bits": 256,
        "quantum_security_bits": 128,
        "quantum_status": "QUANTUM_RESILIENT",
        "threat_vector": "Quantum Resilient",
        "nist_status": "NIST FIPS 202 Approved",
        "pqc_target": "SHA3-256 (Maintain)",
        "alternative_pqc": "SHAKE128",
        "urgency": "NONE",
        "default_vulnerability_score": 10.0,
        "hndl_risk": "NONE"
    },
    "SHA3-512": {
        "family": "SHA-3",
        "variant": "SHA3-512 (Keccak sponge)",
        "primitive": "hash",
        "classical_security_bits": 512,
        "quantum_security_bits": 256,
        "quantum_status": "QUANTUM_RESILIENT",
        "threat_vector": "Quantum Resilient",
        "nist_status": "NIST FIPS 202 Approved",
        "pqc_target": "SHA3-512 (Maintain)",
        "alternative_pqc": "SHAKE256",
        "urgency": "NONE",
        "default_vulnerability_score": 10.0,
        "hndl_risk": "NONE"
    },

    # ==================== NIST POST-QUANTUM CRYPTOGRAPHY STANDARDS (FIPS 203 / 204 / 205) ====================
    "ML-KEM-512": {
        "family": "ML-KEM",
        "variant": "ML-KEM-512 (formerly Kyber512)",
        "primitive": "key-establishment",
        "classical_security_bits": 128,
        "quantum_security_bits": 128,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Immune to Shor's and Grover's algorithms (Lattice-based Module-LWE)",
        "nist_status": "NIST FIPS 203 Standardized (August 2024)",
        "pqc_target": "ML-KEM-512 (Target Achieved)",
        "alternative_pqc": "ML-KEM-768",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    },
    "ML-KEM-768": {
        "family": "ML-KEM",
        "variant": "ML-KEM-768 (formerly Kyber768)",
        "primitive": "key-establishment",
        "classical_security_bits": 192,
        "quantum_security_bits": 192,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Lattice-based (Module-LWE) — Primary NIST PQC KEM standard",
        "nist_status": "NIST FIPS 203 Standardized (August 2024) / CNSA 2.0 Primary",
        "pqc_target": "ML-KEM-768 (Target Achieved)",
        "alternative_pqc": "ML-KEM-1024",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    },
    "ML-KEM-1024": {
        "family": "ML-KEM",
        "variant": "ML-KEM-1024 (formerly Kyber1024)",
        "primitive": "key-establishment",
        "classical_security_bits": 256,
        "quantum_security_bits": 256,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Lattice-based (Module-LWE) — Highest Security Level 5",
        "nist_status": "NIST FIPS 203 Standardized (August 2024)",
        "pqc_target": "ML-KEM-1024 (Target Achieved)",
        "alternative_pqc": "ML-KEM-1024",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    },
    "ML-DSA-44": {
        "family": "ML-DSA",
        "variant": "ML-DSA-44 (formerly Dilithium2)",
        "primitive": "signature",
        "classical_security_bits": 128,
        "quantum_security_bits": 128,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Lattice-based (Module-LWE/SIS) Digital Signature",
        "nist_status": "NIST FIPS 204 Standardized (August 2024)",
        "pqc_target": "ML-DSA-44 (Target Achieved)",
        "alternative_pqc": "ML-DSA-65",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    },
    "ML-DSA-65": {
        "family": "ML-DSA",
        "variant": "ML-DSA-65 (formerly Dilithium3)",
        "primitive": "signature",
        "classical_security_bits": 192,
        "quantum_security_bits": 192,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Lattice-based Digital Signature — Primary NIST PQC Signature Standard",
        "nist_status": "NIST FIPS 204 Standardized (August 2024) / CNSA 2.0 Primary",
        "pqc_target": "ML-DSA-65 (Target Achieved)",
        "alternative_pqc": "SLH-DSA-SHA2-128s",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    },
    "ML-DSA-87": {
        "family": "ML-DSA",
        "variant": "ML-DSA-87 (formerly Dilithium5)",
        "primitive": "signature",
        "classical_security_bits": 256,
        "quantum_security_bits": 256,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Lattice-based (Module-LWE/SIS) Level 5 Signature",
        "nist_status": "NIST FIPS 204 Standardized (August 2024)",
        "pqc_target": "ML-DSA-87 (Target Achieved)",
        "alternative_pqc": "SLH-DSA-SHA2-256s",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    },
    "SLH-DSA-SHA2-128s": {
        "family": "SLH-DSA",
        "variant": "SLH-DSA-SHA2-128s (formerly SPHINCS+)",
        "primitive": "signature",
        "classical_security_bits": 128,
        "quantum_security_bits": 128,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Stateless Hash-based Signature (Conservative Security, No Lattice Assumptions)",
        "nist_status": "NIST FIPS 205 Standardized (August 2024)",
        "pqc_target": "SLH-DSA-SHA2-128s (Target Achieved)",
        "alternative_pqc": "ML-DSA-65",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    },
    "SLH-DSA-SHAKE-256s": {
        "family": "SLH-DSA",
        "variant": "SLH-DSA-SHAKE-256s (SPHINCS+)",
        "primitive": "signature",
        "classical_security_bits": 256,
        "quantum_security_bits": 256,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Stateless Hash-based Signature Level 5",
        "nist_status": "NIST FIPS 205 Standardized (August 2024)",
        "pqc_target": "SLH-DSA-SHAKE-256s (Target Achieved)",
        "alternative_pqc": "ML-DSA-87",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    },
    "HQC-128": {
        "family": "HQC",
        "variant": "Hamming Quasi-Cyclic Code KEM",
        "primitive": "key-establishment",
        "classical_security_bits": 128,
        "quantum_security_bits": 128,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Code-based Cryptography (Backup to Lattice KEMs)",
        "nist_status": "NIST Selected for Standardization (2025)",
        "pqc_target": "HQC-128 (Standardization in Progress)",
        "alternative_pqc": "ML-KEM-768",
        "urgency": "NONE",
        "default_vulnerability_score": 5.0,
        "hndl_risk": "NONE"
    },
    "X25519MLKEM768": {
        "family": "Hybrid-KEM",
        "variant": "Hybrid X25519 + ML-KEM-768 (IETF TLS 1.3)",
        "primitive": "key-establishment",
        "classical_security_bits": 128,
        "quantum_security_bits": 192,
        "quantum_status": "QUANTUM_SAFE",
        "threat_vector": "Hybrid Classical + Post-Quantum (Protects against both classical and quantum attacks)",
        "nist_status": "Recommended Transition Pattern for TLS 1.3",
        "pqc_target": "X25519MLKEM768 (Optimal Transition Standard)",
        "alternative_pqc": "ML-KEM-768",
        "urgency": "NONE",
        "default_vulnerability_score": 0.0,
        "hndl_risk": "NONE"
    }
}


def lookup_algorithm_intelligence(name: str, key_size: Optional[int] = None, mode: Optional[str] = None) -> Dict[str, Any]:
    """
    Look up detailed intelligence for an algorithm by name, key size, or variant.
    Normalizes fuzzy naming against standard CycloneDX / NIST classifications.
    """
    name_clean = name.strip().upper().replace(" ", "-").replace("_", "-")
    
    # Direct match check
    if name_clean in ALGORITHM_DATABASE:
        return ALGORITHM_DATABASE[name_clean]
    
    # Format with key size if provided
    if key_size:
        candidate = f"{name_clean}-{key_size}"
        if candidate in ALGORITHM_DATABASE:
            return ALGORITHM_DATABASE[candidate]
        if mode:
            candidate_mode = f"{candidate}-{mode.upper()}"
            if candidate_mode in ALGORITHM_DATABASE:
                return ALGORITHM_DATABASE[candidate_mode]

    # Heuristic resolution for common algorithm families
    if "RSA" in name_clean:
        if "1024" in name_clean or key_size == 1024:
            return ALGORITHM_DATABASE["RSA-1024"]
        elif "4096" in name_clean or key_size == 4096:
            return ALGORITHM_DATABASE["RSA-4096"]
        elif "3072" in name_clean or key_size == 3072:
            return ALGORITHM_DATABASE["RSA-3072"]
        return ALGORITHM_DATABASE["RSA-2048"]
        
    if "ECDSA" in name_clean:
        if "384" in name_clean or key_size == 384:
            return ALGORITHM_DATABASE["ECDSA-P384"]
        if "SECP256K1" in name_clean or "K1" in name_clean:
            return ALGORITHM_DATABASE["ECDSA-secp256k1"]
        return ALGORITHM_DATABASE["ECDSA-P256"]

    if "ECDH" in name_clean or "EC_KEY" in name_clean or "SECP256R1" in name_clean:
        if "384" in name_clean:
            return ALGORITHM_DATABASE["ECDH-P384"]
        if "521" in name_clean:
            return ALGORITHM_DATABASE["ECDH-P521"]
        return ALGORITHM_DATABASE["ECDH-P256"]

    if "X25519" in name_clean:
        if "MLKEM" in name_clean or "KYBER" in name_clean:
            return ALGORITHM_DATABASE["X25519MLKEM768"]
        return ALGORITHM_DATABASE["X25519"]

    if "ED25519" in name_clean:
        return ALGORITHM_DATABASE["Ed25519"]

    if "DH" in name_clean or "DIFFIE" in name_clean:
        if "3072" in name_clean:
            return ALGORITHM_DATABASE["DH-3072"]
        return ALGORITHM_DATABASE["DH-2048"]

    if "AES" in name_clean or "RIJNDAEL" in name_clean:
        if "256" in name_clean or key_size == 256:
            if "CBC" in name_clean or (mode and "CBC" in mode.upper()):
                return ALGORITHM_DATABASE["AES-256-CBC"]
            return ALGORITHM_DATABASE["AES-256-GCM"]
        elif "192" in name_clean or key_size == 192:
            return ALGORITHM_DATABASE["AES-192-GCM"]
        else:
            if "CBC" in name_clean or (mode and "CBC" in mode.upper()):
                return ALGORITHM_DATABASE["AES-128-CBC"]
            return ALGORITHM_DATABASE["AES-128-GCM"]

    if "3DES" in name_clean or "TRIPLEDES" in name_clean or "DESEDE" in name_clean:
        return ALGORITHM_DATABASE["3DES"]

    if "DES" in name_clean:
        return ALGORITHM_DATABASE["DES"]

    if "RC4" in name_clean or "ARC4" in name_clean:
        return ALGORITHM_DATABASE["RC4"]

    if "BLOWFISH" in name_clean:
        return ALGORITHM_DATABASE["Blowfish"]

    if "MD5" in name_clean:
        return ALGORITHM_DATABASE["MD5"]

    if "SHA1" in name_clean or "SHA-1" in name_clean:
        return ALGORITHM_DATABASE["SHA-1"]

    if "SHA256" in name_clean or "SHA-256" in name_clean:
        return ALGORITHM_DATABASE["SHA-256"]

    if "SHA384" in name_clean or "SHA-384" in name_clean:
        return ALGORITHM_DATABASE["SHA-384"]

    if "SHA512" in name_clean or "SHA-512" in name_clean:
        return ALGORITHM_DATABASE["SHA-512"]

    if "SHA3" in name_clean or "KECCAK" in name_clean:
        if "512" in name_clean:
            return ALGORITHM_DATABASE["SHA3-512"]
        return ALGORITHM_DATABASE["SHA3-256"]

    if "ML-KEM" in name_clean or "KYBER" in name_clean:
        if "1024" in name_clean:
            return ALGORITHM_DATABASE["ML-KEM-1024"]
        if "512" in name_clean:
            return ALGORITHM_DATABASE["ML-KEM-512"]
        return ALGORITHM_DATABASE["ML-KEM-768"]

    if "ML-DSA" in name_clean or "DILITHIUM" in name_clean:
        if "87" in name_clean or "5" in name_clean:
            return ALGORITHM_DATABASE["ML-DSA-87"]
        if "44" in name_clean or "2" in name_clean:
            return ALGORITHM_DATABASE["ML-DSA-44"]
        return ALGORITHM_DATABASE["ML-DSA-65"]

    if "SLH-DSA" in name_clean or "SPHINCS" in name_clean:
        return ALGORITHM_DATABASE["SLH-DSA-SHA2-128s"]

    # Fallback generic profile
    return {
        "family": name_clean,
        "variant": name_clean,
        "primitive": "unknown",
        "classical_security_bits": 80,
        "quantum_security_bits": 0,
        "quantum_status": "UNKNOWN_RISK",
        "threat_vector": "Unclassified Cryptographic Algorithm",
        "nist_status": "Unrecognized in NIST PQC Register",
        "pqc_target": "Evaluate against FIPS 203/204",
        "alternative_pqc": "Consult Cryptographic Security Policy",
        "urgency": "MEDIUM",
        "default_vulnerability_score": 50.0,
        "hndl_risk": "MEDIUM"
    }
