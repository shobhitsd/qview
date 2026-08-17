"""
Adversarial & Evasive Cryptographic Patterns (Python)
Inspired by CryptoAPI-Bench, MASC Mutation, and NIST PQC Edge Vectors.
Tests dynamic construction, legacy weak ciphers, variable dispatch, and hybrid PQC.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, padding
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import Blowfish, DES, DES3, ARC4

# ── Case 1: Dynamic / Aliased Algorithm Names ──────────────────────────────
algo_prefix = "RS"
algo_suffix = "A"
assembled_algo = f"{algo_prefix}{algo_suffix}-2048"

# ── Case 2: Insecure Legacy Symmetric & Broken Ciphers (Grover/Classical vulnerable)
legacy_des_cipher = DES.new(b"8bytekey", DES.MODE_ECB)
legacy_blowfish = Blowfish.new(b"blowfish_key_16b", Blowfish.MODE_CBC, iv=b"12345678")
legacy_arc4 = ARC4.new(b"weak_rc4_stream_key")
legacy_3des = DES3.new(b"16byte3deskey123", DES3.MODE_CBC, iv=b"12345678")

# ── Case 3: Weak Legacy Hashes ──────────────────────────────────────────────
weak_hash_md4 = hashes.MD5() # Insecure hash MD5
weak_hash_sha1 = hashes.SHA1() # Deprecated SHA-1

# ── Case 4: Classical Public Key Cryptography (Shor's Vulnerable) ───────────
private_key_rsa = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

ec_key_weak_curve = ec.generate_private_key(ec.SECP224R1()) # Shor's vulnerable ECC
ec_key_p384 = ec.generate_private_key(ec.SECP384R1())       # Shor's vulnerable ECC

# ── Case 5: Hybrid Post-Quantum & Classical Key Exchange ────────────────────
# Hybrid PQC: Combining X25519 classical with ML-KEM-768 lattice KEM
hybrid_kex_suite = "X25519Kyber768Draft00"
hybrid_nist_fips = "ECDH-P256-ML-KEM-768"

# ── Case 6: Pure NIST Post-Quantum Approved ─────────────────────────────────
pqc_kem = "ML-KEM-1024" # NIST FIPS 203 Approved (Level V)
pqc_sig = "SLH-DSA-SHAKE-256f" # NIST FIPS 205 Stateless Hash Signature
