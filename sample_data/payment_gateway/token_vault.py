"""
Payment Gateway Token Vault & Settlement Service
Handles credit card tokenization, bank settlement signatures, and secure key exchanges.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
import os

class TokenVault:
    def __init__(self):
        # Vulnerable: RSA-2048 keypair generation for settlement transactions
        self.rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Vulnerable: ECDSA NIST P-256 for instant API webhooks
        self.ec_key = ec.generate_private_key(ec.SECP256R1())

    def encrypt_card_token(self, card_bytes: bytes, key_128: bytes) -> bytes:
        # Vulnerable: AES-128 in CBC mode (Subject to Grover's algorithm halving and padding oracle)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key_128), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return iv + encryptor.update(card_bytes) + encryptor.finalize()

    def generate_sha1_transaction_digest(self, payload: bytes) -> bytes:
        # Vulnerable: Legacy SHA-1 hash for legacy banking partner
        digest = hashes.Hash(hashes.SHA1())
        digest.update(payload)
        return digest.finalize()
