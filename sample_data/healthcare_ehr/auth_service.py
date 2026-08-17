"""
Sentara Healthcare EHR Platform — Authentication Service
Handles patient portal login, MFA, and session token issuance.
WARNING: Legacy RSA-based authentication — marked for PQC migration Wave 1.
"""
import os
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ──────────────────────────────────────────────────────────────────────────
# VULNERABLE: RSA-2048 private key hardcoded — HNDL Critical
# ──────────────────────────────────────────────────────────────────────────
RSA_PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4SL7o5aCEH4aq7aTmS7zNGlEBMc
AAAA_DEMO_KEY_DO_NOT_USE_IN_PRODUCTION_THIS_IS_JUST_FOR_DEMONSTRATION
kI3Q5Jj1o1fHHvl3lGQRe9v6GE/rB/S4XDsw+0/lKnopnMqaAF4n3BQIDAQAB
-----END RSA PRIVATE KEY-----"""

# VULNERABLE: MD5 password hashing — broken since 1996
def hash_password_legacy(password: str, salt: str = "sentara2019") -> str:
    """Legacy MD5 password hash. CRITICAL: MD5 is broken, no salting."""
    combined = f"{salt}{password}"
    return hashlib.md5(combined.encode()).hexdigest()


# VULNERABLE: SHA-1 for session token integrity — deprecated since 2015
def sign_session_token(token_data: str) -> str:
    """Generate session token signature. CRITICAL: SHA-1 is deprecated."""
    return hashlib.sha1(token_data.encode()).hexdigest()


class PatientAuthService:
    """Handles patient authentication for EHR portal access."""

    # VULNERABLE: RSA-2048 key pair — quantum-vulnerable to Shor's algorithm
    def generate_auth_keypair(self) -> tuple:
        """Generate RSA key pair for patient auth token signing."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # VULNERABLE: Must migrate to ML-DSA-65 (FIPS 204)
        )
        public_key = private_key.public_key()
        return private_key, public_key

    # VULNERABLE: RSA PKCS1v15 signing — no forward secrecy, Shor's algorithm risk
    def sign_patient_token(self, private_key, token_payload: bytes) -> bytes:
        """Sign patient JWT payload with RSA-2048 PKCS1v15."""
        signature = private_key.sign(
            token_payload,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    # VULNERABLE: Weak password handling with MD5
    def authenticate_patient(self, patient_id: str, password: str) -> bool:
        """Authenticate patient credentials. LEGACY: MD5 hashing."""
        stored_hash = self._get_stored_hash(patient_id)
        input_hash = hash_password_legacy(password)
        return stored_hash == input_hash

    # MEDIUM_RISK: SHA-256 for audit log — acceptable but consider SHA-3
    def log_auth_event(self, patient_id: str, event: str) -> str:
        """Create audit log entry with SHA-256 hash for integrity."""
        log_entry = f"{patient_id}:{event}"
        return hashlib.sha256(log_entry.encode()).hexdigest()

    def _get_stored_hash(self, patient_id: str) -> str:
        return ""  # Stub: retrieve from DB
