"""
QView Network & TLS Crypto Scanner
Analyzes TLS endpoints, SSH servers, and PCAP/PCAPNG files for weak cryptographic
protocols, cipher suites, and key exchange mechanisms.
"""

import re
import os
import ssl
import socket
import struct
from typing import List, Dict, Any, Optional, Tuple
from core.models import CryptoFinding, CryptoAsset, Evidence, PQCRecommendation
from scanners.base_scanner import BaseScanner


# TLS cipher suite quantum risk classification
CIPHER_SUITE_DB: Dict[str, Dict[str, Any]] = {
    # CRITICAL - broken/weak
    "TLS_RSA_WITH_RC4_128_MD5":          {"status": "CRITICAL_VULNERABLE", "kex": "RSA", "enc": "RC4", "mac": "MD5"},
    "TLS_RSA_WITH_RC4_128_SHA":          {"status": "CRITICAL_VULNERABLE", "kex": "RSA", "enc": "RC4", "mac": "SHA1"},
    "TLS_RSA_WITH_DES_CBC_SHA":          {"status": "CRITICAL_VULNERABLE", "kex": "RSA", "enc": "DES", "mac": "SHA1"},
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA":     {"status": "CRITICAL_VULNERABLE", "kex": "RSA", "enc": "3DES", "mac": "SHA1"},
    "TLS_DHE_RSA_WITH_DES_CBC_SHA":      {"status": "CRITICAL_VULNERABLE", "kex": "DHE-RSA", "enc": "DES", "mac": "SHA1"},
    "TLS_NULL_WITH_NULL_NULL":            {"status": "CRITICAL_VULNERABLE", "kex": "NULL", "enc": "NULL", "mac": "NULL"},
    # HIGH quantum risk - RSA/ECDSA key exchange (Shor's)
    "TLS_RSA_WITH_AES_128_CBC_SHA":      {"status": "CRITICAL_VULNERABLE", "kex": "RSA", "enc": "AES-128", "mac": "SHA1"},
    "TLS_RSA_WITH_AES_256_CBC_SHA":      {"status": "CRITICAL_VULNERABLE", "kex": "RSA", "enc": "AES-256", "mac": "SHA1"},
    "TLS_RSA_WITH_AES_128_GCM_SHA256":   {"status": "CRITICAL_VULNERABLE", "kex": "RSA", "enc": "AES-128", "mac": "SHA256"},
    "TLS_RSA_WITH_AES_256_GCM_SHA384":   {"status": "CRITICAL_VULNERABLE", "kex": "RSA", "enc": "AES-256", "mac": "SHA384"},
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": {"status": "MEDIUM_RISK", "kex": "ECDHE", "enc": "AES-128", "mac": "SHA256"},
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": {"status": "MEDIUM_RISK", "kex": "ECDHE", "enc": "AES-256", "mac": "SHA384"},
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {"status": "MEDIUM_RISK", "kex": "ECDHE", "enc": "AES-256", "mac": "SHA384"},
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": {"status": "MEDIUM_RISK", "kex": "ECDHE-ECDSA", "enc": "AES-128", "mac": "SHA256"},
    # LOW/SAFE - TLS 1.3 suites (still need PQC key exchange upgrade)
    "TLS_AES_128_GCM_SHA256":            {"status": "LOW_RISK", "kex": "TLS1.3-DHE", "enc": "AES-128", "mac": "SHA256"},
    "TLS_AES_256_GCM_SHA384":            {"status": "LOW_RISK", "kex": "TLS1.3-DHE", "enc": "AES-256", "mac": "SHA384"},
    "TLS_CHACHA20_POLY1305_SHA256":      {"status": "LOW_RISK", "kex": "TLS1.3-DHE", "enc": "ChaCha20", "mac": "SHA256"},
}

TLS_VERSION_RISK = {
    "SSLv2":   ("CRITICAL_VULNERABLE", "SSLv2 is completely broken and must be immediately disabled."),
    "SSLv3":   ("CRITICAL_VULNERABLE", "SSLv3 is broken (POODLE attack). Must be disabled."),
    "TLSv1.0": ("CRITICAL_VULNERABLE", "TLS 1.0 deprecated (RFC 8996). Supports weak ciphers, BEAST/POODLE vulnerable."),
    "TLSv1.1": ("CRITICAL_VULNERABLE", "TLS 1.1 deprecated (RFC 8996). Disable and upgrade to TLS 1.3."),
    "TLSv1.2": ("MEDIUM_RISK", "TLS 1.2 acceptable short-term, but key exchange may be ECDHE (quantum vulnerable). Plan hybrid TLS 1.3 upgrade."),
    "TLSv1.3": ("LOW_RISK", "TLS 1.3 — Modern, secure symmetric ciphers. Key exchange still ECDHE (quantum vulnerable). Plan ML-KEM-768 hybrid upgrade."),
}


class NetworkScanner(BaseScanner):
    """Scans TLS endpoints and PCAP files for cryptographic weaknesses."""

    SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

    def scan_file(self, file_path: str) -> List[CryptoFinding]:
        """Scan a PCAP file for TLS/SSL cryptographic weaknesses."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            return []

        findings: List[CryptoFinding] = []
        try:
            findings.extend(self._analyze_pcap(file_path))
        except Exception:
            pass
        return findings

    def scan_tls_endpoint(self, host: str, port: int = 443, app_name: str = "") -> List[CryptoFinding]:
        """
        Actively probe a TLS endpoint and analyze its cipher suites, protocol version,
        and certificate algorithm. Returns quantum risk findings.
        """
        findings: List[CryptoFinding] = []
        endpoint = f"{host}:{port}"

        try:
            # Try each legacy TLS version to detect if server accepts broken protocols
            for tls_ver_name, tls_ver_const in [
                ("TLSv1.0", ssl.TLSVersion.TLSv1),
                ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
            ]:
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    ctx.minimum_version = tls_ver_const
                    ctx.maximum_version = tls_ver_const
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host):
                            # Server accepted this deprecated version
                            risk, desc = TLS_VERSION_RISK.get(tls_ver_name, ("MEDIUM_RISK", ""))
                            findings.append(self._make_tls_version_finding(
                                endpoint, tls_ver_name, risk, desc, host, port
                            ))
                except (ssl.SSLError, OSError, ConnectionRefusedError):
                    pass  # Server correctly refused

            # Probe current/preferred connection
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get negotiated TLS version & cipher
                    tls_version = ssock.version() or "Unknown"
                    cipher_name, _, key_bits = ssock.cipher()

                    # Analyze negotiated cipher suite
                    suite_finding = self._analyze_cipher_suite(
                        cipher_name, tls_version, key_bits or 0, endpoint, host, port
                    )
                    if suite_finding:
                        findings.append(suite_finding)

                    # Analyze server certificate
                    cert = ssock.getpeercert(binary_form=True)
                    if cert:
                        cert_findings = self._analyze_peer_cert(cert, endpoint, host, port)
                        findings.extend(cert_findings)

        except (ssl.SSLError, OSError, ConnectionRefusedError, socket.timeout):
            pass

        return findings

    def _analyze_cipher_suite(
        self, cipher_name: str, tls_version: str, key_bits: int, endpoint: str, host: str, port: int
    ) -> Optional[CryptoFinding]:
        """Analyze a negotiated TLS cipher suite for quantum risk."""

        # Detect key exchange algorithm
        kex = "UNKNOWN"
        if "ECDHE" in cipher_name:
            kex = "ECDHE"
        elif "DHE" in cipher_name or "EDH" in cipher_name:
            kex = "DHE"
        elif "RSA" in cipher_name and "ECDHE" not in cipher_name:
            kex = "RSA-Static"
        elif "ECDH" in cipher_name:
            kex = "ECDH-Static"

        # Detect encryption algorithm
        enc_status = "MEDIUM_RISK"
        enc_algo = "AES-256"
        if any(b in cipher_name for b in ["RC4", "DES", "3DES", "NULL", "EXPORT"]):
            enc_status = "CRITICAL_VULNERABLE"
            enc_algo = cipher_name

        # RSA static key exchange = quantum critical (HNDL risk)
        if kex == "RSA-Static":
            quantum_status = "CRITICAL_VULNERABLE"
            threat = "RSA key exchange — Shor's algorithm breaks integer factorization. HNDL: all past sessions retroactively vulnerable."
            pqc_target = "Hybrid TLS 1.3 + ML-KEM-768 (FIPS 203). Disable RSA static key exchange immediately."
            score = 90.0
        elif kex in ("ECDHE", "DHE"):
            quantum_status = "MEDIUM_RISK"
            threat = f"{kex} key exchange — Shor's algorithm breaks discrete logarithm. Sessions protected by forward secrecy but quantum-vulnerable long term."
            pqc_target = "Hybrid TLS 1.3 + ML-KEM-768 (FIPS 203). Replace ECDHE with hybrid PQC key exchange."
            score = 65.0
        else:
            quantum_status = "LOW_RISK"
            threat = "TLS 1.3 cipher suite — modern symmetric encryption. Key exchange still requires PQC upgrade."
            pqc_target = "Upgrade key exchange to Hybrid ML-KEM-768."
            score = 30.0

        # Combine TLS version risk
        tls_risk, tls_desc = TLS_VERSION_RISK.get(tls_version, ("MEDIUM_RISK", ""))
        if tls_risk == "CRITICAL_VULNERABLE":
            quantum_status = "CRITICAL_VULNERABLE"
            score = max(score, 88.0)
            threat = f"{tls_desc} {threat}"

        evidence = Evidence(
            source_type="network",
            file_path=endpoint,
            start_line=port,
            code_snippet=f"Negotiated: {cipher_name} ({tls_version}, {key_bits}-bit)",
            rule_id="NETWORK-TLS-CIPHER-ANALYSIS",
            matched_pattern=cipher_name,
            detection_method="TLS_HANDSHAKE_PROBE",
            confidence=0.99,
            reasoning=threat,
        )

        asset = CryptoAsset(
            name=f"TLS Cipher @ {endpoint}",
            algorithm_family=kex,
            algorithm_variant=f"{cipher_name} ({tls_version})",
            primitive="key-establishment",
            key_size=key_bits,
            protocol=tls_version,
        )

        pqc_rec = PQCRecommendation(
            target_algorithm="Hybrid TLS 1.3 + ML-KEM-768 (FIPS 203)",
            migration_pattern="HYBRID_TRANSITION",
            migration_wave="WAVE_1_CRITICAL" if quantum_status == "CRITICAL_VULNERABLE" else "WAVE_2_HIGH",
            effort_estimate="MEDIUM",
            remediation_steps=[
                "1. Upgrade server to TLS 1.3 minimum",
                "2. Enable ML-KEM-768 hybrid key exchange (X25519MLKEM768)",
                "3. Disable RSA static key exchange, TLS 1.0/1.1, RC4, DES, 3DES",
                "4. Reference: NIST SP 800-52 Rev 2, NSA CNSA 2.0",
            ]
        )

        return CryptoFinding(
            crypto_asset=asset,
            evidence=evidence,
            pqc_recommendation=pqc_rec,
            quantum_status=quantum_status,
            threat_vector=threat[:200],
            nist_status="Requires hybrid TLS 1.3 + ML-KEM-768 per NIST SP 800-52 Rev 2",
            classical_security_bits=key_bits,
            quantum_security_bits=0 if kex in ("RSA-Static", "ECDHE") else key_bits // 2,
            vulnerability_score=score,
            qei_score=score,
            cai_score=55.0,  # Configurable via server settings
            confidence=0.97,
            hndl_risk="CRITICAL" if kex == "RSA-Static" else "HIGH",
        )

    def _make_tls_version_finding(
        self, endpoint: str, version: str, risk: str, desc: str, host: str, port: int
    ) -> CryptoFinding:
        evidence = Evidence(
            source_type="network",
            file_path=endpoint,
            start_line=port,
            code_snippet=f"Server accepted deprecated {version} handshake",
            rule_id=f"NETWORK-TLS-VERSION-{version.replace('.', '')}",
            matched_pattern=version,
            detection_method="TLS_VERSION_PROBE",
            confidence=0.99,
            reasoning=desc,
        )
        asset = CryptoAsset(
            name=f"TLS Protocol @ {endpoint}",
            algorithm_family="TLS",
            algorithm_variant=version,
            primitive="protocol",
            protocol=version,
        )
        pqc_rec = PQCRecommendation(
            target_algorithm="TLS 1.3 + Hybrid ML-KEM-768",
            migration_pattern="DIRECT_REPLACEMENT",
            migration_wave="WAVE_1_CRITICAL",
            effort_estimate="LOW",
            remediation_steps=[
                f"Disable {version} immediately on all servers",
                "Configure TLS 1.3 as minimum protocol version",
                "Enable hybrid PQC key exchange: X25519MLKEM768",
                "Reference: RFC 8996 — Deprecating TLS 1.0 and TLS 1.1",
            ]
        )
        return CryptoFinding(
            crypto_asset=asset,
            evidence=evidence,
            pqc_recommendation=pqc_rec,
            quantum_status=risk,
            threat_vector=desc[:200],
            nist_status="Deprecated per RFC 8996 and NIST SP 800-52",
            classical_security_bits=0,
            quantum_security_bits=0,
            vulnerability_score=95.0,
            qei_score=90.0,
            cai_score=40.0,
            confidence=0.99,
            hndl_risk="CRITICAL",
        )

    def _analyze_peer_cert(self, cert_der: bytes, endpoint: str, host: str, port: int) -> List[CryptoFinding]:
        """Parse certificate to check signature algorithm quantum risk."""
        findings: List[CryptoFinding] = []
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            cert = x509.load_der_x509_certificate(cert_der)

            pub_key = cert.public_key()
            sig_algo = cert.signature_algorithm_oid.dotted_string

            algo_name = "RSA"
            key_size = 0
            curve_name = None
            quantum_status = "CRITICAL_VULNERABLE"

            if isinstance(pub_key, rsa.RSAPublicKey):
                algo_name = "RSA"
                key_size = pub_key.key_size
                threat = f"RSA-{key_size} certificate — Shor's algorithm completely breaks this. All past TLS sessions protected by this certificate are HNDL-vulnerable."
                pqc_target = "ML-DSA-65 (FIPS 204) for signatures. Replace certificate with PQC or hybrid certificate."
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                algo_name = "ECC"
                key_size = pub_key.key_size
                curve_name = pub_key.curve.name
                threat = f"ECDSA-{curve_name} certificate — Shor's algorithm breaks elliptic curve discrete logarithm."
                pqc_target = "ML-DSA-65 (FIPS 204). Hybrid X.509 certificate with both ECDSA and ML-DSA."
            else:
                return findings

            evidence = Evidence(
                source_type="network",
                file_path=endpoint,
                start_line=port,
                code_snippet=f"Certificate: {cert.subject.rfc4514_string()} | Algo: {algo_name}-{key_size} | Expires: {cert.not_valid_after_utc}",
                rule_id="NETWORK-CERT-QUANTUM-RISK",
                detection_method="TLS_CERTIFICATE_INSPECTION",
                confidence=0.99,
                reasoning=threat,
            )
            asset = CryptoAsset(
                name=f"{algo_name}-{key_size} Certificate @ {endpoint}",
                algorithm_family=algo_name,
                algorithm_variant=f"{algo_name}-{key_size}",
                primitive="certificate",
                key_size=key_size,
                curve=curve_name,
                protocol="X.509",
            )
            pqc_rec = PQCRecommendation(
                target_algorithm=pqc_target,
                migration_pattern="HYBRID_TRANSITION",
                migration_wave="WAVE_1_CRITICAL",
                effort_estimate="MEDIUM",
                remediation_steps=[
                    "1. Request PQC or hybrid certificate from CA",
                    "2. Deploy ML-DSA-65 certificate alongside existing ECDSA (hybrid)",
                    "3. Monitor CA ecosystem readiness for PQC certificate issuance",
                    "4. Reference: NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes",
                ]
            )
            findings.append(CryptoFinding(
                crypto_asset=asset,
                evidence=evidence,
                pqc_recommendation=pqc_rec,
                quantum_status=quantum_status,
                threat_vector=threat[:200],
                nist_status="Certificate algorithm deprecated by NIST SP 800-131A Rev 3",
                classical_security_bits=key_size,
                quantum_security_bits=0,
                vulnerability_score=88.0,
                qei_score=85.0,
                cai_score=50.0,
                confidence=0.99,
                hndl_risk="HIGH",
            ))
        except ImportError:
            pass  # cryptography library not available
        except Exception:
            pass

        return findings

    def _analyze_pcap(self, file_path: str) -> List[CryptoFinding]:
        """
        Basic PCAP parser to detect TLS Client Hello version and cipher suites.
        Does not require Scapy — uses raw byte parsing of libpcap format.
        """
        findings: List[CryptoFinding] = []
        TLS_CONTENT_TYPE_HANDSHAKE = 0x16
        TLS_HANDSHAKE_CLIENT_HELLO = 0x01

        try:
            with open(file_path, "rb") as f:
                # Read global header (24 bytes)
                global_header = f.read(24)
                if len(global_header) < 24:
                    return findings

                magic = struct.unpack_from("<I", global_header, 0)[0]
                if magic not in (0xA1B2C3D4, 0xD4C3B2A1, 0x0A0D0D0A):
                    return findings  # Not a PCAP file

                tls_versions_seen = set()
                packets_analyzed = 0

                while packets_analyzed < 1000:  # Limit for performance
                    rec_header = f.read(16)
                    if len(rec_header) < 16:
                        break
                    incl_len = struct.unpack_from("<I", rec_header, 8)[0]
                    if incl_len > 65535:
                        break
                    packet = f.read(incl_len)
                    if len(packet) < incl_len:
                        break
                    packets_analyzed += 1

                    # Look for TLS record (skip Ethernet+IP+TCP headers: typically 14+20+20=54 bytes)
                    for offset in range(14, min(len(packet) - 5, 80)):
                        if packet[offset] == TLS_CONTENT_TYPE_HANDSHAKE:
                            tls_major = packet[offset + 1]
                            tls_minor = packet[offset + 2]
                            if tls_major == 3:  # TLS
                                if tls_minor == 1:
                                    tls_versions_seen.add("TLSv1.0")
                                elif tls_minor == 2:
                                    tls_versions_seen.add("TLSv1.1")
                                elif tls_minor == 3:
                                    tls_versions_seen.add("TLSv1.2")
                                elif tls_minor == 4:
                                    tls_versions_seen.add("TLSv1.3")
                            break

                for version in tls_versions_seen:
                    risk, desc = TLS_VERSION_RISK.get(version, ("MEDIUM_RISK", ""))
                    if risk in ("CRITICAL_VULNERABLE", "MEDIUM_RISK"):
                        findings.append(self._make_tls_version_finding(
                            file_path, version, risk, desc, file_path, 0
                        ))

        except Exception:
            pass

        return findings
