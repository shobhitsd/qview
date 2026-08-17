"""
QView Dependency & SBOM Scanner
Inspects package manifests (pom.xml, package.json, requirements.txt, go.mod, Cargo.toml)
to discover cryptographic libraries, transitive providers, and PQC dependencies.
"""

import os
import re
from typing import List, Optional
from core.models import CryptoFinding, CryptoAsset, Evidence, PQCRecommendation
from scanners.base_scanner import BaseScanner


class DependencyScanner(BaseScanner):
    """Discovers cryptographic dependencies and libraries in software bills of materials."""

    MANIFEST_FILES = {
        "pom.xml", "package.json", "requirements.txt",
        "pyproject.toml", "go.mod", "Cargo.toml", "Gemfile", "composer.json"
    }

    def is_supported(self, file_path: str) -> bool:
        fname = os.path.basename(file_path).lower()
        return fname in self.MANIFEST_FILES

    def scan_file(self, file_path: str) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []
        if not os.path.exists(file_path) or not self.is_supported(file_path):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        fname = os.path.basename(file_path).lower()

        # Java Maven POM checks
        if fname == "pom.xml":
            if "bcprov-jdk" in content or "bouncycastle" in content.lower():
                is_pqc = "bcpqc" in content.lower()
                line_no = self._find_line(lines, "bcprov") or 1
                
                evidence = Evidence(
                    source_type="dependency",
                    file_path=file_path,
                    start_line=line_no,
                    end_line=line_no + 5,
                    code_snippet="\n".join(lines[max(0, line_no-1):min(len(lines), line_no+6)]),
                    rule_id="RULE-DEP-MAVEN-BOUNCYCASTLE",
                    confidence=0.98,
                    reasoning="Bouncy Castle Cryptography Provider dependency identified."
                )

                crypto_asset = CryptoAsset(
                    name="Bouncy Castle Cryptographic Provider",
                    algorithm_family="Multiple (RSA, ECC, AES, SHA)",
                    algorithm_variant="Bouncy Castle JCA/JCE Provider",
                    primitive="crypto-provider",
                    library_name="org.bouncycastle:bcprov",
                    hardcoded=False,
                    configurable=True
                )

                rec = PQCRecommendation(
                    target_algorithm="org.bouncycastle:bcpqc-jdk18on (FIPS 203/204)",
                    migration_pattern="DEPENDENCY_UPGRADE",
                    migration_wave="WAVE_1_CRITICAL" if not is_pqc else "MAINTAIN"
                )

                findings.append(CryptoFinding(
                    app_name=os.path.basename(os.path.dirname(os.path.abspath(file_path))),
                    crypto_asset=crypto_asset,
                    evidence=evidence,
                    pqc_recommendation=rec,
                    quantum_status="CRITICAL_VULNERABLE" if not is_pqc else "QUANTUM_SAFE",
                    threat_vector="Underlying asymmetric primitives subject to Shor's algorithm" if not is_pqc else "Post-Quantum Ready",
                    nist_status="Upgrade to Bouncy Castle PQC module required" if not is_pqc else "NIST FIPS 203/204 Ready",
                    vulnerability_score=75.0 if not is_pqc else 0.0,
                    confidence=0.98,
                    hndl_risk="HIGH" if not is_pqc else "NONE"
                ))

        # Python requirements checks
        elif fname in ["requirements.txt", "pyproject.toml"]:
            if "cryptography" in content or "pycryptodome" in content or "oqs" in content:
                is_pqc = "oqs" in content or "pqclean" in content
                line_no = self._find_line(lines, "cryptography") or self._find_line(lines, "pycryptodome") or 1
                
                evidence = Evidence(
                    source_type="dependency",
                    file_path=file_path,
                    start_line=line_no,
                    end_line=line_no + 1,
                    code_snippet=lines[line_no - 1] if line_no <= len(lines) else "",
                    rule_id="RULE-DEP-PYTHON-CRYPTO",
                    confidence=0.95,
                    reasoning="Python Cryptography ecosystem package dependency"
                )

                crypto_asset = CryptoAsset(
                    name="Python Cryptography Library",
                    algorithm_family="Multiple",
                    algorithm_variant="cryptography.io / PyCryptodome",
                    primitive="crypto-provider",
                    library_name="cryptography",
                    hardcoded=False,
                    configurable=True
                )

                findings.append(CryptoFinding(
                    app_name=os.path.basename(os.path.dirname(os.path.abspath(file_path))),
                    crypto_asset=crypto_asset,
                    evidence=evidence,
                    pqc_recommendation=PQCRecommendation(
                        target_algorithm="liboqs-python / Open Quantum Safe",
                        migration_pattern="DEPENDENCY_UPGRADE",
                        migration_wave="WAVE_2_HIGH"
                    ),
                    quantum_status="MEDIUM_RISK" if not is_pqc else "QUANTUM_SAFE",
                    threat_vector="Contains classical RSA/ECC primitives" if not is_pqc else "PQC enabled",
                    nist_status="Plan PQC provider integration",
                    vulnerability_score=60.0 if not is_pqc else 0.0,
                    confidence=0.95,
                    hndl_risk="MEDIUM"
                ))

        return findings

    @staticmethod
    def _find_line(lines: List[str], keyword: str) -> Optional[int]:
        for idx, line in enumerate(lines):
            if keyword.lower() in line.lower():
                return idx + 1
        return None
