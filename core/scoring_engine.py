"""
QView Mathematical Scoring Engine v2
Calculates QEI (Quantum Exposure Index), CAI (Cryptographic Agility Index),
QRI (Quantum Readiness Index with Coverage Confidence Multiplier),
Mosca's Inequality HNDL Risk, and per-finding Quantum Band classification.
"""

from typing import List, Dict, Any, Optional
from core.models import CryptoFinding, AssessmentSummary

# Mosca's Inequality parameters (defaults — configurable per org)
DEFAULT_MOSCA_PARAMS = {
    "time_to_crqc_years": 7,      # Z: Estimated years until CRQC (conservative: 7)
    "migration_time_years": 3,    # Y: Average enterprise migration effort in years
}

QRI_BANDS = [
    (90, 100, "Quantum Ready",  "#22c55e"),
    (75,  89, "Prepared",       "#84cc16"),
    (60,  74, "Progressing",    "#eab308"),
    (40,  59, "At Risk",        "#f97316"),
    (20,  39, "Vulnerable",     "#ef4444"),
    (0,   19, "Critical",       "#dc2626"),
]

QEI_BANDS = [
    (90, 100, "Critical",       "#dc2626"),
    (75,  89, "Very High",      "#ef4444"),
    (60,  74, "High",           "#f97316"),
    (40,  59, "Moderate",       "#eab308"),
    (20,  39, "Low",            "#84cc16"),
    (0,   19, "Minimal",        "#22c55e"),
]


def get_band(score: float, bands: list) -> Dict[str, Any]:
    for lo, hi, label, color in bands:
        if lo <= score <= hi:
            return {"label": label, "color": color, "min": lo, "max": hi}
    return {"label": "Unknown", "color": "#6b7280", "min": 0, "max": 100}


class MoscaAnalyzer:
    """
    Evaluates Mosca's Inequality: if X + Y > Z, migrate NOW.
    X = Data shelf-life (years confidentiality needed)
    Y = Migration time (years to complete crypto migration)
    Z = Time to CRQC threat (estimated)
    """

    @staticmethod
    def evaluate(
        data_lifetime_years: int,
        quantum_status: str,
        migration_time_years: int = DEFAULT_MOSCA_PARAMS["migration_time_years"],
        time_to_crqc_years: int = DEFAULT_MOSCA_PARAMS["time_to_crqc_years"],
    ) -> Dict[str, Any]:
        """
        Returns Mosca evaluation: mosca_flag, hndl_risk, urgency, and rationale.
        """
        x = data_lifetime_years   # Data shelf life
        y = migration_time_years  # Migration effort
        z = time_to_crqc_years    # Time to quantum threat

        mosca_violated = (x + y) > z
        total_horizon = x + y

        if quantum_status == "CRITICAL_VULNERABLE":
            if mosca_violated:
                return {
                    "mosca_flag": True,
                    "mosca_x": x, "mosca_y": y, "mosca_z": z,
                    "hndl_risk": "CRITICAL",
                    "urgency": "IMMEDIATE",
                    "rationale": (
                        f"Mosca's Inequality VIOLATED: Data lifetime ({x}yr) + Migration time ({y}yr) = "
                        f"{total_horizon}yr > Time to CRQC ({z}yr). "
                        f"This data will still need protection when CRQCs arrive. "
                        f"HNDL: Adversaries are capturing this data TODAY for future decryption. "
                        f"PQC migration must begin immediately (Wave 1 — Critical)."
                    )
                }
            else:
                return {
                    "mosca_flag": False,
                    "mosca_x": x, "mosca_y": y, "mosca_z": z,
                    "hndl_risk": "HIGH",
                    "urgency": "HIGH_PRIORITY",
                    "rationale": (
                        f"Algorithm is quantum-vulnerable. Although X+Y ({total_horizon}yr) ≤ Z ({z}yr), "
                        f"HNDL risk exists today. Plan migration in Wave 2."
                    )
                }
        elif quantum_status == "MEDIUM_RISK":
            return {
                "mosca_flag": x >= 5,
                "mosca_x": x, "mosca_y": y, "mosca_z": z,
                "hndl_risk": "MEDIUM" if x < 10 else "HIGH",
                "urgency": "MEDIUM_PRIORITY",
                "rationale": (
                    f"Grover's algorithm reduces effective security. "
                    f"For data requiring {x}yr protection, upgrade key sizes (AES-256, SHA-3-512)."
                )
            }
        else:
            return {
                "mosca_flag": False,
                "mosca_x": x, "mosca_y": y, "mosca_z": z,
                "hndl_risk": "LOW",
                "urgency": "MONITOR",
                "rationale": "Algorithm is quantum-resilient. Continue monitoring for NIST updates."
            }


class ScoringEngine:
    """Deterministic mathematical scoring engine implementing QEI, QRI, CAI, and Mosca's Inequality."""

    @staticmethod
    def calculate_finding_qei(finding: CryptoFinding) -> float:
        """
        Calculate individual Quantum Exposure Index (0–100, Higher = Worse Risk).

        QEI = Norm(V_algo × S_data × L_data × C_biz × E_ext × M_comp)

        Then apply Mosca's Inequality escalation if X+Y > Z.
        """
        v_algo = finding.vulnerability_score / 100.0  # 0.0 to 1.0

        # S_data: Data Sensitivity
        sens_map = {
            "PUBLIC": 0.10,
            "INTERNAL": 0.30,
            "CONFIDENTIAL": 0.70,
            "RESTRICTED": 0.90,
            "PHI_GENOMIC": 1.00
        }
        s_data = sens_map.get(finding.data_sensitivity, 0.70)

        # L_data: Data Longevity (years confidentiality required)
        years = finding.confidentiality_lifetime_years
        if years <= 1:
            l_data = 0.10
        elif years <= 3:
            l_data = 0.40
        elif years <= 7:
            l_data = 0.70
        elif years <= 15:
            l_data = 0.90
        elif years <= 30:
            l_data = 0.97
        else:
            l_data = 1.00  # 30–100 years: Genomic, pediatric, legal records

        # C_biz: Business Criticality (1–5 scale)
        c_biz = max(1, min(5, finding.business_criticality)) / 5.0

        # E_ext: External Exposure factor
        # Default: assume internet-facing for most applications
        proto = (finding.crypto_asset.protocol or "").upper()
        if "TLS" in proto or "HTTPS" in proto or "SSH" in proto:
            e_ext = 1.00   # Internet-facing
        elif finding.crypto_asset.primitive in ("key-establishment", "signature"):
            e_ext = 0.90   # Likely exposed
        else:
            e_ext = 0.75   # Internal but significant

        # M_comp: Migration Complexity
        if finding.crypto_asset.hardcoded:
            m_comp = 0.95  # Hardcoded = near-impossible to rotate
        elif not finding.crypto_asset.configurable:
            m_comp = 0.80
        else:
            m_comp = 0.45  # Configurable = easier

        # Weighted composite
        raw_qei = (
            0.35 * v_algo +
            0.20 * s_data +
            0.15 * l_data +
            0.15 * c_biz +
            0.10 * e_ext +
            0.05 * m_comp
        ) * 100.0

        # ── Mosca's Inequality Escalation ─────────────────────────────────────
        mosca = MoscaAnalyzer.evaluate(years, finding.quantum_status)
        if mosca["mosca_flag"] and finding.quantum_status == "CRITICAL_VULNERABLE":
            # Mosca violated: hard-floor of 90 (Critical)
            raw_qei = max(raw_qei, 90.0)
        elif finding.quantum_status == "CRITICAL_VULNERABLE" and years >= 5:
            # Close to violation: hard-floor of 82
            raw_qei = max(raw_qei, 82.0)

        # Update HNDL risk on finding
        finding.hndl_risk = mosca["hndl_risk"]
        finding.mosca_flag = mosca["mosca_flag"]

        return round(min(100.0, max(0.0, raw_qei)), 1)

    @staticmethod
    def calculate_finding_cai(finding: CryptoFinding) -> float:
        """
        Calculate individual Cryptographic Agility Index (0–100, Higher = More Agile).
        Evaluates how easily this particular crypto asset can be replaced.
        """
        score = 50.0  # Baseline

        # Hardcoded: -35 penalty (zero agility)
        if finding.crypto_asset.hardcoded:
            score -= 35.0
        else:
            score += 10.0

        # Configurable via config file/env: +20
        if finding.crypto_asset.configurable:
            score += 20.0

        # Provider-abstracted (JCA, EVP, provider pattern): +10
        lib = finding.crypto_asset.library_name or ""
        if any(kw in lib for kw in ["JCA", "EVP", "Provider", "cryptography", "BouncyCastle"]):
            score += 10.0

        # Protocol supports algorithm negotiation (TLS 1.3 > TLS 1.2): +10
        proto = finding.crypto_asset.protocol or ""
        if "TLS 1.3" in proto or "TLSv1.3" in proto:
            score += 10.0
        elif "TLS 1.2" in proto or "TLSv1.2" in proto:
            score += 5.0

        # Already PQC: +25
        if finding.quantum_status in ("QUANTUM_SAFE", "QUANTUM_RESILIENT"):
            score += 25.0

        return round(min(100.0, max(0.0, score)), 1)

    @classmethod
    def score_assessment(cls, summary: AssessmentSummary, coverage_pct: float = 1.0) -> AssessmentSummary:
        """
        Compute enterprise-wide QEI, CAI, 8-dimension Base QRI, and Final QRI
        with mandatory Coverage Confidence Multiplier.
        """
        findings = summary.findings
        total = len(findings)

        if total == 0:
            summary.qri = round(100.0 * coverage_pct, 1)
            summary.base_qri = 100.0
            summary.qei = 0.0
            summary.cai = 100.0
            summary.coverage_confidence = round(coverage_pct, 2)
            summary.qri_band = get_band(summary.qri, QRI_BANDS)
            summary.qei_band = get_band(0.0, QEI_BANDS)
            return summary

        # ── Step 1: Score each finding ──────────────────────────────────────
        vuln_count = med_count = safe_count = unknown_count = 0
        total_qei = total_cai = 0.0
        mosca_count = hndl_critical = 0

        for f in findings:
            f.qei_score = cls.calculate_finding_qei(f)
            f.cai_score = cls.calculate_finding_cai(f)
            total_qei += f.qei_score
            total_cai += f.cai_score

            if f.quantum_status == "CRITICAL_VULNERABLE":
                vuln_count += 1
            elif f.quantum_status == "MEDIUM_RISK":
                med_count += 1
            elif f.quantum_status in ("QUANTUM_SAFE", "QUANTUM_RESILIENT"):
                safe_count += 1
            else:
                unknown_count += 1

            if getattr(f, "mosca_flag", False):
                mosca_count += 1
            if getattr(f, "hndl_risk", "") == "CRITICAL":
                hndl_critical += 1

        summary.total_crypto_assets = total
        summary.quantum_vulnerable_count = vuln_count
        summary.medium_risk_count = med_count
        summary.quantum_safe_count = safe_count
        summary.unknown_crypto_count = unknown_count
        summary.mosca_violation_count = mosca_count
        summary.hndl_critical_count = hndl_critical

        avg_qei = total_qei / total
        avg_cai = total_cai / total
        summary.qei = round(avg_qei, 1)
        summary.cai = round(avg_cai, 1)

        # ── Step 2: 8-Dimension Base QRI ────────────────────────────────────
        # Dim 1 (25%): Crypto Exposure → Inverted average QEI
        dim_exposure = max(0.0, 100.0 - avg_qei)

        # Dim 2 (15%): Data Sensitivity — ratio of sensitive data protected by safe crypto
        safe_ratio = safe_count / total if total > 0 else 1.0
        dim_data_protection = safe_ratio * 100.0

        # Dim 3 (15%): Business Criticality Alignment
        crit_vuln = sum(1 for f in findings if f.business_criticality >= 4 and f.quantum_status == "CRITICAL_VULNERABLE")
        dim_biz_crit = max(0.0, 100.0 - (crit_vuln / total * 100.0))

        # Dim 4 (15%): Crypto Agility
        dim_agility = avg_cai

        # Dim 5 (10%): PQC Compatibility
        pqc_ratio = safe_count / total
        dim_pqc_compat = min(100.0, (pqc_ratio * 70.0) + (30.0 if avg_cai > 60 else 10.0))

        # Dim 6 (10%): Inventory Coverage
        dim_coverage = coverage_pct * 100.0

        # Dim 7 (5%): Migration Complexity
        hardcoded_count = sum(1 for f in findings if f.crypto_asset.hardcoded)
        dim_migration_comp = max(0.0, 100.0 - (hardcoded_count / total * 100.0))

        # Dim 8 (5%): Governance & Policy Compliance
        legacy_broken = sum(1 for f in findings if f.crypto_asset.algorithm_family in ("DES", "RC4", "MD5", "SHA-1", "3DES"))
        dim_governance = max(0.0, 100.0 - (legacy_broken / total * 100.0))

        base_qri = (
            0.25 * dim_exposure +
            0.15 * dim_data_protection +
            0.15 * dim_biz_crit +
            0.15 * dim_agility +
            0.10 * dim_pqc_compat +
            0.10 * dim_coverage +
            0.05 * dim_migration_comp +
            0.05 * dim_governance
        )

        summary.base_qri = round(base_qri, 1)
        summary.coverage_confidence = round(coverage_pct, 2)

        # ── Step 3: Coverage Confidence Multiplier (MANDATORY) ──────────────
        # Final QRI = Base QRI × Coverage Confidence
        # You cannot claim high readiness with low scan coverage.
        final_qri = base_qri * coverage_pct
        summary.qri = round(min(100.0, max(0.0, final_qri)), 1)

        # ── Step 4: Dimension scores & band labels ───────────────────────────
        summary.qri_dimensions = {
            "crypto_exposure":      {"score": round(dim_exposure, 1), "weight": 0.25},
            "data_protection":      {"score": round(dim_data_protection, 1), "weight": 0.15},
            "business_criticality": {"score": round(dim_biz_crit, 1), "weight": 0.15},
            "crypto_agility":       {"score": round(dim_agility, 1), "weight": 0.15},
            "pqc_compatibility":    {"score": round(dim_pqc_compat, 1), "weight": 0.10},
            "inventory_coverage":   {"score": round(dim_coverage, 1), "weight": 0.10},
            "migration_complexity": {"score": round(dim_migration_comp, 1), "weight": 0.05},
            "governance_policy":    {"score": round(dim_governance, 1), "weight": 0.05},
        }
        summary.qri_band = get_band(summary.qri, QRI_BANDS)
        summary.qei_band = get_band(summary.qei, QEI_BANDS)

        return summary
