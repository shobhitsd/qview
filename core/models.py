"""
QView Core Data Models & Schemas
Defines structured classes for Findings, Evidence, Crypto Assets, CBOM, Assessments, and Metrics.
"""

import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class Evidence:
    """Tamper-evident proof linking finding to exact technical source."""
    evidence_id: str = field(default_factory=lambda: f"EVD-{uuid.uuid4().hex[:8].upper()}")
    source_type: str = "source-code"  # 'source-code', 'binary', 'certificate', 'network', 'dependency', 'config'
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    column: Optional[int] = None
    function_name: Optional[str] = None
    code_snippet: Optional[str] = None
    ast_path: Optional[str] = None
    rule_id: Optional[str] = None
    matched_pattern: Optional[str] = None
    detection_method: str = "AST_SEMANTIC_ANALYSIS"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 0.95
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CryptoAsset:
    """Normalized Cryptographic Asset matching CycloneDX 1.6 CBOM standards."""
    asset_id: str = field(default_factory=lambda: f"CA-{uuid.uuid4().hex[:8].upper()}")
    name: str = ""
    algorithm_family: str = ""
    algorithm_variant: str = ""
    primitive: str = ""  # 'key-establishment', 'signature', 'symmetric-encryption', 'hash', 'mac'
    key_size: Optional[int] = None
    curve: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    library_name: Optional[str] = None
    library_version: Optional[str] = None
    provider: Optional[str] = None
    protocol: Optional[str] = None  # 'TLS 1.3', 'TLS 1.2', 'SSHv2', 'IPsec'
    oid: Optional[str] = None
    hardcoded: bool = False
    configurable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PQCRecommendation:
    """Target Post-Quantum migration mapping aligned to NIST FIPS 203/204/205."""
    target_algorithm: str = ""
    target_standard: str = "NIST FIPS 203/204/205"
    alternative_algorithm: Optional[str] = None
    migration_pattern: str = "HYBRID_TRANSITION"  # 'DIRECT_REPLACEMENT', 'HYBRID_TRANSITION', 'CRYPTO_ABSTRACTION'
    migration_wave: str = "WAVE_1_CRITICAL"  # 'WAVE_0_DISCOVERY', 'WAVE_1_CRITICAL', 'WAVE_2_HIGH', 'WAVE_3_STANDARD', 'WAVE_4_LEGACY'
    effort_estimate: str = "MEDIUM"  # 'LOW', 'MEDIUM', 'HIGH', 'ARCHITECTURAL_REFACTOR'
    suggested_code_snippet: str = ""
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CryptoFinding:
    """Individual cryptographic vulnerability finding with line-level evidence and explanation."""
    finding_id: str = field(default_factory=lambda: f"QF-{uuid.uuid4().hex[:8].upper()}")
    assessment_id: str = ""
    app_id: str = "APP-DEFAULT"
    app_name: str = "Default Application"
    business_service: str = "Core Business Service"
    business_criticality: int = 4  # 1 (Low) to 5 (Critical)
    data_sensitivity: str = "CONFIDENTIAL"  # 'PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED', 'PHI_GENOMIC'
    confidentiality_lifetime_years: int = 10
    
    crypto_asset: CryptoAsset = field(default_factory=CryptoAsset)
    evidence: Evidence = field(default_factory=Evidence)
    pqc_recommendation: PQCRecommendation = field(default_factory=PQCRecommendation)
    
    classical_security_bits: int = 112
    quantum_security_bits: int = 0
    quantum_status: str = "CRITICAL_VULNERABLE"  # 'CRITICAL_VULNERABLE', 'MEDIUM_RISK', 'LOW_RISK', 'QUANTUM_RESILIENT', 'QUANTUM_SAFE'
    threat_vector: str = "Shor's Algorithm (Polynomial Time Factorization)"
    nist_status: str = "Deprecated by 2030 (NIST SP 800-131A)"
    
    # Quantitative Risk Metrics
    vulnerability_score: float = 90.0
    qei_score: float = 85.0
    cai_score: float = 50.0
    confidence: float = 0.95
    hndl_risk: str = "HIGH"
    mosca_flag: bool = False  # True when Mosca's Inequality X+Y > Z is violated
    compliance_violations: List[Dict[str, Any]] = field(default_factory=list)  # Regulatory violations

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        return res


@dataclass
class AssessmentSummary:
    """Summary metrics of an assessment run."""
    assessment_id: str = field(default_factory=lambda: f"ASM-{uuid.uuid4().hex[:8].upper()}")
    target_name: str = ""
    target_path: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_files_scanned: int = 0
    total_loc_scanned: int = 0
    total_crypto_assets: int = 0
    quantum_vulnerable_count: int = 0
    medium_risk_count: int = 0
    quantum_safe_count: int = 0
    unknown_crypto_count: int = 0
    
    # 3 Core Quantitative Indices (0-100)
    qri: float = 0.0  # Quantum Readiness Index (Higher = Better)
    qei: float = 0.0  # Quantum Exposure Index (Higher = Worse)
    cai: float = 0.0  # Crypto Agility Index (Higher = Better)

    base_qri: float = 0.0
    coverage_confidence: float = 1.0  # % of inventory observed (Coverage Confidence Multiplier)
    overall_confidence: float = 0.95

    # Mosca's Inequality + HNDL metrics
    mosca_violation_count: int = 0      # Findings where X+Y > Z
    hndl_critical_count: int = 0        # Findings with CRITICAL HNDL risk

    # QRI dimension breakdown (8 weighted dimensions)
    qri_dimensions: Dict[str, Any] = field(default_factory=dict)

    # Band labels (e.g., "At Risk", "Prepared")
    qri_band: Dict[str, Any] = field(default_factory=dict)
    qei_band: Dict[str, Any] = field(default_factory=dict)

    # Compliance report
    compliance_report: Dict[str, Any] = field(default_factory=dict)

    findings: List[CryptoFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data
