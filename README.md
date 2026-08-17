# ⚡ QView: Post-Quantum Cryptography (PQC) Governance & CBOM Platform

[![QView CI](https://github.com/shobhitsd/qview/actions/workflows/ci.yml/badge.svg)](https://github.com/shobhitsd/qview/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Standard](https://img.shields.io/badge/CBOM-CycloneDX_1.6-purple.svg)](https://cyclonedx.org/)
[![NIST Compliance](https://img.shields.io/badge/NIST-FIPS_203%20%2F%20204%20%2F%20205-emerald.svg)](https://csrc.nist.gov/)

**QView** is an enterprise-grade Post-Quantum Cryptography (PQC) discovery engine, Cryptographic Bill of Materials (CBOM) generator, and quantum risk governance cockpit. It analyzes codebases, dependencies, certificates, secrets, and network configurations to calculate mathematical quantum exposure metrics, detect **Mosca's Inequality** violations, enforce global compliance mandates, and generate automated PQC migration playbooks.

---

## 🏛️ Why QView? The Quantum Transition Challenge

Shor's algorithm running on a Cryptanalytically Relevant Quantum Computer (CRQC) will break asymmetric public-key cryptography (RSA, ECC, Diffie-Hellman, DSA). Threat actors are currently executing **Harvest Now, Decrypt Later (HNDL)** attacks—intercepting and storing encrypted enterprise traffic today to decrypt once quantum hardware matures.

### Mosca's Inequality Analyzer
QView evaluates whether your organization violates **Mosca's Theorem**:
$$\text{If } X + Y > Z \implies \text{Data will be compromised}$$
- **$X$ (Shelf-life):** How many years the encrypted data must remain confidential.
- **$Y$ (Migration Time):** How many years required to re-engineer systems with PQC.
- **$Z$ (Quantum Horizon):** Estimated years until a CRQC is operational (NIST estimated ~2030–2035).

---

## 🚀 Key Features

- **🔍 Deterministic Multi-Layer Cryptographic Scanner**: Zero-AI hallucination static code analysis, AST inspection, secret detection, certificate parsing, and dependency mapping across Python, Java, JavaScript/TypeScript, C/C++, Rust, Go, and configuration files.
- **📦 CycloneDX 1.6 Cryptographic BOM (CBOM)**: Full compliant export of crypto assets, algorithms, NIST quantum security levels (I–V), primitive types, and key properties.
- **📐 Mathematical Scoring Engine**:
  - **QRI (Quantum Readiness Index)**: 8-dimension weighted posture multiplied by codebase discovery coverage confidence ($QRI = Base \times Coverage$).
  - **QEI (Quantum Exposure Index)**: Surface area measurement of Shor's/Grover's vulnerable assets weighted by data criticality.
  - **CAI (Crypto Agility Index)**: Flexibility score tracking hardcoded keys, provider abstractions, and algorithmic decoupling.
- **⚖️ Global Regulatory Compliance Engine**: Maps findings against **NIST FIPS 203/204/205**, **HIPAA §164.312**, **PCI-DSS 4.0**, **NSA CNSA 2.0**, **SEBI CSCRF §7.4**, **GDPR/DPDP**, and **QCCPA**.
- **🗺️ Interactive 2D Knowledge Graph**: Interactive topology connecting *Applications $\rightarrow$ Files $\rightarrow$ Cryptographic Libraries $\rightarrow$ Algorithm Nodes* with drag-and-drop mechanics.
- **🛠️ Automated Migration Playbooks**: Step-by-step code transition recipes replacing legacy ciphers (e.g. RSA-2048, ECDH-P256) with NIST-standardized algorithms (**ML-KEM-768/1024**, **ML-DSA-65/87**, **SLH-DSA**).
- **☀️ Corporate Day / Light Dashboard**: Clean, CISO-friendly UI featuring live Mosca sliders, interactive matrix drill-downs, radar charts, and an onboard User Guide.

---

## 📊 Core Scoring Dimensions (8-Axis QRI Decomposition)

```
                       [1] Algorithm Security (25%)
                                   ▲
                                   │
       [8] Certificate Posture (10%)  [2] Key Length Sufficiency (15%)
                   ◄               │               ►
                                   │
   [7] PQC Implementation (10%) ───┼─── [3] Crypto Agility (15%)
                                   │
                   ◄               │               ►
       [6] Secrets Sanitization (10%) [4] Protocol Hardening (10%)
                                   │
                                   ▼
                       [5] Dependency Health (5%)
```

---

## 🖥️ UI Cockpit Views

1. **Executive Overview**: High-level CISO telemetry, radial gauges for QRI/QEI/CAI, 8-dimension spider radar chart, and real-time interactive Mosca risk horizon simulator.
2. **Crypto Universe**: Searchable inventory of all discovered algorithms, key lengths, curves, and risk tiers with instant CSV/JSON exports.
3. **Quantum Heatmap Matrix**: 4×4 Business Criticality $\times$ Quantum Exposure matrix with instant cell selection and asset drill-downs.
4. **Compliance Cockpit**: Real-time pass/fail gap analysis across 7 major regulatory frameworks.
5. **Migration Cockpit**: Phased transition roadmap with estimated developer effort hours and dependency ordering.
6. **Knowledge Graph**: Interactive 2D dependency topology with draggable nodes.
7. **Evidence Center**: Exact file paths, line numbers, detection rule IDs, raw code snippets, and automated PQC replacement playbooks.

---

## ⚡ Quick Start

### 1. Installation
QView is built using Python's standard library with zero mandatory external runtime dependencies:
```bash
git clone https://github.com/shobhitsd/qview.git
cd qview
```

*(Optional) Install development dependencies for extended testing:*
```bash
pip install -r requirements.txt
```

### 2. Run Test Suite
Verify deterministic discovery and scoring rules:
```bash
python test_suite.py
```

### 3. Launch CLI Scan
Scan a target directory or repository:
```bash
python cli.py --scan ./sample_data --cbom cbom.json --report report.json
```

### 4. Start the Interactive Web Dashboard
```bash
python server.py --port 8765
```
Open **[http://localhost:8765](http://localhost:8765)** in your browser.

---

## 🔌 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health and active platform status |
| `GET` | `/api/assessment/latest` | Latest comprehensive assessment summary and quantitative scores |
| `GET` | `/api/findings` | Filterable cryptographic findings list |
| `GET` | `/api/findings/:id` | Individual finding details with AST evidence and remediation |
| `GET` | `/api/cbom` | Full CycloneDX 1.6 Cryptographic BOM JSON |
| `GET` | `/api/heatmap` | 4×4 Criticality vs. Quantum Exposure matrix payload |
| `GET` | `/api/compliance` | Status across 7 global regulatory frameworks |
| `GET` | `/api/migration-plan` | Phased PQC migration tasks with work estimates |
| `GET` | `/api/knowledge-graph` | Graph nodes and edges for architectural blast radius analysis |
| `POST` | `/api/scan` | Trigger a new target path or repository scan |

---

## 📂 Project Structure

```
qview/
├── core/                         # Core Mathematical & Compliance Engines
│   ├── algorithm_database.py     # Quantum vulnerability signatures & NIST classifications
│   ├── cbom_engine.py            # CycloneDX 1.6 CBOM generation engine
│   ├── compliance_engine.py      # HIPAA, PCI-DSS, NIST, CNSA, SEBI compliance rules
│   ├── knowledge_graph.py        # Graph topology generator
│   ├── migration_planner.py      # Automated PQC transition roadmap generator
│   ├── models.py                 # Dataclasses and type definitions
│   └── scoring_engine.py         # QRI (8-dim), QEI, CAI & Mosca inequality algorithms
├── scanners/                     # Deterministic Multi-Layer Scanners
│   ├── base_scanner.py           # Abstract scanner base class
│   ├── code_scanner.py           # AST & regex static code analysis (Java, Py, JS, C++, Go)
│   ├── certificate_scanner.py    # X.509, PEM, and DER certificate inspector
│   ├── dependency_scanner.py     # Package manifest parser (pom.xml, package.json, requirements.txt)
│   ├── secrets_scanner.py        # Hardcoded private keys, entropy checks, and tokens
│   ├── network_scanner.py        # TLS protocol, cipher suite, and endpoint configuration auditor
│   └── repo_orchestrator.py      # Master multi-scanner aggregation & deduplication engine
├── sample_data/                  # Sample repositories for POC & testing
│   ├── healthcare_ehr/           # Legacy healthcare stack (RSA-2048, MD5, SHA-1)
│   ├── payment_gateway/          # Fintech payment microservices (ECDH-P256, 3DES)
│   ├── modern_pqc_service/       # Post-Quantum safe service (ML-KEM-768, ML-DSA-65)
│   └── certificates/             # Sample legacy & hybrid certificates
├── web/                          # Corporate Day Theme Frontend Cockpit
│   ├── index.html                # Single-page enterprise layout with User Guide modal
│   ├── styles.css                # Slate/Blue day theme design system
│   └── app.js                    # Client-side state, Chart.js radar, and 2D canvas graph
├── .github/workflows/ci.yml      # Automated GitHub Actions CI pipeline
├── cli.py                        # Command-line interface
├── server.py                     # High-concurrency ThreadingTCPServer REST API
├── test_suite.py                 # Deterministic validation test suite
├── requirements.txt              # Optional dependencies
├── pyproject.toml                # Standard packaging metadata
├── LICENSE                       # Apache License 2.0
├── CONTRIBUTING.md               # Contribution guidelines
└── SECURITY.md                   # Vulnerability disclosure policy
```

---

## 📜 Compliance & Standards Mapping

| Standard | Target Mandate | QView Enforcement |
| :--- | :--- | :--- |
| **NIST FIPS 203** | ML-KEM Key Encapsulation | Replaces RSA, ECDH, X25519 |
| **NIST FIPS 204** | ML-DSA Digital Signatures | Replaces RSA-PSS, ECDSA, Ed25519 |
| **NIST FIPS 205** | SLH-DSA Stateless Hash Signatures | State-free fallback signatures |
| **NSA CNSA 2.0** | Quantum-Resistant Commercial National Security Algorithms | Mandates ML-KEM-1024 / ML-DSA-87 |
| **PCI-DSS 4.0** | Req 4.2 & 12.3 Strong Cryptography & Inventory | Flags SHA-1, 3DES, uninventoried keys |
| **HIPAA §164.312** | Transmission & Storage Encryption of ePHI | Flags non-quantum safe patient data at rest |
| **SEBI CSCRF §7.4** | Cyber Security & Cyber Resilience Framework | Mandates crypto-agility & migration roadmaps |

---

## 🤝 Contributing

Contributions are welcomed! Please read [CONTRIBUTING.md](CONTRIBUTING.md) and check [SECURITY.md](SECURITY.md) before submitting pull requests.

## 📄 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.
