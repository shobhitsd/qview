# Contributing to QView

Thank you for your interest in contributing to **QView**!

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/shobhitsd/qview.git
   cd qview
   ```

2. **Run Tests**:
   QView uses Python standard libraries for deterministic scanning and zero runtime vulnerabilities.
   ```bash
   python test_suite.py
   ```

3. **Start the Local Development Server**:
   ```bash
   python server.py --port 8765
   ```
   Open `http://localhost:8765` in your browser.

## Code Standards
- **Zero AI Hallucination Policy**: All cryptographic discoveries, compliance violations, and mathematical scoring equations must be deterministic and backed by AST code rules, standard regular expressions, or certificate parsers.
- **Standards Adherence**: Ensure CBOM outputs comply with **CycloneDX 1.6 Cryptographic BOM** schema specifications.
- **Testing**: Add test cases to `test_suite.py` for every new scanner rule, algorithm definition, or compliance framework.
