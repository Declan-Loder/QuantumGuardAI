# QuantumGuardAI 🐙

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)

**Privacy-preserving, self-optimizing AI-powered network threat detection**

QuantumGuard uses Graph Neural Networks (GNNs) to detect sophisticated threats in network traffic while **never sending raw data** anywhere. It continuously learns from its own detections, adapts detection thresholds automatically, and can simulate or execute graduated responses (alert → isolate → block).

Built with a clean, modular architecture — ready for real-world deployment.

### Features
- Behavioral threat detection using GraphSAGE GNNs
- Real-time network graph visualization (Plotly HTML)
- Graduated response simulation (alert, block IP, isolate node)
- Self-optimization of confidence thresholds from detection history
- Threat intelligence from public sources (URLhaus, FireHOL, etc.)
- Modern Streamlit dashboard with PDF report export
- Privacy-first design (no cloud telemetry, differential privacy planned)

### Current Status (February 2026)
- **Core pipeline**: Logs → parsed events → NetworkX graph → GNN scoring → prevention simulation → interactive graph
- **Dashboard**: Overview, detection results, parsed summary table, suspicious IPs list, PDF download, embedded graph
- **Learning**: Basic optimizer analyzes past detections and adjusts thresholds (config loading in progress)
- **Threat intel**: Fetching free public IOCs (Phase 1 in progress)

### Roadmap (2026)

Phase 1 (now): Real internet threat intel integration (public feeds)
Phase 2: Continual learning + federated updates (privacy-preserving)
Phase 3: Real-time prevention (ufw/firewall integration)
Phase 4: Post-quantum encryption + full self-improvement loop
Phase 5: Commercial licensing, API, enterprise dashboard

### Contributing

Pull requests welcome!
Especially:

Better threat feed parsers
Training scripts for GNN
Dashboard improvements
Real firewall integrations

### License
MIT License (open core) — commercial / enterprise licensing available for production use.
Made with 🐙 by Declan Loder
Johannesburg, South Africa
2026

### Quick Start
```bash
# 1. Clone the repo
git clone https://github.com/Declan-Loder/QuantumGuardAI.git
cd QuantumGuardAI

# 2. Install dependencies (Poetry recommended)
poetry install

# 3. Run a detection (CLI)
poetry run quantumguard detect data/dummy_logs.json

# 4. Launch the dashboard
poetry run streamlit run dashboard.py

Open http://localhost:8501 in your browser → click Run Detect → watch it analyze, score threats, simulate blocking, and generate a PDF report.