# SentinelAI v3.0 — Active Runtime Intelligence

### Sub-100ms · Near-Zero False Positives · RTX 3050 Ti + AirLLM · Privacy-First

SentinelAI v3.0 is a next-generation, local, privacy-first web security platform. It monitors website behavior in real-time using a two-tier AI inference system to detect and block threats before they can execute.

## 🚀 Key Features (v3.0)

- **Two-Tier Inference**: Lightning-fast Tier 1 scans (<15ms) for 80% of sites, with deep Tier 2 analysis (<100ms) for ambiguous cases.
- **AirLLM Integration**: Run high-parameter models (7B+) on consumer GPUs (4GB VRAM) via layer streaming.
- **18 Runtime Hooks**: Advanced monitoring for credential theft, clickjacking, malicious service workers, and more.
- **Privacy-First**: Fully offline-capable threat intelligence with zero external calls during browsing.
- **Ensemble Voting**: Reduced false positives via multi-agent consensus and personal behavioral baselines.

## 🏗️ Project Structure

- `sentinelai-v2/`: Core implementation of the extension and backend.
- `SentinelAI_v3_Architecture.md`: Detailed technical specification of the v3 upgrade.
- `monitor (2).py`: Enhanced privacy monitoring and risk assessment script.

## 🧠 Documentation

For a deep dive into the technical implementation and hardware optimization, see the [SentinelAI v3 Architecture](SentinelAI_v3_Architecture.md).

## ⚙️ Quick Start

Please refer to the setup instructions in the [sentinelai-v2/README.md](sentinelai-v2/README.md) for basic deployment steps. The v3 features are currently being integrated based on the new architecture plan.

---
*SentinelAI — Protecting your privacy with Active Intelligence.*
