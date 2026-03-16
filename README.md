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

## ⚙️ Quick Setup

Follow these steps to get SentinelAI running on your local machine.

### 1. Backend Setup
1. Navigate to the project folder:
   ```bash
   cd "sentinelai-v2"
   ```
2. Create and activate a Python Virtual Environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r backend\requirements.txt
   ```

### 2. Start Redis
1. Open a new terminal and start the Redis server:
   ```bash
   cd "sentinelai-v2\redis"
   .\redis-server.exe
   ```

### 3. Start the Backend API
1. In your initial terminal (with `venv` active), run the server:
   ```bash
   python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

### 4. Load the Chrome Extension
1. Open Chrome and go to `chrome://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `sentinelai-v2` folder.

## 🏗️ v3 Architecture

For a deep dive into the technical implementation and hardware optimization, see the [SentinelAI v3 Architecture](SentinelAI_v3_Architecture.md).

---
*SentinelAI — Protecting your privacy with Active Intelligence.*
