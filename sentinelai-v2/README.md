# SentinelAI v3.0
Active Runtime Intelligence — Web Safety Extension

SentinelAI v3.0 is a local, privacy-first malicious website blocker that integrates a Chrome extension with a powerful backend powered by language models and a Redis cache. This version introduces the Unified Launcher and enhanced agent orchestration.

## 🧠 Introduction

Traditional web security relies on static blocklists that are often outdated and slow to respond to new threats. **SentinelAI v3.0** uses Active Runtime Intelligence — instead of just checking if a URL is bad, it actively watches how a website *behaves* when you visit it. 

It runs entirely on your local machine, ensuring that your browsing data never leaves your device out of privacy concerns.

## 🏗️ Architecture Overview

SentinelAI is divided into two main components that communicate with each other in real-time:

1. **The Chrome Extension (Frontend):** Injects "hooks" into websites to monitor suspicious behavior (like stealing passwords, capturing keystrokes, or taking over your hardware) and blocks malicious pages instantly.
2. **The LangGraph Backend (AI Core):** A set of specialized AI Agents running on your machine (via Python, Uvicorn, and Ollama) that analyze the data caught by the extension to reach a finalized "Verdict" (Safe, Warning, or Block) using Advanced Large Language Models.
3. **Attack Simulation Toolkit (`simulation/`):** A comprehensive suite for testing SentinelAI's detection capabilities. It includes tools for simulating port scans, brute force, DDoS, and data exfiltration.

### The AI Agents
- **URL Agent:** Analyzes the URL structure for phishing tricks.
- **Content Agent:** Scans the static HTML/DOM of the webpage.
- **Runtime Agent:** Analyzes the active behavior and hooks triggered by the site.
- **Exfil Agent:** Watches for attempts to secretly steal or transmit your data.
- **Visual Agent:** Checks for UI red flags and layout spoofing.
- **Tracker Agent:** Detects and analyzes tracking scripts and their origins.
- **Monitor Agent:** Precisely calculates risk scores based on real-time findings.
- **Verdict Agent (Orchestrator):** Gathers all the reports and makes the final decision.

## ✨ Premium UI Overhaul (v3.1)
SentinelAI now features a high-end, premium user interface across all alert surfaces:
- **Glassmorphism Design:** Sleek, blurred backgrounds with frosted glass cards for a modern, futuristic feel.
- **Neural Risk Ring:** A dynamic, glowing circular risk gauge in the extension popup that visualizes page safety in real-time.
- **Unified Aesthetics:** Consistent "Neural Protection" branding across the block page, in-page overlays, and the extension popup.
- **Micro-Animations:** Pulsing shield icons and smooth transitions that indicate the active status of our security agents.

## ⚙️ How It Works

1. **Visit a Webpage:** The Chrome Extension immediately intercepts the website before it fully loads.
2. **Capture Signals:** The extension extracts the URL, the page structure, and any active scripts trying to execute.
3. **Send to Backend:** This data is sent locally to `http://localhost:8000/scan`.
4. **AI Analysis:** The Orchestrator spins up parallel AI Agents to investigate different parts of the website simultaneously.
5. **Final Verdict:** A combined risk score (0-100) is generated. If it crosses the danger threshold, the extension throws up an unpassable warning screen to protect you.
6. **Memory:** The verdict is stored in a local Redis cache so that if you visit the site again, the scan happens instantly.

## 🚀 Setup Instructions

Below are the complete steps to start the **Backend Server**, **Redis**, and load the **Chrome Extension**.

### 1. Unified Launcher (Recommended)

The easiest way to start all services (Backend, Redis, and Simulator) is using the unified batch script:

1. Open a terminal in the project folder.
2. Run the launcher:
   ```bash
   .\start_v3.bat
   ```
   *This will automatically start Redis, the Backend (Port 8000), and the Attack Simulator (Port 5000).*

### 2. Manual Backend Setup (Optional)

If you prefer to start services individually:

1. **Start Redis Server:**
   ```bash
   cd "redis"
   .\redis-server.exe
   ```

2. **Start the Backend API:**
   ```bash
   # In a new terminal
   .\venv\Scripts\activate
   python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

### 3. Load the Chrome Extension

1. Open Google Chrome and go to `chrome://extensions/`.
2. Turn on **Developer mode** (toggle in the top right corner).
3. Click the **Load unpacked** button.
4. Select the `sentinelai-v2` folder.
5. The extension will be loaded. It will now automatically communicate with the Uvicorn backend running on your machine!

## 🔄 Making Changes

If you modify the project files, commit them to GitHub using these commands in your terminal (make sure your active directory is `sentinelai-v2`):

```bash
git add .
git commit -m "Describe your changes here"
git push
```
