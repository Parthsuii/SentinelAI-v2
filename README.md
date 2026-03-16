# SentinelAI v2.0
Active Runtime Intelligence — Web Safety Extension

SentinelAI v2.0 is a local, privacy-first malicious website blocker that integrates a Chrome extension with a powerful backend powered by language models and a Redis cache.

## 🧠 Introduction

Traditional web security relies on static blocklists that are often outdated and slow to respond to new threats. **SentinelAI v2.0** uses Active Runtime Intelligence — instead of just checking if a URL is bad, it actively watches how a website *behaves* when you visit it. 

It runs entirely on your local machine, ensuring that your browsing data never leaves your device out of privacy concerns.

## 🏗️ Architecture Overview

SentinelAI is divided into two main components that communicate with each other in real-time:

1. **The Chrome Extension (Frontend):** Injects "hooks" into websites to monitor suspicious behavior (like stealing passwords, capturing keystrokes, or taking over your hardware) and blocks malicious pages instantly.
2. **The LangGraph Backend (AI Core):** A set of 6 specialized AI Agents running on your machine (via Python, Uvicorn, and Ollama) that analyze the data caught by the extension to reach a finalized "Verdict" (Safe, Warning, or Block) using Advanced Large Language Models.

### The 6 AI Agents
- **URL Agent:** Analyzes the URL structure for phishing tricks.
- **Content Agent:** Scans the static HTML/DOM of the webpage.
- **Runtime Agent:** Analyzes the active behavior and hooks triggered by the site.
- **Exfil Agent:** Watches for attempts to secretly steal or transmit your data.
- **Visual Agent:** Checks for UI red flags and layout spoofing.
- **Verdict Agent (Orchestrator):** Gathers all the reports and makes the final decision.

## ⚙️ How It Works

1. **Visit a Webpage:** The Chrome Extension immediately intercepts the website before it fully loads.
2. **Capture Signals:** The extension extracts the URL, the page structure, and any active scripts trying to execute.
3. **Send to Backend:** This data is sent locally to `http://localhost:8000/scan`.
4. **AI Analysis:** The Orchestrator spins up the 6 parallel AI Agents to investigate different parts of the website simultaneously.
5. **Final Verdict:** A combined risk score (0-100) is generated. If it crosses the danger threshold, the extension throws up an unpassable warning screen to protect you.
6. **Memory:** The verdict is stored in a local Redis cache so that if you visit the site again, the scan happens instantly.
## 🚀 Setup Instructions

Below are the complete steps to start the **Backend Server**, **Redis**, and load the **Chrome Extension**.

### 1. Backend Setup

The backend handles scanning operations via an API.

1. Open your terminal and navigate to the project folder:
   ```bash
   cd "c:\ai security\sentinelai-v2"
   ```

2. Create a Python Virtual Environment:
   ```bash
   python -m venv venv
   ```

3. Activate the Virtual Environment:
   * **Windows/PowerShell:** `.\venv\Scripts\activate`

4. Install the requirements (inside the virtual environment):
   ```bash
   pip install -r backend\requirements.txt
   ```

### 2. Install and Start Redis

The backend requires Redis for short-term caching. 

1. Ensure the Windows port of Redis is downloaded (this should be inside the `redis` folder in the project workspace).
2. Open a **new terminal tab** and navigate to the project directory:
   ```bash
   cd "c:\ai security\sentinelai-v2\redis"
   ```
3. Start the Redis server:
   ```bash
   .\redis-server.exe
   ```
   *(Keep this terminal window running in the background).*

### 3. Start the Backend API

Go back to your initial terminal (with the `(venv)` active).

1. Ensure you are in the `sentinelai-v2` directory.
2. Run the Uvicorn server:
   ```bash
   python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
   ```
   *You should see output indicating that the API is running on `http://0.0.0.0:8000`.*

### 4. Load the Chrome Extension

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
