# SentinelAI v2.0
Active Runtime Intelligence — Web Safety Extension

SentinelAI v2.0 is a local, privacy-first malicious website blocker that integrates a Chrome extension with a powerful backend powered by language models and a Redis cache.

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
