In-place update for the existing AgentGuard backend
Target folder (Windows): C:\Users\aryan\OneDrive\Desktop\backend

This update is designed to be copied directly into the existing backend folder. It does not require creating or running a new backend folder.
Before copying
1. Stop Uvicorn in any terminal with Ctrl+C.
2. Make backup copies of the existing main.py and database.py.
3. Copy this archive's files directly into the existing backend root, not into a nested folder.
4. Replace main.py, database.py, .env.example, API.md and .gitignore if present. Add the other files. Do not copy or overwrite .env, .venv, or agentguard_audit.db.
5. .env.example is documentation/template only. Do not replace the real .env with it.
saas_store.py creates its own separate agentguard_app.db for local accounts, sessions, history, preferences, and API keys. It must not reuse agentguard_audit.db. A local .agentguard_auth_secret file is also created automatically if AGENTGUARD_AUTH_SECRET is unset; keep both files private and do not delete them while using local accounts.
Test from the existing backend folder
cd "C:\Users\aryan\OneDrive\Desktop\backend"
.\.venv\Scripts\Activate.ps1
python -m py_compile main.py agent_logic.py rag_engine.py mcp_gateway.py database.py detectors.py saas_store.py
python -m pytest -q
The updated source/test set passes 63 backend tests in the isolated verification environment. This is not a substitute for running tests on the user's Windows machine or validating the full Next.js build and end-to-end browser flow.
Run
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
If Windows returns WinError 10013, diagnose the port separately; do not delete Windows port reservations blindly. /health and /docs can be opened at http://127.0.0.1:8000/health and http://127.0.0.1:8000/docs once Uvicorn starts.