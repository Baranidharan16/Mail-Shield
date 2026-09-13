"""
MailShield SOC & Email Forensics Platform - Unified Launcher
Builds frontend (if needed) and runs both backend & frontend together on a single port.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
BACKEND = ROOT / "backend"
VENV_PYTHON = BACKEND / ".venv" / "Scripts" / "python.exe"
PYTHON_EXE = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable

def main():
    dist_index = FRONTEND / "dist" / "index.html"
    if not dist_index.exists():
        print("[*] Building frontend bundle...")
        subprocess.run(["npm", "run", "build"], cwd=str(FRONTEND), shell=True, check=True)
    
    print("\n=======================================================")
    print(" [MAILSHIELD] SOC & Email Forensics Platform")
    print(" Unified Server: http://localhost:8000")
    print(" API Docs:       http://localhost:8000/docs")
    print("=======================================================\n")

    subprocess.run([
        PYTHON_EXE, "-m", "uvicorn", "main:app",
        "--host", "127.0.0.1", "--port", "8000"
    ], cwd=str(BACKEND))

if __name__ == "__main__":
    main()
