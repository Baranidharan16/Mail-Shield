"""
MailShield SOC & Email Forensics Platform - Unified Launcher
Builds frontend (if needed) and runs both backend & frontend together on a single port.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FRONTEND = ROOT / "frontend"
BACKEND = ROOT / "backend"
VENV_PYTHON = BACKEND / ".venv" / "Scripts" / "python.exe"
PYTHON_EXE = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable

def _frontend_is_stale(dist_index: Path) -> bool:
    """True when any frontend source file is newer than the built bundle."""
    if not dist_index.exists():
        return True
    built_at = dist_index.stat().st_mtime
    watched = [FRONTEND / "index.html", FRONTEND / "vite.config.ts", FRONTEND / ".env.production"]
    watched += [p for p in (FRONTEND / "src").rglob("*") if p.is_file()]
    return any(p.exists() and p.stat().st_mtime > built_at for p in watched)


def main():
    dist_index = FRONTEND / "dist" / "index.html"
    # Previously the bundle was only built when missing, so source changes
    # (including auth fixes) never reached the browser. Rebuild when stale.
    if _frontend_is_stale(dist_index):
        print("[*] Building frontend bundle (sources changed)...")
        subprocess.run(["npm", "run", "build"], cwd=str(FRONTEND), shell=True, check=True)

    # HOST=0.0.0.0 lets other devices on your network reach http://<your-ip>:8000
    host = os.getenv("HOST", "127.0.0.1")
    port = os.getenv("PORT", "8000")
    
    print("\n=======================================================")
    print(" [MAILSHIELD] SOC & Email Forensics Platform")
    print(" Unified Server: http://localhost:8000")
    print(" API Docs:       http://localhost:8000/docs")
    print("=======================================================\n")

    subprocess.run([
        PYTHON_EXE, "-m", "uvicorn", "main:app",
        "--host", host, "--port", port
    ], cwd=str(BACKEND))

if __name__ == "__main__":
    main()
