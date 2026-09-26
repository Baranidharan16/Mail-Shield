"""Per-job isolation inside the sandbox container.

Each analysis runs in a short-lived forked child process that, before it
touches the untrusted bytes:
  * caps its address space, CPU time and open files (setrlimit),
  * forbids creating files (RLIMIT_FSIZE=0) — nothing is ever written to disk,
  * disables all socket creation (no network, even if the container had it),
  * is killed if it exceeds the wall-clock timeout.
A crash, hang or memory blow-up in a parser therefore only kills that child;
the service keeps running and reports the job as a (suspicious) timeout.
"""
from __future__ import annotations

import multiprocessing as mp
import os
import socket
import traceback
from typing import Any, Dict

MEM_MB = int(os.getenv("SANDBOX_JOB_MEMORY_MB", "384"))
CPU_SECONDS = int(os.getenv("SANDBOX_JOB_CPU_SECONDS", "30"))
WALL_SECONDS = int(os.getenv("SANDBOX_JOB_TIMEOUT_SECONDS", "45"))


def _lockdown() -> Dict[str, Any]:
    applied: Dict[str, Any] = {}
    try:
        import resource
        limits = {
            "RLIMIT_AS": MEM_MB * 1024 * 1024,
            "RLIMIT_CPU": CPU_SECONDS,
            "RLIMIT_FSIZE": 0,
            "RLIMIT_NOFILE": 64,
            "RLIMIT_CORE": 0,
        }
        for name, val in limits.items():
            try:
                resource.setrlimit(getattr(resource, name), (val, val))
                applied[name] = val
            except (ValueError, OSError, AttributeError):
                applied[name] = "unsupported"
    except ImportError:  # non-POSIX dev machine
        applied["resource"] = "unavailable"

    def _no_net(*_a, **_k):
        raise PermissionError("network access is disabled inside the sandbox job")

    socket.socket = _no_net  # type: ignore[assignment]
    socket.create_connection = _no_net  # type: ignore[assignment]
    socket.getaddrinfo = _no_net  # type: ignore[assignment]
    applied["network"] = "disabled"
    return applied


def _child(conn, payload):
    try:
        applied = _lockdown()
        from .engine import analyze_request
        result = analyze_request(payload)
        result["isolation"] = {"mode": "forked-process", "limits": applied, "wall_timeout_s": WALL_SECONDS}
        conn.send({"ok": True, "result": result})
    except MemoryError:
        conn.send({"ok": False, "error": "memory limit exceeded"})
    except Exception as exc:  # noqa: BLE001
        conn.send({"ok": False, "error": f"{type(exc).__name__}: {exc}", "trace": traceback.format_exc()[-1500:]})
    finally:
        conn.close()


def run_isolated(payload: dict) -> dict:
    ctx = mp.get_context("fork") if hasattr(os, "fork") else mp.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child, args=(child, payload), daemon=True)
    proc.start()
    child.close()
    msg = None
    if parent.poll(WALL_SECONDS):
        try:
            msg = parent.recv()
        except EOFError:
            msg = None
    proc.join(2)
    if proc.is_alive():
        proc.kill()
        proc.join(2)
    if msg is None:
        reason = "timed out" if proc.exitcode in (None, -9) else f"crashed (exit code {proc.exitcode})"
        return {"ok": False, "error": f"analysis job {reason}", "exitcode": proc.exitcode}
    return msg
