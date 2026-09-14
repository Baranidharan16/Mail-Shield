"""
mailshield_codec_fix.py — Must be imported before ANY keras / tensorflow import.

Problem
-------
Keras 3.x stores the TextVectorization vocabulary as a plain text file inside
the .keras zip archive.  When loading, `index_lookup.load_assets()` calls:

    with open(vocabulary_filepath, "r") as f:   # no encoding= kwarg!

On Windows, Python's default encoding is cp1252 ("charmap").  The vocabulary
file contains byte 0x9D which is UNDEFINED in cp1252, producing:

    ValueError: 'charmap' codec can't decode byte 0x9d in position 27516

Fix
---
We patch `builtins.open` so that every text-mode `open()` call that does not
already specify an encoding defaults to UTF-8.  This must happen before the
`keras.src.layers.preprocessing.index_lookup` module is imported (i.e. before
the first `import keras` anywhere in the process).

Why not PYTHONUTF8=1?
---------------------
`PYTHONUTF8` is a CPython interpreter startup flag read before `site.py` runs.
Setting it in `os.environ` mid-process has no effect on an already-running
interpreter's default encoding.  The builtins.open patch is the only reliable
in-process fix.

Why not in ml_service.py / nlp_service.py?
-------------------------------------------
Those files applied the patch at module-level, but they are imported AFTER
`from services.ml_service import get_ml_service` which itself happens AFTER
`import keras` has already fired inside FastAPI's import chain.  Once
`index_lookup` is imported, the patch is pointless.  Putting it in THIS module,
which is imported as the VERY FIRST thing in main.py (before FastAPI, before
the services), guarantees the patch is in place before any Keras code runs.
"""
from __future__ import annotations

import builtins as _builtins
import os as _os

# ── 1. Set environment variables that affect TF/Keras startup ─────────────────
_os.environ.setdefault("TF_ENABLE_ONEDNN_OPTS", "0")
_os.environ.setdefault("CUDA_VISIBLE_DEVICES", "-1")
_os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")

# ── 2. Patch builtins.open to default to UTF-8 ────────────────────────────────
_original_open = _builtins.open


def _utf8_open(*args, **kwargs):
    """Thin wrapper around builtins.open that defaults encoding to 'utf-8'.

    Only applies to text-mode opens that do not already specify an encoding.
    Binary-mode opens are passed through unchanged.
    """
    mode = kwargs.get("mode", args[1] if len(args) > 1 else "r")
    if "b" not in str(mode) and kwargs.get("encoding") is None:
        kwargs["encoding"] = "utf-8"
        kwargs.setdefault("errors", "replace")  # extra safety: don't crash on remaining bad bytes
    return _original_open(*args, **kwargs)


_builtins.open = _utf8_open  # type: ignore[assignment]
