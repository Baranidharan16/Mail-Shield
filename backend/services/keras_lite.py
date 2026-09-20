"""
MailShield Keras-Lite runtime: runs the trained MailShield Keras text models
(TextVectorization -> Embedding(mask_zero) -> Bidirectional(LSTM) -> Dense(relu)
-> Dense(sigmoid)) in pure NumPy.

Why: TensorFlow needs >500 MB RAM and does not fit Render's free 512 MB instance.
The weights and vocabulary are exported 1:1 from the original .keras files into
a compressed .npz (see export_keras_lite.py), so predictions are numerically
identical to Keras (verified to <1e-5), with ~40 MB RAM and no TensorFlow.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Dict, List

import numpy as np

# Keras TextVectorization "lower_and_strip_punctuation" regex (keras.src.layers.preprocessing.text_vectorization)
_PUNCT_RE = re.compile(r'[!"#$%&()\*\+,\-\./:;<=>?@\[\\\]^_`{|}~\']')
# tf.strings.lower() without an encoding lowercases ASCII only; tf.strings.split()
# splits on ASCII whitespace only. Mirror both exactly.
_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}
_WS_RE = re.compile(r"[ \t\n\v\f\r]+")


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


class KerasLiteTextModel:
    """Pure-NumPy inference for an exported MailShield BiLSTM text model."""

    def __init__(self, npz_path: str):
        self.path = str(npz_path)
        d = np.load(self.path, allow_pickle=False)
        vocab = [str(t) for t in d["vocab"]]
        # index 0 = padding (""), index 1 = OOV ("[UNK]")
        self.index: Dict[str, int] = {tok: i for i, tok in enumerate(vocab) if i >= 2}
        self.seq_len = int(d["seq_len"])
        self.emb = d["emb"].astype(np.float32)
        self.fw = (d["fw_k"].astype(np.float32), d["fw_r"].astype(np.float32), d["fw_b"].astype(np.float32))
        self.bw = (d["bw_k"].astype(np.float32), d["bw_r"].astype(np.float32), d["bw_b"].astype(np.float32))
        self.d1_w, self.d1_b = d["d1_w"].astype(np.float32), d["d1_b"].astype(np.float32)
        self.d2_w, self.d2_b = d["d2_w"].astype(np.float32), d["d2_b"].astype(np.float32)
        self.units = self.fw[1].shape[0]
        self._lock = threading.Lock()

    # --- TextVectorization(standardize="lower_and_strip_punctuation", split="whitespace") ---
    def vectorize(self, text: str) -> List[int]:
        text = _PUNCT_RE.sub("", (text or "").translate(_ASCII_LOWER))
        ids = [self.index.get(tok, 1) for tok in _WS_RE.split(text) if tok]
        return ids[: self.seq_len]

    def _lstm(self, x: np.ndarray, weights) -> np.ndarray:
        kernel, recurrent, bias = weights
        u = self.units
        h = np.zeros(u, dtype=np.float32)
        c = np.zeros(u, dtype=np.float32)
        xw = x @ kernel + bias  # precompute input projections for all steps
        for t in range(xw.shape[0]):
            z = xw[t] + h @ recurrent
            i = _sigmoid(z[:u])
            f = _sigmoid(z[u:2 * u])
            g = np.tanh(z[2 * u:3 * u])
            o = _sigmoid(z[3 * u:])
            c = f * c + i * g
            h = o * np.tanh(c)
        return h

    def predict_proba(self, text: str) -> np.ndarray:
        ids = self.vectorize(text)
        if not ids:  # Keras with an all-masked sequence returns the zero state
            feats = np.zeros(2 * self.units, dtype=np.float32)
        else:
            # mask_zero=True: only the real (non-padding) tokens are processed;
            # the backward LSTM reads the real tokens in reverse order.
            x = self.emb[np.asarray(ids)]
            feats = np.concatenate([self._lstm(x, self.fw), self._lstm(x[::-1], self.bw)])
        hidden = np.maximum(0.0, feats @ self.d1_w + self.d1_b)
        return _sigmoid(hidden @ self.d2_w + self.d2_b)


_CACHE: Dict[str, KerasLiteTextModel] = {}
_CACHE_LOCK = threading.Lock()


def load_lite_model(npz_path: str) -> KerasLiteTextModel:
    p = str(Path(npz_path).resolve())
    with _CACHE_LOCK:
        if p not in _CACHE:
            _CACHE[p] = KerasLiteTextModel(p)
        return _CACHE[p]
