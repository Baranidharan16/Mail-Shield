"""
Export the MailShield Keras text models to the TensorFlow-free "Keras-Lite"
format used in production (services/keras_lite.py).

Run this ONLY on a machine that has TensorFlow/Keras installed, every time you
retrain a .keras model:

    cd backend
    python scripts/export_keras_lite.py

It writes models/<name>.npz next to each .keras file and verifies that the
NumPy runtime reproduces Keras' predictions.
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

MODELS = ["MailShield_NLP_v2", "Mailshield_phishing_model_v2"]
SAMPLES = [
    "",
    "Hi team, lunch at 1pm tomorrow?",
    "URGENT: your account will be suspended. Verify your password now at http://secure-login.example",
    "Please process the attached invoice and wire $9,800 to the new bank account today.",
]


def export(name: str) -> None:
    import keras
    import tensorflow as tf
    from services.keras_lite import KerasLiteTextModel

    src = BACKEND / "models" / f"{name}.keras"
    dst = BACKEND / "models" / f"{name}.npz"
    model = keras.models.load_model(src)
    tv = next(l for l in model.layers if l.__class__.__name__ == "TextVectorization")
    cfg = tv.get_config()
    assert cfg["standardize"] == "lower_and_strip_punctuation" and cfg["split"] == "whitespace", cfg
    emb = next(l for l in model.layers if l.__class__.__name__ == "Embedding").get_weights()[0]
    bi = next(l for l in model.layers if l.__class__.__name__ == "Bidirectional")
    fw, bw = bi.forward_layer.get_weights(), bi.backward_layer.get_weights()
    d1, d2 = [l for l in model.layers if l.__class__.__name__ == "Dense"]
    np.savez_compressed(
        dst,
        vocab=np.array([str(t) for t in tv.get_vocabulary()]),
        emb=emb.astype(np.float32),
        fw_k=fw[0], fw_r=fw[1], fw_b=fw[2], bw_k=bw[0], bw_r=bw[1], bw_b=bw[2],
        d1_w=d1.get_weights()[0], d1_b=d1.get_weights()[1],
        d2_w=d2.get_weights()[0], d2_b=d2.get_weights()[1],
        seq_len=np.array(cfg["output_sequence_length"]),
    )
    lite = KerasLiteTextModel(str(dst))
    ref = model.predict(tf.constant(SAMPLES), verbose=0)
    got = np.stack([lite.predict_proba(t) for t in SAMPLES])
    diff = float(np.abs(ref - got).max())
    print(f"{name}: wrote {dst.name} ({dst.stat().st_size / 1e6:.1f} MB), max |keras - lite| = {diff:.2e}")
    if diff > 1e-3:
        raise SystemExit("Mismatch between Keras and Keras-Lite - do not deploy this export.")


if __name__ == "__main__":
    for n in MODELS:
        export(n)
