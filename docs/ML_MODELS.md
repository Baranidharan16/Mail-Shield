# MailShield ML / NLP models

## Models in production

| Panel / role | Model | Architecture | Test metrics (from training metadata) |
|---|---|---|---|
| **ML Phishing Detection** panel + text component of the risk score | `Mailshield_phishing_model_v2` | TextVectorization (20k vocab, 300 tokens) → Embedding 128 → BiLSTM 64 → Dense 64 → sigmoid | accuracy 0.993, F1 0.993, ROC-AUC 0.9996 on 23,520 held-out emails (CEAS, Enron, Ling, Nazario, Nigerian Fraud, SpamAssassin, phishing_email) |
| **NLP Threat-Pattern** panel (6 categories) | `MailShield_NLP_v2` | TextVectorization (15k vocab, 200 tokens) → Embedding 96 → BiLSTM 48 → Dense 64 → 6× sigmoid | macro-F1 0.83, micro-F1 0.90 on 6,036 held-out emails |
| Structured forensic-feature model | `app/ml/artifacts/structured_model.joblib` | scikit-learn | see `app/ml/artifacts/metrics.json` |
| Auxiliary TF-IDF text model | `app/ml/artifacts/text_model.joblib` | scikit-learn | see `app/ml/artifacts/metrics.json` |

## Keras-Lite runtime (no TensorFlow in production)

TensorFlow needs more RAM than Render's free 512 MB instance has. The trained
Keras models are therefore exported **1:1** (same vocabulary, same weights) to
`backend/models/*.npz` and executed by `backend/services/keras_lite.py` in pure
NumPy:

* predictions match Keras to < 1e-5 (tokenization identical),
* the two models add ~42 MB RAM (whole backend ≈ 380 MB),
* `LOAD_ML_MODELS=false` now only means "never import TensorFlow".

**After retraining a `.keras` model**, regenerate the exports on a machine with
TensorFlow installed:

```bash
cd backend
python scripts/export_keras_lite.py   # writes + verifies models/*.npz
```

## How the risk score uses the models

`overall = fusion(deterministic forensics 45%, structured model 15%, text model 25%, threat intel 15%)`

The text component is the average of the Keras BiLSTM and the TF-IDF model.
On the MailShield evaluation set (20 emails: 7 legitimate incl. real Google /
Anthropic notifications, 13 spoofing / phishing / BEC / malware / auth-failure):

| Text component | Correct | False alarms | Missed |
|---|---|---|---|
| TF-IDF only | 20/20 | 0 | 0 |
| Keras only | 19/20 | 0 | 1 (lookalike-domain mail with harmless wording) |
| **Average (used)** | **20/20** | **0** | **0** |

Safety gates in `app/ai/fusion.py`:
* models alone can never declare a threat without deterministic evidence;
* a DMARC-authenticated sender with no strong forensic indicator is capped at 24 (LOW),
  so genuine security notices / sign-in links are not flagged because of their wording.
