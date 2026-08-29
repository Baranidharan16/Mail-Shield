"""
Model provider abstraction + versioning.

Tracks, per prediction: model name, model version, training-dataset
version, feature version, timestamp, and prediction confidence - so no
model is ever "silently replaced" and every prediction is traceable to
exactly which artifact produced it.

Design intent per the brief: "The application must work even if the
advanced model is unavailable." `ModelProvider.predict()` therefore never
raises past this layer - if the trained artifact is missing/corrupt, it
returns a clearly-labeled UNAVAILABLE result and the Threat Fusion Engine
(app/ai/fusion.py) simply drops that component from the fused score
rather than failing the whole investigation.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

ARTIFACT_DIR = os.path.join(os.path.dirname(__file__), "artifacts")


@dataclass
class ModelMetadata:
    model_name: str
    model_version: str
    training_dataset_version: str
    feature_version: str
    trained_at: str
    algorithm: str
    classes: List[str]


@dataclass
class ModelPrediction:
    available: bool
    model_metadata: Optional[ModelMetadata]
    predicted_label: Optional[str]
    class_probabilities: Dict[str, float] = field(default_factory=dict)
    confidence: float = 0.0
    top_features: List[Dict[str, object]] = field(default_factory=list)  # interpretable contributions
    note: Optional[str] = None
    predicted_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def save_metadata(path_prefix: str, metadata: ModelMetadata) -> None:
    with open(f"{path_prefix}.meta.json", "w", encoding="utf-8") as f:
        json.dump(metadata.__dict__, f, indent=2)


def load_metadata(path_prefix: str) -> Optional[ModelMetadata]:
    meta_path = f"{path_prefix}.meta.json"
    if not os.path.exists(meta_path):
        return None
    with open(meta_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return ModelMetadata(**data)
