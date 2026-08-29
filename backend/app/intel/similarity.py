"""Email similarity engine (TF-IDF cosine) - Phase 2 Part 9."""
from __future__ import annotations
from typing import List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


def compute_similarity(target_text: str, candidate_texts: List[str]) -> List[float]:
    """Returns cosine similarity of target_text against each candidate,
    using a small TF-IDF space built just from these documents (real
    computation, no external service)."""
    docs = [target_text] + candidate_texts
    if not any(d.strip() for d in docs):
        return [0.0] * len(candidate_texts)
    vectorizer = TfidfVectorizer(max_features=300, ngram_range=(1, 2), min_df=1)
    try:
        matrix = vectorizer.fit_transform(docs)
    except ValueError:
        return [0.0] * len(candidate_texts)
    sims = cosine_similarity(matrix[0:1], matrix[1:])[0]
    return [float(s) for s in sims]
