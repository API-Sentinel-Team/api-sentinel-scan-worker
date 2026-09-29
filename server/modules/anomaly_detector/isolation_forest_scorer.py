"""
Isolation Forest anomaly scorer using PyOD.
Scores incoming requests on a 0.0–1.0 scale.
"""
import math

try:
    import numpy as np
    from pyod.models.iforest import IForest
    PYOD_AVAILABLE = True
except ImportError:
    PYOD_AVAILABLE = False


class IsolationForestScorer:
    """
    Trains an Isolation Forest on feature vectors extracted from request logs.
    Falls back to a heuristic scorer if PyOD is not installed.
    """

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self._model = None
        self._trained = False

    def fit(self, feature_vectors: list[list]) -> None:
        """Train the model on a list of feature vectors."""
        if not PYOD_AVAILABLE or len(feature_vectors) < 20:
            return
        X = np.array(feature_vectors, dtype=float)
        self._model = IForest(contamination=self.contamination, random_state=42)
        self._model.fit(X)
        self._trained = True

    def score(self, request_features: dict) -> float:
        """
        Returns anomaly score 0.0 (normal) – 1.0 (highly anomalous).
        request_features keys:
          requests_per_sec, unique_paths, payload_entropy,
          param_count, error_rate, response_time_ms
        """
        vector = self._extract_vector(request_features)

        if self._trained and PYOD_AVAILABLE:
            X = np.array([vector], dtype=float)
            # PyOD decision_function returns negative = anomaly
            raw = self._model.decision_function(X)[0]
            # Normalise to 0–1 (higher = more anomalous)
            score = 1.0 / (1.0 + math.exp(raw))  # sigmoid inversion
            return round(float(score), 4)

        # Heuristic fallback
        return self._heuristic_score(request_features)

    def _extract_vector(self, f: dict) -> list:
        return [
            float(f.get("requests_per_sec", 0)),
            float(f.get("unique_paths", 1)),
            float(f.get("payload_entropy", 0)),
            float(f.get("param_count", 0)),
            float(f.get("error_rate", 0)),
            float(f.get("response_time_ms", 100)),
        ]

    def _heuristic_score(self, f: dict) -> float:
        """Simple rule-based anomaly score when PyOD unavailable."""
        score = 0.0
        rps = f.get("requests_per_sec", 0)
        if rps > 100:
            score += 0.4
        elif rps > 30:
            score += 0.2
        if f.get("error_rate", 0) > 0.5:
            score += 0.3
        if f.get("payload_entropy", 0) > 4.5:
            score += 0.2
        if f.get("unique_paths", 1) > 50:
            score += 0.1
        return round(min(score, 1.0), 4)
