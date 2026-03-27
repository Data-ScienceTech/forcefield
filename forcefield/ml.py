"""ML-based threat detection using a bundled TF-IDF + LogisticRegression model.

Preferred runtime: ``onnxruntime`` (no scikit-learn needed at inference).
Fallback: ``joblib`` + ``scikit-learn`` (via ``pip install forcefield[ml]``).

Falls back gracefully if neither runtime is installed -- the Guard class
will use regex-only detection in that case.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_MODELS_DIR = Path(__file__).parent / "models"
_ONNX_PATH = _MODELS_DIR / "tfidf_model.onnx"
_JOBLIB_PATH = _MODELS_DIR / "tfidf_model.joblib"

_backend: Optional[str] = None  # "onnx" or "joblib"
_model = None
_onnx_session = None
_onnx_classes: Optional[List[str]] = None
_available: Optional[bool] = None


def _load_onnx():
    global _onnx_session, _onnx_classes, _backend, _available
    if _onnx_session is not None:
        return _onnx_session
    try:
        import onnxruntime as ort
    except ImportError:
        return None
    if not _ONNX_PATH.exists():
        return None
    try:
        opts = ort.SessionOptions()
        opts.inter_op_num_threads = 1
        opts.intra_op_num_threads = 1
        _onnx_session = ort.InferenceSession(str(_ONNX_PATH), opts)
        _backend = "onnx"
        _available = True
        logger.debug("Loaded ONNX model from %s", _ONNX_PATH)
        return _onnx_session
    except Exception as exc:
        logger.debug("ONNX load failed: %s", exc)
        return None


def _load_joblib():
    global _model, _backend, _available
    if _model is not None:
        return _model
    try:
        import joblib
    except ImportError:
        return None
    if not _JOBLIB_PATH.exists():
        return None
    try:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            _model = joblib.load(_JOBLIB_PATH)
        _backend = "joblib"
        _available = True
        logger.debug("Loaded joblib model from %s", _JOBLIB_PATH)
        return _model
    except Exception as exc:
        logger.warning("Failed to load joblib model: %s", exc)
        return None


def _ensure_loaded() -> bool:
    global _available
    if _available is True:
        return True
    if _available is None:
        if _load_onnx() is not None:
            return True
        if _load_joblib() is not None:
            return True
        _available = False
    return _available


def is_available() -> bool:
    """Return True if an ML model (ONNX or joblib) is available."""
    return _ensure_loaded()


_ONNX_CLASSES = ["benign", "data_exfiltration", "jailbreak", "prompt_injection"]


def _predict_onnx(texts: List[str]) -> List[Tuple[str, float, Dict[str, float]]]:
    import numpy as np
    input_name = _onnx_session.get_inputs()[0].name
    arr = np.array([[t] for t in texts])
    results_raw = _onnx_session.run(None, {input_name: arr})
    labels = results_raw[0]       # shape (N,) string labels
    probs_arr = results_raw[1]    # shape (N, num_classes) float probabilities
    out = []
    for i, label in enumerate(labels):
        prob_dict = {cls: float(probs_arr[i][j]) for j, cls in enumerate(_ONNX_CLASSES)}
        confidence = float(max(probs_arr[i]))
        out.append((str(label), confidence, prob_dict))
    return out


def _predict_joblib(texts: List[str]) -> List[Tuple[str, float, Dict[str, float]]]:
    preds = _model.predict(texts)
    all_probs = _model.predict_proba(texts)
    classes = _model.classes_
    out = []
    for pred, probs in zip(preds, all_probs):
        prob_dict = {str(cls): float(p) for cls, p in zip(classes, probs)}
        out.append((str(pred), float(max(probs)), prob_dict))
    return out


def predict(text: str) -> Tuple[str, float, Dict[str, float]]:
    """Classify a single text.

    Returns:
        ``(predicted_label, confidence, class_probabilities)``

        If no model is available, returns ``("unknown", 0.0, {})``.
    """
    if not _ensure_loaded():
        return ("unknown", 0.0, {})
    results = _predict_onnx([text]) if _backend == "onnx" else _predict_joblib([text])
    return results[0]


def score_threat(text: str) -> Tuple[float, str, Dict[str, float]]:
    """Return a threat score for *text*.

    Returns:
        ``(risk_score, predicted_label, class_probabilities)``

        ``risk_score`` is ``1.0 - P(benign)`` clamped to ``[0, 1]``.
        If no model is available, returns ``(0.0, "unknown", {})``.
    """
    label, confidence, probs = predict(text)
    if not probs:
        return (0.0, "unknown", {})
    benign_prob = probs.get("benign", 1.0)
    risk = 1.0 - benign_prob
    return (max(0.0, min(1.0, risk)), label, probs)


def batch_predict(texts: List[str]) -> List[Tuple[str, float, Dict[str, float]]]:
    """Classify a batch of texts. Returns list of ``(label, confidence, probs)``."""
    if not _ensure_loaded():
        return [("unknown", 0.0, {}) for _ in texts]
    return _predict_onnx(texts) if _backend == "onnx" else _predict_joblib(texts)
