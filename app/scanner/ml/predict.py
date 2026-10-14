import joblib
from pathlib import Path
from .features import extract_features, FEATURE_ORDER

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = PROJECT_ROOT / "app" / "scanner" / "ml" / "model.pkl"
_model = None

def get_model():
    global _model
    if _model is None and MODEL_PATH.exists():
        _model = joblib.load(MODEL_PATH)
    return _model

def refine_confidence(finding):
    model = get_model()
    if model is None:
        return finding
    feats = extract_features(finding)
    X = [[feats[k] for k in FEATURE_ORDER]]
    proba = model.predict_proba(X)[0]
    if len(proba) < 2:
        # Model was trained on a single class — no real probability to extract yet.
        return finding
    model_score = float(proba[1])
    finding.confidence = round((finding.confidence * 0.5) + (model_score * 0.5), 2)   
    return finding
