import csv
from pathlib import Path
from .features import extract_features, FEATURE_ORDER

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATASET_PATH = PROJECT_ROOT / "data" / "labeled_findings.csv"

def append_labeled_finding(finding, label: int):
    """label: 1 = real vulnerability (true positive), 0 = false positive"""
    DATASET_PATH.parent.mkdir(exist_ok=True)
    features = extract_features(finding)
    file_exists = DATASET_PATH.exists()
    with open(DATASET_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_ORDER + ["label"])
        if not file_exists:
            writer.writeheader()
        writer.writerow({**features, "label": label})

def load_dataset():
    import pandas as pd
    if not DATASET_PATH.exists():
        return None
    return pd.read_csv(DATASET_PATH)
