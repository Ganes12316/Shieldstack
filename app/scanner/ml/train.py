import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from .dataset import load_dataset
from .features import FEATURE_ORDER

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = PROJECT_ROOT / "app" / "scanner" / "ml" / "model.pkl"

def train():
    df = load_dataset()
    if df is None or len(df) < 10:
        n = 0 if df is None else len(df)
        print(f"Only {n} labeled examples — too few to train meaningfully. Need ~20-30+ minimum.")
        return

    X, y = df[FEATURE_ORDER], df["label"]
    stratify = y if y.nunique() > 1 else None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=stratify)

    clf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42, class_weight="balanced")
    clf.fit(X_train, y_train)

    if len(X_test):
        print(classification_report(y_test, clf.predict(X_test)))

    print("Feature importances:")
    for name, imp in sorted(zip(FEATURE_ORDER, clf.feature_importances_), key=lambda x: -x[1]):
        print(f"  {name}: {imp:.3f}")

    joblib.dump(clf, MODEL_PATH)
    print(f"Saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
