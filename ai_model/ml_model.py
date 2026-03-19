"""
ai_model/ml_model.py  —  TF-IDF + Random Forest scam classifier

Train:
    python train_model.py

After training, scam_model.pkl appears in ai_model/
"""
import os
import pickle
import re

MODEL_PATH = os.path.join(os.path.dirname(__file__), "scam_model.pkl")


def preprocess(text: str) -> str:
    text = text.lower()
    text = re.sub(r"https?://\S+", " url_token ", text)
    text = re.sub(r"\b\d{10,}\b",  " phone_token ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def build_pipeline():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            preprocessor=preprocess,
            ngram_range=(1, 2),
            max_features=15000,
            sublinear_tf=True,
            min_df=2,
        )),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])


def train(csv_path: str):
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report

    print(f"[AI] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path)

    # Support SMS Spam Collection format (v1=ham/spam, v2=text)
    if "v1" in df.columns and "v2" in df.columns:
        df = df.rename(columns={"v2": "text", "v1": "label_str"})
        df["label"] = (df["label_str"] == "spam").astype(int)
    elif "label" not in df.columns or "text" not in df.columns:
        raise ValueError("CSV must have 'text' and 'label' columns (0=safe, 1=scam)")

    X = df["text"].astype(str)
    y = df["label"].astype(int)
    print(f"[AI] {len(df)} samples | Scam: {y.sum()} | Safe: {(y==0).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    pipeline = build_pipeline()
    print("[AI] Training ...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("\n[AI] Evaluation:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Scam"]))

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"[AI] Model saved → {MODEL_PATH}")
    return pipeline


# Module-level cache
_pipeline = None


def load_model():
    global _pipeline
    if _pipeline is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Model not found at {MODEL_PATH}. "
                "Run: python train_model.py --data your_dataset.csv"
            )
        with open(MODEL_PATH, "rb") as f:
            _pipeline = pickle.load(f)
    return _pipeline


def predict(text: str) -> dict:
    """Returns {'ml_score': float 0-1, 'label': int 0/1}"""
    try:
        model = load_model()
        prob  = model.predict_proba([text])[0]
        scam_prob = float(prob[1]) if len(prob) > 1 else float(prob[0])
        return {"ml_score": scam_prob, "label": int(scam_prob >= 0.5)}
    except FileNotFoundError:
        return {"ml_score": 0.5, "label": 0}