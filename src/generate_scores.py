import pandas as pd
import joblib
import matplotlib.pyplot as plt
import numpy as np

# --------------------------
# File paths
# --------------------------
DATA_PATH = r"F:\FortiSMB\data\processed_events.csv"
MODEL_PATH = r"F:\FortiSMB\data\iforest_model.pkl"
FEATURES_PATH = r"F:\FortiSMB\data\model_features.pkl"
OUTPUT_CSV = r"F:\FortiSMB\data\scored_events.csv"
OUTPUT_PLOT = r"F:\FortiSMB\data\anomaly_distribution.png"
FORTISMB_OUTPUT = r"F:\FortiSMB\data\scored_events.csv"


def main():
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH, low_memory=False)

    print("Loading model...")
    model = joblib.load(MODEL_PATH)

    print("Loading feature list...")
    feature_cols = joblib.load(FEATURES_PATH)

    # Drop non-model columns
    leakage_and_id_columns = [
        "id",
        "timestamp",
        "user_id",
        "pc",
        "file_path",
        "raw_activity",
        "rbac_violations",
        "rbac_allowed",
        "_ts",
    ]
    df_features = df.drop(columns=[col for col in leakage_and_id_columns if col in df.columns]).copy()

    # Handle boolean-like columns
    bool_columns = ["is_usb", "off_hours"]
    for col in bool_columns:
        if col in df_features.columns:
            df_features[col] = df_features[col].fillna(0).astype(int)

    if "hour" in df_features.columns:
        df_features["hour"] = df_features["hour"].fillna(-1)

    # Same encoding as training
    categorical_cols = ["action", "fortismb_role", "file_op"]
    existing_cat_cols = [c for c in categorical_cols if c in df_features.columns]
    df_encoded = pd.get_dummies(df_features, columns=existing_cat_cols, drop_first=False)

    # Convert bools to int
    for col in df_encoded.columns:
        if df_encoded[col].dtype == bool:
            df_encoded[col] = df_encoded[col].astype(int)

    df_encoded = df_encoded.fillna(0)

    # Align with model features
    for col in feature_cols:
        if col not in df_encoded.columns:
            df_encoded[col] = 0

    X = df_encoded[feature_cols]

    # Scores
    raw_scores = model.score_samples(X)
    decision_scores = model.decision_function(X)
    pred_labels = model.predict(X)

    # Higher = more anomalous
    df["anomaly_score"] = -decision_scores
    df["anomaly_label"] = pred_labels
    df["is_anomaly"] = (df["anomaly_label"] == -1).astype(int)

    # Optional normalized score 0..1
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s - min_s == 0:
        df["anomaly_score_normalized"] = 0.0
    else:
        df["anomaly_score_normalized"] = 1 - ((raw_scores - min_s) / (max_s - min_s))

    # Plot
    plt.figure(figsize=(10, 5))
    plt.hist(df["anomaly_score"], bins=50, edgecolor="black", alpha=0.7)
    plt.title("Anomaly Score Distribution")
    plt.xlabel("Anomaly Score (higher = more anomalous)")
    plt.ylabel("Event Count")
    plt.tight_layout()
    plt.savefig(OUTPUT_PLOT)
    plt.close()

    print(f"Histogram saved to {OUTPUT_PLOT}")

    # Save
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Scored dataset saved to {OUTPUT_CSV}")

    df.to_csv(FORTISMB_OUTPUT, index=False)
    print(f"Scored dataset also saved to {FORTISMB_OUTPUT}")


if __name__ == "__main__":
    main()