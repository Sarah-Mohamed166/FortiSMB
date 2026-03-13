# -*- coding: utf-8 -*-
"""
Isolation Forest Model + its metrics

Task
- Prepare F:/FortiSMB/data/ directory
- Load processed_events.csv
- Perform feature engineering
- Train Isolation Forest
- Generate anomaly scores and metrics
- Save:
    - iforest_model.pkl
    - model_features.pkl
    - processed_output.csv
"""

import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest


# =========================
# Paths
# =========================
output_dir = "F:/FortiSMB/data/"
input_file = os.path.join(output_dir, "processed_events.csv")
model_path = os.path.join(output_dir, "iforest_model.pkl")
feature_path = os.path.join(output_dir, "model_features.pkl")
data_output_path = os.path.join(output_dir, "processed_output.csv")
plot_output_path = os.path.join(output_dir, "average_path_length_hist.png")

os.makedirs(output_dir, exist_ok=True)
print(f"[Success] Output directory prepared: {output_dir}")


# =========================
# Load data
# =========================
df = pd.read_csv(input_file, low_memory=False)
print(f"[Success] Loaded dataset: {input_file}")
print(f"Original dataframe shape: {df.shape}")


# =========================
# Feature engineering
# =========================
# Drop non-behavioral / leakage / identifier columns
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

# Handle hour
if "hour" in df_features.columns:
    df_features["hour"] = df_features["hour"].fillna(-1)

# Categorical encoding
categorical_cols = ["action", "fortismb_role", "file_op"]
existing_cat_cols = [c for c in categorical_cols if c in df_features.columns]
df_encoded = pd.get_dummies(df_features, columns=existing_cat_cols, drop_first=False)

# Convert any bool dummies to int
for col in df_encoded.columns:
    if df_encoded[col].dtype == bool:
        df_encoded[col] = df_encoded[col].astype(int)

# Final cleanup
df_encoded = df_encoded.fillna(0)

print(f"Encoded dataframe shape: {df_encoded.shape}")
print(f"Total missing values: {df_encoded.isnull().sum().sum()}")
print(f"All columns numeric: {all(pd.api.types.is_numeric_dtype(df_encoded[c]) for c in df_encoded.columns)}")
print(df_encoded.head())


# =========================
# Train model
# =========================
feature_cols = df_encoded.columns.tolist()
X = df_encoded[feature_cols]

model = IsolationForest(
    n_estimators=100,
    contamination="auto",
    random_state=42,
    n_jobs=-1,
)

model.fit(X)
print("[Success] Isolation Forest model training complete.")


# =========================
# Metrics
# =========================
def c_factor(n: int) -> float:
    if n > 2:
        return 2 * (np.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n
    elif n == 2:
        return 1.0
    return 0.0


# Raw model outputs
score_samples = model.score_samples(X)          # lower = more abnormal
decision_scores = model.decision_function(X)    # lower = more abnormal
pred_labels = model.predict(X)                  # 1 = normal, -1 = anomaly

# Average path length
n_samples = X.shape[0]
constant = c_factor(n_samples)
average_path_length = -score_samples * constant

# User-friendly anomaly score: higher = more anomalous
anomaly_score = -decision_scores

# Save metrics to encoded dataframe
df_encoded["average_path_length"] = average_path_length
df_encoded["anomaly_score"] = anomaly_score
df_encoded["anomaly_label"] = pred_labels
df_encoded["is_anomaly"] = (df_encoded["anomaly_label"] == -1).astype(int)

print("--- Average Path Length Statistics ---")
print(df_encoded["average_path_length"].describe())

print("--- Anomaly Score Statistics ---")
print(df_encoded["anomaly_score"].describe())

print(df_encoded[["average_path_length", "anomaly_score", "anomaly_label", "is_anomaly"]].head())


# =========================
# Save outputs to original dataframe
# =========================
df_output = df.copy()
df_output["average_path_length"] = average_path_length
df_output["anomaly_score"] = anomaly_score
df_output["anomaly_label"] = pred_labels
df_output["is_anomaly"] = (df_output["anomaly_label"] == -1).astype(int)

df_output.to_csv(data_output_path, index=False)
print(f"[Success] Processed data saved to {data_output_path}")


# =========================
# Save artifacts
# =========================
joblib.dump(model, model_path)
print(f"[Success] Model saved to {model_path}")

joblib.dump(feature_cols, feature_path)
print(f"[Success] Feature list saved to {feature_path}")


# =========================
# Plot
# =========================
plt.figure(figsize=(12, 7))
plt.hist(df_output["average_path_length"], bins=50, edgecolor="black", alpha=0.7)
plt.title("Distribution of Average Path Lengths")
plt.xlabel("Average Path Length")
plt.ylabel("Frequency")

mean_path = df_output["average_path_length"].mean()
plt.axvline(mean_path, linestyle="dashed", linewidth=2, label=f"Mean = {mean_path:.2f}")

plt.legend()
plt.grid(axis="y", linestyle="--", alpha=0.6)
plt.tight_layout()
plt.savefig(plot_output_path)
plt.close()

print(f"[Success] Histogram saved to {plot_output_path}")


# =========================
# Verify outputs
# =========================
files_in_dir = os.listdir(output_dir)
print(f"\nContents of {output_dir}:")
for file_name in files_in_dir:
    print(f" - {file_name}")

print("\n[Done] Isolation Forest pipeline finished successfully.")