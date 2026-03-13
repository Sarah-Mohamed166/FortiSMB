import os
import json
import joblib
import numpy as np
import pandas as pd
import shap

from lime.lime_tabular import LimeTabularExplainer

# --------------------------
# Paths
# --------------------------
BASE_DIR = r"F:\FortiSMB\data"
CLASSIFIED_PATH = os.path.join(BASE_DIR, "classified_events.csv")
MODEL_PATH = os.path.join(BASE_DIR, "iforest_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "model_features.pkl")
OUTPUT_CSV = os.path.join(BASE_DIR, "xai_explanations.csv")

# --------------------------
# Controls
# --------------------------
# Explaining every flagged event with SHAP/LIME can be very slow on huge datasets.
# Start with top N highest-risk anomalies, then increase later.
MAX_EXPLANATIONS = 200
BACKGROUND_SIZE = 200
LIME_NUM_FEATURES = 8
SHAP_NSAMPLES = 100

# --------------------------
# Human-readable RBAC reasons
# --------------------------
RBAC_REASON_MAP = {
    "EMP_USB_NOT_ALLOWED": "Employee used a USB/device action that is not allowed by policy.",
    "EMP_CONF_EXEC_ACCESS_NOT_ALLOWED": "Employee tried to access confidential, executive, or board-related files.",
    "EMP_OFF_HOURS_LOGON_NOT_ALLOWED": "Employee logged in outside approved working hours.",
    "EMP_LARGE_DOWNLOAD_NOT_ALLOWED": "Employee exceeded the allowed download threshold.",

    "MGR_HR_FIN_SYS_NOT_ALLOWED": "Manager tried to access HR, finance, or system-technical files.",
    "MGR_HIGH_VOLUME_DOWNLOAD_NOT_ALLOWED": "Manager exceeded the allowed download threshold.",
    "MGR_UNAUTHORIZED_DEVICE_NOT_ALLOWED": "Manager used an unauthorized device or USB-related action.",
    "MGR_SYSTEM_CONFIG_EDIT_NOT_ALLOWED": "Manager attempted to modify protected system configuration or registry files.",

    "CTR_OUTSIDE_SCOPE_NOT_ALLOWED": "Contractor accessed files outside the allowed project/documentation scope.",
    "CTR_SENSITIVE_DATA_NOT_ALLOWED": "Contractor accessed sensitive data that is forbidden by policy.",
    "CTR_COPY_DOWNLOAD_NOT_ALLOWED": "Contractor attempted to copy or write files, which is not allowed.",

    "SYS_SENSITIVE_ACCESS_NOT_ALLOWED": "System administrator accessed sensitive business data outside permitted scope.",
    "SYS_USER_DATA_COPY_NOT_ALLOWED": "System administrator copied or read user profile/home data, which is restricted.",

    "EXEC_TECH_LOGS_ADMIN_TOOLS_NOT_ALLOWED": "Executive accessed technical admin tools or logs that are not permitted.",
    "EXEC_CONFIG_EDIT_NOT_ALLOWED": "Executive attempted to modify protected configuration or registry files.",
    "EXEC_BULK_DOWNLOAD_NOT_ALLOWED": "Executive exceeded the allowed bulk download threshold.",
}


def preprocess_for_model(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
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
        "average_path_length",
        "anomaly_score",
        "anomaly_label",
        "is_anomaly",
        "anomaly_score_normalized",
        "risk_level",
    ]

    df_features = df.drop(
        columns=[col for col in leakage_and_id_columns if col in df.columns],
        errors="ignore"
    ).copy()

    bool_columns = ["is_usb", "off_hours"]
    for col in bool_columns:
        if col in df_features.columns:
            df_features[col] = df_features[col].fillna(0).astype(int)

    if "hour" in df_features.columns:
        df_features["hour"] = df_features["hour"].fillna(-1)

    categorical_cols = ["action", "fortismb_role", "file_op"]
    existing_cat_cols = [c for c in categorical_cols if c in df_features.columns]
    df_encoded = pd.get_dummies(df_features, columns=existing_cat_cols, drop_first=False)

    for col in df_encoded.columns:
        if df_encoded[col].dtype == bool:
            df_encoded[col] = df_encoded[col].astype(int)

    df_encoded = df_encoded.fillna(0)

    for col in feature_cols:
        if col not in df_encoded.columns:
            df_encoded[col] = 0

    return df_encoded[feature_cols]


def format_pairs(names: list[str], vals: list[float], top_k: int = 5) -> str:
    pairs = sorted(zip(names, vals), key=lambda x: abs(x[1]), reverse=True)[:top_k]
    return "; ".join([f"{name} ({value:+.4f})" for name, value in pairs])


def violation_text(v: str) -> str:
    if not isinstance(v, str) or not v.strip():
        return "No RBAC violation code found."
    codes = [x.strip() for x in v.split("|") if x.strip()]
    if not codes:
        return "No RBAC violation code found."
    reasons = [RBAC_REASON_MAP.get(code, f"Unknown violation code: {code}") for code in codes]
    return " | ".join(reasons)


def combined_explanation(row, shap_text: str, lime_text: str) -> str:
    return (
        f"Risk={row.get('risk_level', 'Unknown')}; "
        f"role={row.get('fortismb_role', 'Unknown')}; "
        f"action={row.get('action', 'Unknown')}; "
        f"rbac_allowed={row.get('rbac_allowed', 'Unknown')}; "
        f"violations={row.get('rbac_violations', '')}. "
        f"Rule explanation: {violation_text(row.get('rbac_violations', ''))} "
        f"Model explanation via SHAP: {shap_text}. "
        f"Model explanation via LIME: {lime_text}."
    )


def main():
    print("Loading classified events...")
    df = pd.read_csv(CLASSIFIED_PATH, low_memory=False)

    print("Loading model and feature list...")
    model = joblib.load(MODEL_PATH)
    feature_cols = joblib.load(FEATURES_PATH)

    # Explain only suspicious/violating rows first
    flagged = df[
        (df.get("rbac_allowed", True) == False) |
        (df.get("is_anomaly", 0) == 1) |
        (df.get("risk_level", "") == "High Risk")
    ].copy()

    if flagged.empty:
        print("No flagged rows found. Nothing to explain.")
        return

    flagged = flagged.sort_values(
        by=["risk_level", "anomaly_score"],
        ascending=[False, False]
    )

    if MAX_EXPLANATIONS is not None:
        flagged = flagged.head(MAX_EXPLANATIONS).copy()

    print(f"Preparing explanations for {len(flagged)} flagged events...")

    # Build model matrix for full df and flagged subset
    X_all = preprocess_for_model(df, feature_cols)
    X_flagged = preprocess_for_model(flagged, feature_cols)

    # Background sample for SHAP/LIME
    background = X_all.sample(
        n=min(BACKGROUND_SIZE, len(X_all)),
        random_state=42
    )

    def predict_anomaly_score(arr):
        if isinstance(arr, pd.DataFrame):
            xdf = arr.copy()
        else:
            xdf = pd.DataFrame(arr, columns=feature_cols)
        return -model.decision_function(xdf)

    print("Initializing LIME...")
    lime_explainer = LimeTabularExplainer(
        training_data=background.values,
        feature_names=feature_cols,
        mode="regression",
        discretize_continuous=True,
        random_state=42
    )

    print("Initializing SHAP...")
    shap_explainer = shap.KernelExplainer(
        predict_anomaly_score,
        background.values
    )

    print("Computing SHAP values...")
    shap_values = shap_explainer.shap_values(
        X_flagged.values,
        nsamples=SHAP_NSAMPLES
    )

    records = []

    print("Computing LIME explanations...")
    for i in range(len(flagged)):
        original_row = flagged.iloc[i]
        instance = X_flagged.iloc[i].values

        # SHAP summary
        shap_row = shap_values[i]
        shap_text = format_pairs(feature_cols, shap_row.tolist(), top_k=5)

        # LIME summary
        lime_exp = lime_explainer.explain_instance(
            data_row=instance,
            predict_fn=lambda arr: predict_anomaly_score(arr).reshape(-1, 1),
            num_features=LIME_NUM_FEATURES
        )
        lime_pairs = lime_exp.as_list()
        lime_text = "; ".join([f"{name} ({weight:+.4f})" for name, weight in lime_pairs[:5]])

        records.append({
            "event_index": int(original_row.name),
            "user_id": original_row.get("user_id", ""),
            "fortismb_role": original_row.get("fortismb_role", ""),
            "action": original_row.get("action", ""),
            "timestamp": original_row.get("timestamp", ""),
            "rbac_allowed": original_row.get("rbac_allowed", ""),
            "rbac_violations": original_row.get("rbac_violations", ""),
            "rbac_explanation": violation_text(original_row.get("rbac_violations", "")),
            "anomaly_score": float(original_row.get("anomaly_score", np.nan)),
            "risk_level": original_row.get("risk_level", ""),
            "shap_top_features": shap_text,
            "lime_top_features": lime_text,
            "combined_explanation": combined_explanation(original_row, shap_text, lime_text),
        })

    out_df = pd.DataFrame(records)
    out_df.to_csv(OUTPUT_CSV, index=False)

    print(f"[Success] XAI explanations saved to: {OUTPUT_CSV}")
    print(out_df.head(10).to_string(index=False))


if __name__ == "__main__":
    main()