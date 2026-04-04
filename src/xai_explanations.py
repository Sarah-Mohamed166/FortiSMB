import os
import numpy as np
import pandas as pd
import shap
import joblib

from lime.lime_tabular import LimeTabularExplainer

# --------------------------
# Paths
# --------------------------
BASE_DIR = r"F:\FortiSMB\data"
DATA_PATH = os.path.join(BASE_DIR, "fortismb_final_stratified_data.csv")
STAGE1_MODEL_PATH = os.path.join(BASE_DIR, "stage1_model.pkl")
STAGE2_MODEL_PATH = os.path.join(BASE_DIR, "stage2_model.pkl")

OUTPUT_ALL_RBAC_CSV = os.path.join(BASE_DIR, "xai_explanations.csv")
OUTPUT_TOP_SHAP_CSV = os.path.join(BASE_DIR, "xai_explanations_top200_shap.csv")
OUTPUT_ANALYST_LIME_CSV = os.path.join(BASE_DIR, "xai_explanations_analyst_lime.csv")

# --------------------------
# Controls
# --------------------------
TOP_SHAP_EXPLANATIONS = 200
BACKGROUND_SIZE = 200
LIME_NUM_FEATURES = 8

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

# --------------------------
# Helpers
# --------------------------
def violation_text(v: str) -> str:
    if pd.isna(v):
        return "No RBAC violation code found."

    v = str(v).strip()
    if not v:
        return "No RBAC violation code found."

    codes = [x.strip() for x in v.split("|") if x.strip()]
    if not codes:
        return "No RBAC violation code found."

    reasons = [RBAC_REASON_MAP.get(code, f"Unknown violation code: {code}") for code in codes]
    return " | ".join(reasons)


def format_pairs(names, vals, top_k=5):
    pairs = sorted(zip(names, vals), key=lambda x: abs(x[1]), reverse=True)[:top_k]
    return "; ".join([f"{name} ({value:+.4f})" for name, value in pairs])


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    X_num = df[[c for c in ["is_usb", "hour", "off_hours"] if c in df.columns]].copy()

    if "is_usb" in X_num.columns:
        X_num["is_usb"] = X_num["is_usb"].fillna(False).astype("float32")

    if "off_hours" in X_num.columns:
        X_num["off_hours"] = X_num["off_hours"].fillna(False).astype("float32")

    if "hour" in X_num.columns:
        X_num["hour"] = pd.to_numeric(X_num["hour"], errors="coerce").fillna(0).astype("float32")

    cat_cols = [c for c in ["action", "fortismb_role", "file_op"] if c in df.columns]
    X_cat = pd.get_dummies(df[cat_cols].astype(str)) if cat_cols else pd.DataFrame(index=df.index)

    X = pd.concat([X_num, X_cat], axis=1)

    for col in X.columns:
        if X[col].dtype == bool:
            X[col] = X[col].astype(int)

    return X.fillna(0)


def align_to_model_features(X: pd.DataFrame, model) -> pd.DataFrame:
    if not hasattr(model, "feature_names_in_"):
        raise ValueError("Saved model does not expose feature_names_in_. Cannot align features safely.")

    feature_cols = list(model.feature_names_in_)

    for col in feature_cols:
        if col not in X.columns:
            X[col] = 0

    return X[feature_cols]


def build_rbac_explanations(flagged: pd.DataFrame) -> pd.DataFrame:
    out = flagged.copy()

    out["rbac_explanation"] = out["rbac_violations"].apply(violation_text)

    cols = [
        "user_id",
        "fortismb_role",
        "action",
        "timestamp",
        "file_path",
        "file_op",
        "is_usb",
        "rbac_allowed",
        "rbac_violations",
        "rbac_explanation",
        "anomaly_score",
        "final_risk_level",
        "system_action",
    ]

    existing_cols = [c for c in cols if c in out.columns]
    return out[existing_cols]


def rank_critical_events(df: pd.DataFrame) -> pd.DataFrame:
    temp = df.copy()

    risk_order = {"High": 3, "Medium": 2, "Low": 1}
    temp["risk_rank"] = temp["final_risk_level"].map(risk_order).fillna(0)
    temp["anomaly_score_num"] = pd.to_numeric(temp.get("anomaly_score", np.nan), errors="coerce")

    # Lower anomaly score first if more suspicious in your pipeline
    temp = temp.sort_values(
        by=["risk_rank", "anomaly_score_num"],
        ascending=[False, True]
    )

    return temp.drop(columns=["risk_rank"], errors="ignore")


def explain_with_shap(df_subset: pd.DataFrame, model, model_name: str) -> pd.DataFrame:
    if df_subset.empty:
        return pd.DataFrame()

    X_subset = build_feature_matrix(df_subset)
    X_subset = align_to_model_features(X_subset.copy(), model)

    shap_explainer = shap.TreeExplainer(model)
    shap_values = shap_explainer.shap_values(X_subset)

    if isinstance(shap_values, list):
        shap_matrix = shap_values[1]
    else:
        shap_values = np.array(shap_values)
        if len(shap_values.shape) == 3:
            shap_matrix = shap_values[:, :, 1]
        else:
            shap_matrix = shap_values

    records = []
    for i in range(len(df_subset)):
        row = df_subset.iloc[i]
        shap_row = shap_matrix[i]
        shap_text = format_pairs(list(X_subset.columns), shap_row.tolist(), top_k=5)

        records.append({
            "event_index": int(row.name),
            "user_id": row.get("user_id", ""),
            "fortismb_role": row.get("fortismb_role", ""),
            "action": row.get("action", ""),
            "timestamp": row.get("timestamp", ""),
            "rbac_violations": row.get("rbac_violations", ""),
            "rbac_explanation": violation_text(row.get("rbac_violations", "")),
            "anomaly_score": pd.to_numeric(row.get("anomaly_score", np.nan), errors="coerce"),
            "final_risk_level": row.get("final_risk_level", ""),
            "system_action": row.get("system_action", ""),
            "explained_model": model_name,
            "shap_top_features": shap_text,
        })

    return pd.DataFrame(records)


def generate_lime_for_event(event_index: int, save_csv: bool = True) -> pd.DataFrame:
    """
    Analyst-on-demand function.
    Use this only when an analyst wants a deep explanation for one event.
    """
    print(f"Loading data for analyst LIME explanation on event_index={event_index}...")
    df = pd.read_csv(DATA_PATH, low_memory=False)
    stage1_model = joblib.load(STAGE1_MODEL_PATH)

    if event_index not in df.index:
        raise ValueError(f"event_index {event_index} not found in dataset index.")

    row_df = df.loc[[event_index]].copy()
    X_all = build_feature_matrix(df)
    X_all = align_to_model_features(X_all.copy(), stage1_model)

    X_row = X_all.loc[[event_index]].copy()
    background = X_all.sample(n=min(BACKGROUND_SIZE, len(X_all)), random_state=42)

    def predict_fn(arr):
        if isinstance(arr, pd.DataFrame):
            xdf = arr.copy()
        else:
            xdf = pd.DataFrame(arr, columns=X_all.columns)
        probs = stage1_model.predict_proba(xdf)
        return probs[:, 1]

    lime_explainer = LimeTabularExplainer(
        training_data=background.values,
        feature_names=list(X_all.columns),
        mode="regression",
        discretize_continuous=True,
        random_state=42
    )

    lime_exp = lime_explainer.explain_instance(
        data_row=X_row.iloc[0].values,
        predict_fn=lambda arr: predict_fn(arr).reshape(-1, 1),
        num_features=LIME_NUM_FEATURES
    )

    lime_text = "; ".join([f"{name} ({weight:+.4f})" for name, weight in lime_exp.as_list()[:5]])

    output = pd.DataFrame([{
        "event_index": int(event_index),
        "user_id": row_df.iloc[0].get("user_id", ""),
        "fortismb_role": row_df.iloc[0].get("fortismb_role", ""),
        "action": row_df.iloc[0].get("action", ""),
        "timestamp": row_df.iloc[0].get("timestamp", ""),
        "rbac_violations": row_df.iloc[0].get("rbac_violations", ""),
        "rbac_explanation": violation_text(row_df.iloc[0].get("rbac_violations", "")),
        "anomaly_score": pd.to_numeric(row_df.iloc[0].get("anomaly_score", np.nan), errors="coerce"),
        "final_risk_level": row_df.iloc[0].get("final_risk_level", ""),
        "system_action": row_df.iloc[0].get("system_action", ""),
        "explained_model": "stage1_model.pkl (Low vs Elevated)",
        "lime_top_features": lime_text,
    }])

    if save_csv:
        if os.path.exists(OUTPUT_ANALYST_LIME_CSV):
            existing = pd.read_csv(OUTPUT_ANALYST_LIME_CSV)
            output = pd.concat([existing, output], ignore_index=True)
        output.to_csv(OUTPUT_ANALYST_LIME_CSV, index=False)
        print(f"[SAVED] Analyst LIME explanation saved to: {OUTPUT_ANALYST_LIME_CSV}")

    return output


def main():
    print("Loading final stratified data...")
    df = pd.read_csv(DATA_PATH, low_memory=False)

    if "rbac_allowed" not in df.columns:
        raise ValueError("Column 'rbac_allowed' not found in final stratified dataset.")

    print("Loading models...")
    stage1_model = joblib.load(STAGE1_MODEL_PATH)
    stage2_model = joblib.load(STAGE2_MODEL_PATH) if os.path.exists(STAGE2_MODEL_PATH) else None

    # 1) ALL RBAC violations
    flagged = df[df["rbac_allowed"] == False].copy()

    if flagged.empty:
        print("No RBAC violation rows found. Nothing to explain.")
        return

    print(f"Building RBAC explanations for all violations: {len(flagged):,} rows")
    all_rbac_df = build_rbac_explanations(flagged)
    all_rbac_df.to_csv(OUTPUT_ALL_RBAC_CSV, index=False)
    print(f"[SAVED] All RBAC explanations: {OUTPUT_ALL_RBAC_CSV}")

    # 2) TOP 200 SHAP explanations
    ranked = rank_critical_events(flagged)
    top_df = ranked.head(TOP_SHAP_EXPLANATIONS).copy()

    print(f"Generating SHAP explanations for top {len(top_df):,} critical events...")

    s1_subset = top_df.copy()
    s1_shap_df = explain_with_shap(
        s1_subset,
        stage1_model,
        "stage1_model.pkl (Low vs Elevated)"
    )

    # Optional Stage 2 SHAP only for Medium/High within top subset
    s2_shap_df = pd.DataFrame()
    if stage2_model is not None:
        s2_subset = top_df[top_df["final_risk_level"].isin(["Medium", "High"])].copy()
        if not s2_subset.empty:
            s2_shap_df = explain_with_shap(
                s2_subset,
                stage2_model,
                "stage2_model.pkl (Medium vs High)"
            )

    top_shap_df = pd.concat([s1_shap_df, s2_shap_df], ignore_index=True)
    top_shap_df.to_csv(OUTPUT_TOP_SHAP_CSV, index=False)
    print(f"[SAVED] Top SHAP explanations: {OUTPUT_TOP_SHAP_CSV}")

    print("\nDone.")
    print(f"All RBAC explanations count: {len(all_rbac_df):,}")
    print(f"Top SHAP explanations count: {len(top_shap_df):,}")
    print("\nTo generate a single LIME explanation later, call for example:")
    print("generate_lime_for_event(event_index=12345)")


if __name__ == "__main__":
    main()