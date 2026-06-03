import pandas as pd


class FeatureBuilder:
    @staticmethod
    def build_feature_matrix(data: dict) -> pd.DataFrame:
        df = pd.DataFrame([data])

        for col in ["is_usb", "hour", "off_hours"]:
            if col not in df.columns:
                df[col] = 0

        df["is_usb"] = df["is_usb"].fillna(False).astype("float32")
        df["off_hours"] = df["off_hours"].fillna(False).astype("float32")
        df["hour"] = pd.to_numeric(df["hour"], errors="coerce").fillna(0).astype("float32")

        cat_cols = ["action", "fortismb_role", "file_op"]
        for col in cat_cols:
            if col not in df.columns:
                df[col] = ""

        x_cat = pd.get_dummies(df[cat_cols].astype(str))
        x_num = df[["is_usb", "hour", "off_hours"]]

        x = pd.concat([x_num, x_cat], axis=1)

        for col in x.columns:
            if x[col].dtype == bool:
                x[col] = x[col].astype(int)

        return x.fillna(0)

    @staticmethod
    def align_to_model_features(x: pd.DataFrame, model) -> pd.DataFrame:
        if not hasattr(model, "feature_names_in_"):
            raise ValueError("Model does not contain feature_names_in_.")

        feature_cols = list(model.feature_names_in_)

        for col in feature_cols:
            if col not in x.columns:
                x[col] = 0

        return x[feature_cols]