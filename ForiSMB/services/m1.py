from pathlib import Path
import joblib

from services.feature_builder import FeatureBuilder


class M1:
    def __init__(self, model_path: str | None = None):
        default_path = Path("data/stage1_model.pkl")
        self.model_path = Path(model_path) if model_path else default_path
        self.model = joblib.load(self.model_path)

    def predict(self, payload: dict) -> dict:
        x = FeatureBuilder.build_feature_matrix(payload)
        x = FeatureBuilder.align_to_model_features(x, self.model)

        pred = int(self.model.predict(x)[0])
        proba = self.model.predict_proba(x)[0].tolist()

        label = "Elevated" if pred == 1 else "Low"

        return {
            "model": "M1",
            "stage": "Stage 1",
            "prediction": pred,
            "label": label,
            "probabilities": {
                "Low": float(proba[0]),
                "Elevated": float(proba[1]),
            },
        }