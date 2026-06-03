from pathlib import Path
import joblib

from services.feature_builder import FeatureBuilder


class M2:
    def __init__(self, model_path: str | None = None):
        default_path = Path("data/stage2_model.pkl")
        self.model_path = Path(model_path) if model_path else default_path
        self.model = joblib.load(self.model_path)

    def predict(self, payload: dict) -> dict:
        x = FeatureBuilder.build_feature_matrix(payload)
        x = FeatureBuilder.align_to_model_features(x, self.model)

        pred = int(self.model.predict(x)[0])

        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(x)[0].tolist()
            probabilities = {
                "Medium": float(proba[0]),
                "High": float(proba[1]),
            }
        else:
            probabilities = None

        label = "High" if pred == 1 else "Medium"

        return {
            "model": "M2",
            "stage": "Stage 2",
            "prediction": pred,
            "label": label,
            "probabilities": probabilities,
        }