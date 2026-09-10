import os
import glob
from typing import Optional, Dict, Any

class ModelLoader:
    """
    Drop-in Model Loader for AI/ML models.
    Scans backend/models/saved_models/ for user-supplied ML/DL models
    (.pkl, .pt, .onnx, .joblib, .h5, etc.).
    Falls back gracefully to explainable heuristic forecasting when empty.
    """
    def __init__(self, models_dir: Optional[str] = None):
        if models_dir is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.models_dir = os.path.join(current_dir, "saved_models")
        else:
            self.models_dir = models_dir
            
        self.loaded_model = None
        self.model_filename = None
        self._detect_and_load_model()

    def _detect_and_load_model(self):
        if not os.path.exists(self.models_dir):
            return
        
        supported_exts = ["*.pkl", "*.joblib", "*.pt", "*.pth", "*.onnx", "*.h5"]
        found_files = []
        for ext in supported_exts:
            found_files.extend(glob.glob(os.path.join(self.models_dir, ext)))

        if found_files:
            target_file = found_files[0]
            self.model_filename = os.path.basename(target_file)
            try:
                if target_file.endswith((".pkl", ".joblib")):
                    import pickle
                    with open(target_file, "rb") as f:
                        self.loaded_model = pickle.load(f)
                    print(f"[ModelLoader] Successfully loaded ML model: {self.model_filename}")
                elif target_file.endswith((".pt", ".pth")):
                    try:
                        import torch
                        self.loaded_model = torch.load(target_file, map_location="cpu")
                        print(f"[ModelLoader] Successfully loaded PyTorch model: {self.model_filename}")
                    except ImportError:
                        print("[ModelLoader] PyTorch not installed. Falling back to rule-based engine.")
                else:
                    print(f"[ModelLoader] Found model file: {self.model_filename}")
            except Exception as e:
                print(f"[ModelLoader] Error loading {self.model_filename}: {e}")
                self.loaded_model = None
        else:
            self.loaded_model = None
            self.model_filename = None

    def is_custom_model_active(self) -> bool:
        return self.loaded_model is not None

    def get_model_info(self) -> Dict[str, Any]:
        if self.is_custom_model_active():
            return {
                "active": True,
                "name": self.model_filename,
                "type": "Custom Pretrained ML Model"
            }
        return {
            "active": False,
            "name": "Calibrated Heuristic and Temporal State Model",
            "type": "Explainable World Model (Baseline)"
        }

    def predict_progression(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.is_custom_model_active():
            return None
        try:
            if hasattr(self.loaded_model, "predict"):
                import numpy as np
                feat_vals = [
                    features.get("avg_packets", 0),
                    features.get("avg_volume", 0),
                    features.get("avg_connections", 0),
                    features.get("failed_logins", 0)
                ]
                X = np.array([feat_vals])
                preds = self.loaded_model.predict(X)
                return {"prediction": str(preds[0]), "custom": True}
        except Exception as err:
            print(f"[ModelLoader] Custom model inference warning: {err}")
        return None

model_loader = ModelLoader()
