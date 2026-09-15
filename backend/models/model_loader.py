"""
UNSW-NB15 Model Loader for CyberNetra.

Loads all trained model artifacts once at application startup:
  - Random Forest binary intrusion detector
  - XGBoost attack-family classifier
  - Attack feature preprocessor (ColumnTransformer / Pipeline)
  - Label encoder (numeric class → attack name)
  - Feature info (expected feature names, categorical/numerical split, threshold)
  - model_config.json

Also preserves the original saved_models/ scanning for backward compatibility.
"""

import os
import json
import glob
from typing import Optional, Dict, Any, List


class ModelLoader:
    """
    Loads and exposes all UNSW-NB15 model artifacts.
    Models are loaded once at import time via the module-level singleton.
    """

    def __init__(self, models_dir: Optional[str] = None):
        if models_dir is None:
            self.models_dir = os.path.dirname(os.path.abspath(__file__))
        else:
            self.models_dir = models_dir

        # UNSW-NB15 model artifacts
        self.binary_model = None
        self.attack_model = None
        self.attack_preprocessor = None
        self.label_encoder = None
        self.feature_info: Dict[str, Any] = {}
        self.model_config: Dict[str, Any] = {}
        self.binary_threshold: float = 0.30

        # Legacy: user-supplied model in saved_models/
        self.loaded_model = None
        self.model_filename = None

        # Track loading status
        self._unsw_loaded = False
        self._load_errors: List[str] = []

        # Load everything
        self._load_unsw_models()
        self._detect_and_load_saved_model()

    def _load_unsw_models(self):
        """Load all UNSW-NB15 .pkl artifacts and model_config.json."""
        # Compatibility patch for scikit-learn version differences during unpickling
        try:
            import sklearn.compose._column_transformer as ct
            if not hasattr(ct, "_RemainderColsList"):
                class _RemainderColsList(list):
                    pass
                ct._RemainderColsList = _RemainderColsList
        except Exception:
            pass

        try:
            import joblib
        except ImportError:
            self._load_errors.append(
                "joblib not installed. Run: pip install joblib"
            )
            print(f"[ModelLoader] ERROR: {self._load_errors[-1]}")
            return

        artifact_map = {
            "binary_model": "unsw_nb15_binary_model.pkl",
            "attack_model": "unsw_nb15_attack_model.pkl",
            "attack_preprocessor": "unsw_nb15_attack_preprocessor.pkl",
            "label_encoder": "unsw_nb15_label_encoder.pkl",
            "feature_info": "unsw_nb15_feature_info.pkl",
        }

        for attr, filename in artifact_map.items():
            filepath = os.path.join(self.models_dir, filename)
            if not os.path.exists(filepath):
                self._load_errors.append(f"Missing model file: {filename}")
                print(f"[ModelLoader] WARNING: {filename} not found at {filepath}")
                continue
            try:
                obj = joblib.load(filepath)
                setattr(self, attr, obj)
                print(f"[ModelLoader] [OK] Loaded {filename}")
            except Exception as e:
                self._load_errors.append(f"Failed to load {filename}: {e}")
                print(f"[ModelLoader] ERROR loading {filename}: {e}")

        # Load model_config.json
        config_path = os.path.join(self.models_dir, "model_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    self.model_config = json.load(f)
                print("[ModelLoader] [OK] Loaded model_config.json")
            except Exception as e:
                self._load_errors.append(f"Failed to load model_config.json: {e}")
                print(f"[ModelLoader] ERROR loading model_config.json: {e}")

        # Set threshold from feature_info or config (feature_info takes precedence)
        if isinstance(self.feature_info, dict):
            self.binary_threshold = self.feature_info.get(
                "binary_threshold",
                self.model_config.get("binary_threshold", 0.30)
            )
        else:
            self.binary_threshold = self.model_config.get("binary_threshold", 0.30)

        # Validate that critical models loaded
        if self.binary_model is not None and self.feature_info:
            self._unsw_loaded = True
            print(
                f"[ModelLoader] [OK] UNSW-NB15 pipeline ready "
                f"(threshold={self.binary_threshold}, "
                f"features={len(self.get_binary_features())})"
            )
        else:
            print("[ModelLoader] WARNING: UNSW-NB15 pipeline NOT fully loaded")

    # ──────────────────────────────────────────────
    # Feature accessors
    # ──────────────────────────────────────────────

    def get_binary_features(self) -> List[str]:
        """Return the ordered list of features expected by the binary model."""
        if isinstance(self.feature_info, dict):
            return self.feature_info.get("binary_features", [])
        return []

    def get_attack_features(self) -> List[str]:
        """Return the ordered list of features expected by the attack model."""
        if isinstance(self.feature_info, dict):
            return self.feature_info.get("attack_features", [])
        return []

    def get_categorical_features(self) -> List[str]:
        """Return the list of categorical feature names."""
        if isinstance(self.feature_info, dict):
            return self.feature_info.get("categorical_features", [])
        return []

    def get_numerical_features(self) -> List[str]:
        """Return the list of numerical feature names."""
        if isinstance(self.feature_info, dict):
            return self.feature_info.get("numerical_features", [])
        return []

    def get_attack_categories(self) -> List[str]:
        """Return the list of attack category names."""
        if isinstance(self.feature_info, dict):
            cats = self.feature_info.get("attack_categories", [])
            if cats:
                return cats
        return self.model_config.get("attack_categories", [])

    def is_unsw_pipeline_ready(self) -> bool:
        """Check if the UNSW-NB15 ML pipeline is fully loaded."""
        return self._unsw_loaded

    # ──────────────────────────────────────────────
    # Legacy: saved_models/ scanning (backward compat)
    # ──────────────────────────────────────────────

    def _detect_and_load_saved_model(self):
        """Scan saved_models/ for user-supplied ML/DL models (legacy behavior)."""
        saved_dir = os.path.join(self.models_dir, "saved_models")
        if not os.path.exists(saved_dir):
            return

        supported_exts = ["*.pkl", "*.joblib", "*.pt", "*.pth", "*.onnx", "*.h5"]
        found_files = []
        for ext in supported_exts:
            found_files.extend(glob.glob(os.path.join(saved_dir, ext)))

        if found_files:
            target_file = found_files[0]
            self.model_filename = os.path.basename(target_file)
            try:
                if target_file.endswith((".pkl", ".joblib")):
                    import pickle
                    with open(target_file, "rb") as f:
                        self.loaded_model = pickle.load(f)
                    print(f"[ModelLoader] [OK] Loaded saved model: {self.model_filename}")
                elif target_file.endswith((".pt", ".pth")):
                    try:
                        # pyrefly: ignore [missing-import]
                        import torch
                        self.loaded_model = torch.load(target_file, map_location="cpu")
                        print(f"[ModelLoader] [OK] Loaded PyTorch model: {self.model_filename}")
                    except ImportError:
                        print("[ModelLoader] PyTorch not installed. Skipping saved model.")
                else:
                    print(f"[ModelLoader] Found model file: {self.model_filename}")
            except Exception as e:
                print(f"[ModelLoader] Error loading {self.model_filename}: {e}")
                self.loaded_model = None

    def reload(self) -> Dict[str, Any]:
        """
        Hot-reload all UNSW-NB15 model artifacts from disk.

        Call this after training or manual model replacement to pick up
        the new .pkl files without restarting the server.

        Returns:
            Dict with 'status', 'errors', and 'model_info' keys.
        """
        print("[ModelLoader] Reloading all model artifacts...")

        # Reset state
        self.binary_model = None
        self.attack_model = None
        self.attack_preprocessor = None
        self.label_encoder = None
        self.feature_info = {}
        self.model_config = {}
        self.binary_threshold = 0.30
        self.loaded_model = None
        self.model_filename = None
        self._unsw_loaded = False
        self._load_errors = []

        # Re-load everything
        self._load_unsw_models()
        self._detect_and_load_saved_model()

        status = "ok" if self._unsw_loaded else "error"
        print(f"[ModelLoader] Reload complete. Status: {status}")
        return {
            "status": status,
            "errors": self._load_errors,
            "model_info": self.get_model_info(),
        }

    def is_custom_model_active(self) -> bool:
        return self.loaded_model is not None

    def get_model_info(self) -> Dict[str, Any]:
        info = {
            "unsw_pipeline_ready": self._unsw_loaded,
            "binary_threshold": self.binary_threshold,
            "load_errors": self._load_errors,
        }

        if self._unsw_loaded:
            info.update({
                "binary_model_type": self.feature_info.get("binary_model", "RandomForest"),
                "attack_model_type": self.feature_info.get("attack_model", "XGBoost"),
                "feature_count": len(self.get_binary_features()),
                "attack_categories": self.get_attack_categories(),
                "dataset": self.feature_info.get("dataset", "UNSW-NB15"),
            })

        if self.is_custom_model_active():
            info["custom_model"] = {
                "active": True,
                "name": self.model_filename,
                "type": "Custom Pretrained ML Model",
            }
        else:
            info["custom_model"] = {
                "active": False,
                "name": "Calibrated Heuristic and Temporal State Model",
                "type": "Explainable World Model (Baseline)",
            }

        return info

    def predict_progression(self, features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Legacy: predict using custom saved model."""
        if not self.is_custom_model_active():
            return None
        try:
            if hasattr(self.loaded_model, "predict"):
                import numpy as np
                feat_vals = [
                    features.get("avg_packets", 0),
                    features.get("avg_volume", 0),
                    features.get("avg_connections", 0),
                    features.get("failed_logins", 0),
                ]
                X = np.array([feat_vals])
                preds = self.loaded_model.predict(X)
                return {"prediction": str(preds[0]), "custom": True}
        except Exception as err:
            print(f"[ModelLoader] Custom model inference warning: {err}")
        return None


# Module-level singleton — loaded once at import time
model_loader = ModelLoader()
