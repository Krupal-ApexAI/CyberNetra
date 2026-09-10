# Saved Models Directory

Drop your trained Machine Learning or Deep Learning models here!

Supported formats:
- `.pkl` or `.joblib` (Scikit-Learn, XGBoost, LightGBM)
- `.pt` or `.pth` (PyTorch Sequence / LSTM / Transformer models)
- `.onnx` (ONNX runtime models)

When a model file is placed in this directory, `model_loader.py` will automatically detect it upon startup and route prediction requests to your model.
If empty, CYBERNETRA AI seamlessly uses the calibrated temporal rule engine.
