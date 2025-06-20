import pickle
import argparse
import numpy as np
import pandas as pd

from pathlib import Path
from huggingface_hub import hf_hub_download
from typing import Dict, Any, Optional

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)

DEFAULT_HF_REPO = "schirrmacher/malwi"
DEFAULT_HF_FILE = "svm_layer.pkl"

# Global SVM model variable
GLOBAL_SVM_MODEL: Optional[Dict[str, Any]] = None


def initialize_svm_model(
    model_path: Optional[str] = None, repo_id: Optional[str] = None
):
    global GLOBAL_SVM_MODEL

    # If already initialized, skip re-loading
    if GLOBAL_SVM_MODEL is not None:
        return

    try:
        if model_path:
            # Check if model_path is a directory or file
            model_path_obj = Path(model_path)
            if model_path_obj.is_dir():
                # If it's a directory, look for svm_layer.pkl inside it
                svm_file_path = model_path_obj / "svm_layer.pkl"
            else:
                # If it's a file, use it directly
                svm_file_path = model_path_obj

            with open(svm_file_path, "rb") as f:
                GLOBAL_SVM_MODEL = pickle.load(f)
        else:
            downloaded_path = hf_hub_download(
                repo_id=repo_id or DEFAULT_HF_REPO,
                filename=DEFAULT_HF_FILE,
            )
            with open(downloaded_path, "rb") as f:
                GLOBAL_SVM_MODEL = pickle.load(f)
    except Exception as e:
        error(f"Failed to load SVM model: {e}")
        GLOBAL_SVM_MODEL = None


def predict(token_stats: Dict[str, float]) -> Dict[str, Any]:
    if GLOBAL_SVM_MODEL is None:
        raise RuntimeError(
            "SVM model not initialized. Call initialize_svm_model() first."
        )

    model = GLOBAL_SVM_MODEL["model"]
    feature_names = GLOBAL_SVM_MODEL["feature_names"]
    label_encoder = GLOBAL_SVM_MODEL["label_encoder"]
    scaler = GLOBAL_SVM_MODEL.get("scaler")
    feature_selector = GLOBAL_SVM_MODEL.get("feature_selector")

    # Create feature vector from token stats
    feature_vector = [token_stats.get(name, 0) for name in feature_names]

    # Convert to pandas DataFrame to maintain feature names for scaler
    feature_df = pd.DataFrame([feature_vector], columns=feature_names)

    # Apply scaling if scaler was used during training
    if scaler is not None:
        feature_vector_scaled = scaler.transform(feature_df)
        # Convert back to DataFrame if feature selection is needed
        if feature_selector is not None:
            feature_df = pd.DataFrame(feature_vector_scaled, columns=feature_names)
            feature_vector = feature_vector_scaled
        else:
            feature_vector = feature_vector_scaled
    else:
        feature_vector = feature_df.values

    # Apply feature selection if selector was used during training
    if feature_selector is not None:
        if hasattr(feature_selector, "transform"):
            # For SelectKBest and similar selectors
            feature_vector = feature_selector.transform(feature_vector)
        elif isinstance(feature_selector, np.ndarray):
            # For RandomForest-based selection (indices array)
            feature_vector = feature_vector[:, feature_selector]

    prediction = model.predict(feature_vector)[0]
    probabilities = model.predict_proba(feature_vector)[0]
    predicted_label = label_encoder.inverse_transform([prediction])[0]

    return {
        "predicted_label": predicted_label,
        "confidence": max(probabilities),
        "confidence_benign": probabilities[0],
        "confidence_malicious": probabilities[1],
        "malicious": predicted_label == "malicious",
    }


def main():
    from research.disassemble_python import MalwiObject, process_files

    parser = argparse.ArgumentParser(
        description="Make predictions using trained SVM model"
    )

    model_group = parser.add_mutually_exclusive_group(required=False)
    model_group.add_argument("--svm", "-s", help="Path to local SVM model file")
    model_group.add_argument(
        "--hf-repo",
        "-r",
        help="Hugging Face repository ID (default: schirrmacher/malwi-svm-layer)",
    )

    parser.add_argument(
        "--tokenizer-path", "-t", metavar="PATH", help="Tokenizer path", default=None
    )
    parser.add_argument(
        "--model-path", "-m", metavar="PATH", help="DistilBert model path", default=None
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress warnings")
    parser.add_argument("path", help="Path to be scanned for prediction")

    args = parser.parse_args()

    # Configure messaging system
    configure_messaging(quiet=args.quiet)

    progress("Loading SVM model...")
    initialize_svm_model(model_path=args.svm, repo_id=args.hf_repo)

    if GLOBAL_SVM_MODEL is None:
        error("Failed to load SVM model. Exiting.")
        return

    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
    except Exception as e:
        if not args.quiet:
            warning(
                f"Could not initialize ML models: {e}. Maliciousness prediction will be disabled."
            )

    result = process_files(
        input_path=Path(args.path),
        accepted_extensions=["py"],
        predict=True,
        retrieve_source_code=True,
        malicious_only=True,
    )

    token_stats = MalwiObject.collect_token_stats(result.objects)
    prediction = predict(token_stats)

    # Temporarily disable these outputs to fix tqdm - they're shown in the final report anyway
    pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        info("👋")
