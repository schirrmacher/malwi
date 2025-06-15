import torch
import pickle
import logging
import argparse
import numpy as np

from pathlib import Path
from huggingface_hub import hf_hub_download
from typing import Dict, Any, Optional

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
            with open(model_path, "rb") as f:
                GLOBAL_SVM_MODEL = pickle.load(f)
        else:
            downloaded_path = hf_hub_download(
                repo_id=repo_id or DEFAULT_HF_REPO,
                filename=DEFAULT_HF_FILE,
            )
            with open(downloaded_path, "rb") as f:
                GLOBAL_SVM_MODEL = pickle.load(f)
    except Exception as e:
        logging.error(f"Failed to load SVM model: {e}")
        GLOBAL_SVM_MODEL = None


def predict(token_stats: Dict[str, float]) -> Dict[str, Any]:
    if GLOBAL_SVM_MODEL is None:
        raise RuntimeError(
            "SVM model not initialized. Call initialize_svm_model() first."
        )

    model = GLOBAL_SVM_MODEL["model"]
    feature_names = GLOBAL_SVM_MODEL["feature_names"]
    label_encoder = GLOBAL_SVM_MODEL["label_encoder"]

    feature_vector = [token_stats.get(name, 0) for name in feature_names]
    feature_vector = np.array(feature_vector).reshape(1, -1)

    prediction = model.predict(feature_vector)[0]
    probabilities = model.predict_proba(feature_vector)[0]
    predicted_label = label_encoder.inverse_transform([prediction])[0]

    return {
        "predicted_label": predicted_label,
        "confidence": max(probabilities),
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

    print("Loading SVM model...")
    initialize_svm_model(model_path=args.svm, repo_id=args.hf_repo)

    if GLOBAL_SVM_MODEL is None:
        print("❌ Failed to load SVM model. Exiting.")
        return

    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
    except Exception as e:
        if not args.quiet:
            print(
                f"Warning: Could not initialize ML models: {e}. Maliciousness prediction will be disabled."
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

    print(f"- {len(result.all_files)} files scanned")
    print(f"- {len(result.skipped_files)} files skipped")
    print(f"- {len(result.objects)} malicious objects identified")
    if prediction["malicious"]:
        print(f"=> 👹 malicious {prediction['confidence']:.2f}")
    else:
        print(f"=> 🟢 not malicious {prediction['confidence']:.2f}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("👋")
