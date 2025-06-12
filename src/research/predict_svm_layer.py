import pickle
import argparse
import numpy as np
from pathlib import Path
from typing import Dict, Any
from huggingface_hub import hf_hub_download

from research.disassemble_python import MalwiObject, process_files

DEFAULT_HF_REPO = "schirrmacher/malwi-svm-layer"


def load_model_from_hf(repo_id: str, filename: str = "svm_layer.pkl") -> Dict[str, Any]:
    """Load the trained SVM model from Hugging Face Hub."""
    try:
        model_path = hf_hub_download(repo_id=repo_id, filename=filename)
        with open(model_path, "rb") as f:
            return pickle.load(f)
    except Exception as e:
        raise RuntimeError(f"Failed to load model from HF Hub: {e}")


def load_model_local(model_path: str) -> Dict[str, Any]:
    """Load the trained SVM model from local pickle file."""
    with open(model_path, "rb") as f:
        return pickle.load(f)


def predict(
    model_payload: Dict[str, Any], token_stats: Dict[str, float]
) -> Dict[str, Any]:
    model = model_payload["model"]
    feature_names = model_payload["feature_names"]
    label_encoder = model_payload["label_encoder"]

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

    # Determine model loading source
    print("Loading SVM model...")
    try:
        if args.svm:
            model_payload = load_model_local(args.svm)
        else:
            repo_id = args.hf_repo if args.hf_repo else DEFAULT_HF_REPO
            model_payload = load_model_from_hf(repo_id)
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return

    # Load ML models for tokenization
    try:
        MalwiObject.load_models_into_memory(
            model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
    except Exception as e:
        if not args.quiet:
            print(
                f"Warning: Could not initialize ML models: {e}. Maliciousness prediction will be disabled."
            )

    # Process files and get token stats
    result = process_files(
        input_path=Path(args.path),
        accepted_extensions=["py"],
        predict=True,
        retrieve_source_code=True,
        malicious_only=True,
    )

    token_stats = MalwiObject.collect_token_stats(result.malwi_objects)

    # Make prediction
    prediction = predict(model_payload, token_stats)

    # Display results
    print(f"- {len(result.all_files)} files scanned")
    print(f"- {len(result.skipped_files)} files skipped")
    print(f"- {len(result.malwi_objects)} malicious objects identified")
    if prediction["malicious"]:
        print(f"=> 👹 malicious {prediction['confidence']:.2f}")
    else:
        print(f"=> 🟢 not malicious {prediction['confidence']:.2f}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("👋")
