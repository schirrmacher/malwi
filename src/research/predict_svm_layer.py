import pickle
import argparse

import numpy as np
from pathlib import Path
from typing import Dict, Any

from research.disassemble_python import MalwiObject, process_files


def load_model(model_path: str) -> Dict[str, Any]:
    """Load the trained SVM model from pickle file."""
    with open(model_path, "rb") as f:
        return pickle.load(f)


def predict(
    model_payload: Dict[str, Any], token_stats: Dict[str, float]
) -> Dict[str, Any]:
    """
    Make a prediction for a package using token statistics.

    Parameters:
    - model_payload: Dictionary containing model, feature_names, label_encoder
    - token_stats: Dictionary from calculate_token_stats() function

    Returns:
    - Dictionary with prediction and confidence
    """
    model = model_payload["model"]
    feature_names = model_payload["feature_names"]
    label_encoder = model_payload["label_encoder"]

    # Extract features in the correct order
    feature_vector = []
    for feature_name in feature_names:
        feature_vector.append(token_stats.get(feature_name, 0))

    feature_vector = np.array(feature_vector).reshape(1, -1)

    # Make prediction
    prediction = model.predict(feature_vector)[0]
    probabilities = model.predict_proba(feature_vector)[0]
    predicted_label = label_encoder.inverse_transform([prediction])[0]

    return {
        "predicted_label": predicted_label,
        "confidence": max(probabilities),
        "malicious": predicted_label == "malicious",
    }


def main():
    """Example usage of the prediction function."""
    parser = argparse.ArgumentParser(
        description="Make predictions using trained SVM model"
    )
    parser.add_argument("--svm", "-s", required=True, help="Path to the SVM model")
    parser.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Tokenizer path",
        default=None,
    )
    parser.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="DistilBert model path",
        default=None,
    )
    parser.add_argument(
        "path",
        help="Path to be scanned for prediction",
    )

    args = parser.parse_args()

    # Load model
    model_payload = load_model(args.svm)

    try:
        MalwiObject.load_models_into_memory(
            model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
    except Exception as e:
        if not args.quiet:
            print(
                f"Warning: Could not initialize ML models: {e}. "
                "Maliciousness prediction will be disabled."
            )

    result = process_files(
        input_path=Path(args.path),
        accepted_extensions=["py"],
        predict=True,
        retrieve_source_code=True,
        malicious_only=True,
    )

    token_stats = MalwiObject.collect_token_stats(result.malwi_objects)

    prediction = predict(model_payload, token_stats)

    print(f"- {len(result.all_files)} files scanned")
    print(f"- {len(result.skipped_files)} files skipped")
    if prediction["malicious"]:
        print(f"- {len(result.malwi_objects)} malicious objects identified")
        print(f"=> 👹 malicious {prediction['confidence']:.2f}")
    else:
        print(f"- {len(result.malwi_objects)} malicious objects identified")
        print(f"=> 🟢 not malicious {prediction['confidence']:.2f}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("👋")
