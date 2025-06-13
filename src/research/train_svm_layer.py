import pickle
import argparse
import json

import numpy as np
import pandas as pd
from sklearn.svm import SVC
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_score,
    recall_score,
    f1_score,
)


def load_and_prepare_data(benign_path, malicious_path):
    """
    Loads data from benign and/or malicious CSV files, handles duplicates,
    and combines them into a single DataFrame.
    """
    benign_df = None
    malicious_df = None

    # Load benign data if path is provided
    if benign_path:
        try:
            benign_df = pd.read_csv(benign_path)
            print(f"Loaded {len(benign_df)} rows from benign file: {benign_path}")
        except FileNotFoundError:
            print(f"Error: Benign file not found at '{benign_path}'")
            return None

    # Load malicious data if path is provided
    if malicious_path:
        try:
            malicious_df = pd.read_csv(malicious_path)
            print(
                f"Loaded {len(malicious_df)} rows from malicious file: {malicious_path}"
            )
        except FileNotFoundError:
            print(f"Error: Malicious file not found at '{malicious_path}'")
            return None

    # Handle duplicates: if a package is in both, keep the benign one
    if benign_df is not None and malicious_df is not None:
        benign_packages = set(benign_df["package"])
        original_malicious_count = len(malicious_df)
        # Keep malicious rows only if their package is NOT in the benign set
        malicious_df = malicious_df[~malicious_df["package"].isin(benign_packages)]
        removed_count = original_malicious_count - len(malicious_df)
        if removed_count > 0:
            print(
                f"Removed {removed_count} duplicate packages from the malicious dataset."
            )

    # Combine the dataframes
    combined_df = pd.concat([benign_df, malicious_df], ignore_index=True, join="outer")

    # Fill any missing feature counts with 0
    feature_cols = combined_df.columns.drop(["package", "label"])
    combined_df[feature_cols] = combined_df[feature_cols].fillna(0)

    print(f"Combined dataset has {len(combined_df)} total rows.")
    return combined_df


def apply_feature_weights(df, feature_weights, feature_names):
    """
    Apply weights to features using pandas operations.

    Parameters:
    - df: pandas DataFrame with features
    - feature_weights: dict mapping feature names to weights, or list of weights
    - feature_names: list of feature column names

    Returns:
    - weighted_df: DataFrame with weighted features
    """
    weighted_df = df.copy()

    if isinstance(feature_weights, dict):
        # Dictionary approach - apply weights by name
        applied_weights = {}
        for feature_name in feature_names:
            if feature_name in feature_weights:
                weight = feature_weights[feature_name]
                weighted_df[feature_name] = weighted_df[feature_name] * weight
                applied_weights[feature_name] = weight
            else:
                applied_weights[feature_name] = 1.0  # Default weight

        print(f"Applied feature weights: {applied_weights}")

    elif isinstance(feature_weights, (list, np.ndarray)):
        # List approach - apply weights by position
        if len(feature_weights) != len(feature_names):
            raise ValueError(
                f"Number of weights ({len(feature_weights)}) must match "
                f"number of features ({len(feature_names)})"
            )

        applied_weights = {}
        for i, feature_name in enumerate(feature_names):
            weight = feature_weights[i]
            weighted_df[feature_name] = weighted_df[feature_name] * weight
            applied_weights[feature_name] = weight

        print(f"Applied feature weights: {applied_weights}")

    else:
        raise ValueError("feature_weights must be a dict or list/array")

    return weighted_df


def create_features_and_labels(
    df,
    allowed_features=None,
    feature_weights=None,
    scale_features=True,
):
    """
    Takes a combined dataframe and prepares the feature matrix (X),
    label vector (y), and other metadata for training.

    Parameters:
    - df: pandas DataFrame
    - allowed_features: list of column names to allow as features (optional)
    - feature_weights: dict or list of feature weights (optional)
    - scale_features: bool, whether to apply standard scaling (default: True)

    Returns:
    - X_features: feature matrix (numpy array)
    - y_encoded: encoded labels
    - feature_names: list of feature column names
    - le: fitted LabelEncoder
    - scaler: fitted StandardScaler (if scale_features=True)
    """
    if "label" not in df.columns:
        print(
            "Error: The combined CSV data must contain a 'label' column for classification ('benign'/'malicious')."
        )
        return None, None, None, None, None

    if "package" not in df.columns:
        print(
            "Error: Combined CSV data must contain a 'package' column to be used as an identifier."
        )
        return None, None, None, None, None

    y_labels = df["label"]

    # Determine which features to keep
    if allowed_features is not None:
        missing = [col for col in allowed_features if col not in df.columns]
        if missing:
            print(
                f"Warning: Some allowed feature columns are missing in the data: {missing}"
            )
        selected_columns = [col for col in allowed_features if col in df.columns]
        X_features_df = df[selected_columns]
    else:
        # Default behavior: drop 'label' and 'package'
        X_features_df = df.drop(["package", "label"], axis=1)

    feature_names = X_features_df.columns.tolist()
    print(f"Using {len(feature_names)} feature columns: {feature_names}")

    # Apply feature weights if provided
    if feature_weights is not None:
        print("\nApplying feature weights...")
        X_features_df = apply_feature_weights(
            X_features_df, feature_weights, feature_names
        )

    # Apply scaling if requested
    scaler = None
    if scale_features:
        print("Applying standard scaling to features...")
        scaler = StandardScaler()
        X_features_scaled = scaler.fit_transform(X_features_df)
        # Convert back to DataFrame to maintain pandas operations
        X_features_df = pd.DataFrame(
            X_features_scaled, columns=feature_names, index=X_features_df.index
        )
        print("Standard scaling applied.")

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y_labels)

    print(f"Encoded {len(le.classes_)} unique labels: {list(le.classes_)}")

    return X_features_df.values, y_encoded, feature_names, le, scaler


def load_feature_weights(weights_file):
    """
    Load feature weights from a JSON file.

    Parameters:
    - weights_file: path to JSON file containing feature weights

    Returns:
    - feature_weights: dict of feature name -> weight
    """
    try:
        with open(weights_file, "r") as f:
            weights = json.load(f)
        print(f"Loaded feature weights from {weights_file}")
        return weights
    except FileNotFoundError:
        print(f"Warning: Feature weights file not found at '{weights_file}'")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in feature weights file '{weights_file}'")
        return None


def main():
    """Main function to parse arguments and run the training pipeline."""
    parser = argparse.ArgumentParser(
        description="CLI for training an SVM model from benign and malicious CSV files.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--benign",
        "-b",
        metavar="BENIGN_CSV_PATH",
        type=str,
        help="Path to the benign CSV file.",
    )
    parser.add_argument(
        "--malicious",
        "-m",
        metavar="MALICIOUS_CSV_PATH",
        type=str,
        help="Path to the malicious CSV file. Duplicates common with the benign file will be REMOVED.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="svm_layer.pkl",
        help="Path to save the trained SVM model (e.g., 'svm_model.pkl').",
    )

    # --- Feature weighting arguments ---
    parser.add_argument(
        "--feature-weights",
        "-w",
        type=str,
        help="Path to JSON file containing feature weights (e.g., {'feature1': 2.0, 'feature2': 0.5})",
    )
    parser.add_argument(
        "--no-scaling",
        action="store_true",
        help="Disable standard scaling of features (not recommended for SVM).",
    )

    # --- Arguments for model tuning ---
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Proportion of the dataset for the test split (default: 0.25).",
    )
    parser.add_argument(
        "--kernel",
        type=str,
        default="rbf",
        choices=["linear", "poly", "rbf", "sigmoid"],
        help="SVM kernel type (default: 'rbf').",
    )
    parser.add_argument(
        "--C",
        type=float,
        default=1.0,
        help="Regularization parameter C (default: 1.0).",
    )
    parser.add_argument(
        "--gamma",
        type=str,
        default="scale",
        help="Kernel coefficient gamma (default: 'scale').",
    )

    args = parser.parse_args()

    if not args.benign and not args.malicious:
        parser.error(
            "At least one of --benign or --malicious input files must be provided."
        )

    # --- Load feature weights if provided ---
    feature_weights = None
    if args.feature_weights:
        feature_weights = load_feature_weights(args.feature_weights)
    else:
        # Default: Give higher weight to NETWORKING feature
        feature_weights = {
            "NETWORKING": 3.0,
            "NETWORK_HTTP_REQUEST": 3.0,
            "NETWORK_FILE_DOWNLOAD": 3.0,
        }

    # --- 1. Prepare Dataset ---
    print("Step 1: Loading and preparing dataset from CSV files...")
    combined_data = load_and_prepare_data(args.benign, args.malicious)

    if combined_data is None or combined_data.empty:
        print("Halting due to data loading errors or no data found.")
        return

    # --- 2. Create Features and Labels with Weighting ---
    print("\nStep 2: Creating features and labels with optional weighting...")
    X, y, feature_names, label_encoder, scaler = create_features_and_labels(
        combined_data,
        feature_weights=feature_weights,
        scale_features=not args.no_scaling,
    )

    if X is None:
        print("Halting due to feature creation errors.")
        return

    # --- 3. Split Data ---
    print(f"\nStep 3: Splitting data (Test size: {args.test_size})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )
    print(f"Training set: {len(X_train)} samples | Testing set: {len(X_test)} samples")

    # --- 4. Train SVM Model ---
    print("\nStep 4: Training the SVM model...")
    gamma_value = (
        float(args.gamma) if args.gamma.replace(".", "", 1).isdigit() else args.gamma
    )
    model = SVC(
        kernel=args.kernel,
        C=args.C,
        gamma=gamma_value,
        probability=True,
        class_weight="balanced",
    )
    print(f"Model parameters: kernel={args.kernel}, C={args.C}, gamma={gamma_value}")
    model.fit(X_train, y_train)
    print("Training complete.")

    # --- 5. Evaluate Model ---
    print("\nStep 5: Evaluating the model...")
    y_pred = model.predict(X_test)

    # --- Overall Performance Metrics ---
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print("\n--- Overall Model Performance ---")
    print(f"Accuracy:           {accuracy * 100:.2f}%")
    print(f"Weighted Precision: {precision:.2f}")
    print(f"Weighted Recall:    {recall:.2f}")
    print(f"Weighted F1-Score:  {f1:.2f}")

    # --- Detailed Per-Class Report ---
    print("\n--- Detailed Classification Report ---")
    try:
        report = classification_report(
            y_test, y_pred, target_names=label_encoder.classes_, zero_division=0
        )
        print(report)
    except ValueError:
        print(
            "Could not generate classification report. Some classes in the test set may have no predicted samples."
        )

    # --- 6. Save Model using Pickle ---
    print(f"\nStep 6: Saving model and metadata to '{args.output}' using pickle...")
    model_payload = {
        "model": model,
        "feature_names": feature_names,
        "label_encoder": label_encoder,
        "scaler": scaler,
        "feature_weights": feature_weights,
    }

    with open(args.output, "wb") as f:
        pickle.dump(model_payload, f)

    print("Model saved successfully.")
    print(
        "Saved components: model, feature_names, label_encoder, scaler, feature_weights"
    )
    print("\nWarning: Only load .pkl files from sources you trust.")


if __name__ == "__main__":
    main()
