import pickle
import argparse

import pandas as pd
from sklearn.svm import SVC
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


def load_and_prepare_data(benign_path, malicious_path):
    """
    Loads data from benign and/or malicious CSV files, handles duplicates,
    and combines them into a single DataFrame.

    Args:
        benign_path (str): Path to the benign CSV file.
        malicious_path (str): Path to the malicious CSV file.

    Returns:
        pandas.DataFrame: A single DataFrame containing the combined and cleaned data,
                          or None if loading fails.
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
    # This handles cases where one file has columns the other doesn't
    feature_cols = combined_df.columns.drop("package")
    combined_df[feature_cols] = combined_df[feature_cols].fillna(0)

    print(f"Combined dataset has {len(combined_df)} total rows.")
    return combined_df


def create_features_and_labels(df):
    """
    Takes a combined dataframe and prepares the feature matrix (X),
    label vector (y), and other metadata for training.
    """
    if "package" not in df.columns:
        print("Error: Combined CSV data must contain a 'package' column.")
        return None, None, None, None

    # Drop the 'label' column if it exists from the source CSVs, as it's not a feature
    if "label" in df.columns:
        df = df.drop("label", axis=1)

    y_labels = df["package"]
    X_features = df.drop("package", axis=1)
    feature_names = X_features.columns.tolist()

    print(f"Found {len(feature_names)} feature columns for the model.")

    le = LabelEncoder()
    y_encoded = le.fit_transform(y_labels)

    print(f"Encoded {len(le.classes_)} unique package labels.")

    return X_features.values, y_encoded, feature_names, le


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

    # --- 1. Prepare Dataset ---
    print("Step 1: Loading and preparing dataset from CSV files...")
    combined_data = load_and_prepare_data(args.benign, args.malicious)

    if combined_data is None or combined_data.empty:
        print("Halting due to data loading errors or no data found.")
        return

    X, y, feature_names, label_encoder = create_features_and_labels(combined_data)

    if X is None:
        print("Halting due to feature creation errors.")
        return

    # --- 2. Split Data (with error handling) ---
    print(f"\nStep 2: Splitting data (Test size: {args.test_size})...")
    try:
        # Pre-emptively check for classes with only one sample
        label_counts = pd.Series(y).value_counts()
        single_sample_labels = label_counts[label_counts == 1].index

        if not single_sample_labels.empty:
            problem_packages = label_encoder.inverse_transform(single_sample_labels)
            print("\n❌ Error: Cannot split data for training.")
            print(
                "The following packages have only one sample and cannot be split into training and testing sets:"
            )
            for pkg in problem_packages:
                print(f"  - {pkg}")
            print(
                "\nPlease provide at least two samples for each package or remove the single-sample packages from your data."
            )
            return  # Exit gracefully

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=args.test_size, random_state=42, stratify=y
        )
        print(
            f"Training set: {len(X_train)} samples | Testing set: {len(X_test)} samples"
        )

    except ValueError as e:
        # Fallback for other potential splitting errors
        print(f"\n❌ An unexpected error occurred during data splitting: {e}")
        print("Please check the integrity and format of your dataset.")
        return

    # --- 3. Train SVM Model ---
    print("\nStep 3: Training the SVM model...")
    gamma_value = (
        float(args.gamma) if args.gamma.replace(".", "", 1).isdigit() else args.gamma
    )
    model = SVC(kernel=args.kernel, C=args.C, gamma=gamma_value, probability=True)
    print(f"Model parameters: kernel={args.kernel}, C={args.C}, gamma={gamma_value}")
    model.fit(X_train, y_train)
    print("Training complete.")

    # --- 4. Evaluate Model ---
    print("\nStep 4: Evaluating the model...")
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nModel Accuracy: {accuracy * 100:.2f}%\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    # --- 5. Save Model using Pickle ---
    print(f"\nStep 5: Saving model and metadata to '{args.output}' using pickle...")
    model_payload = {
        "model": model,
        "feature_names": feature_names,
        "label_encoder": label_encoder,
    }

    with open(args.output, "wb") as f:
        pickle.dump(model_payload, f)

    print("Model saved successfully.")
    print("\nWarning: Only load .pkl files from sources you trust.")


if __name__ == "__main__":
    main()
