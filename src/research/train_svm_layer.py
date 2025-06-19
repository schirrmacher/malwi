import os
import time
import pickle
import argparse
import numpy as np

import pandas as pd
from sklearn.svm import SVC
from datetime import datetime
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, GridSearchCV, StratifiedKFold
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_score,
    recall_score,
    f1_score,
    make_scorer,
)
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
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
            success(f"Loaded {len(benign_df)} rows from benign file: {benign_path}")
        except FileNotFoundError:
            error(f"Benign file not found at '{benign_path}'")
            return None

    # Load malicious data if path is provided
    if malicious_path:
        try:
            malicious_df = pd.read_csv(malicious_path)
            success(
                f"Loaded {len(malicious_df)} rows from malicious file: {malicious_path}"
            )
        except FileNotFoundError:
            error(f"Malicious file not found at '{malicious_path}'")
            return None

    # Handle duplicates: if a package is in both, keep the benign one
    if benign_df is not None and malicious_df is not None:
        benign_packages = set(benign_df["package"])
        original_malicious_count = len(malicious_df)
        # Keep malicious rows only if their package is NOT in the benign set
        malicious_df = malicious_df[~malicious_df["package"].isin(benign_packages)]
        removed_count = original_malicious_count - len(malicious_df)
        if removed_count > 0:
            info(
                f"Removed {removed_count} duplicate packages from the malicious dataset."
            )

    # Combine the dataframes
    combined_df = pd.concat([benign_df, malicious_df], ignore_index=True, join="outer")

    # Fill any missing feature counts with 0
    feature_cols = combined_df.columns.drop(["package", "label"])
    combined_df[feature_cols] = combined_df[feature_cols].fillna(0)

    success(f"Combined dataset has {len(combined_df)} total rows.")
    return combined_df


def clean_and_convert_features(df):
    """
    Clean feature columns by converting string values to numeric.

    Parameters:
    - df: pandas DataFrame with potentially mixed-type feature columns

    Returns:
    - cleaned_df: DataFrame with all feature columns as numeric
    """
    cleaned_df = df.copy()

    for col in cleaned_df.columns:
        # Convert the column to string first, then handle special cases
        col_series = cleaned_df[col].astype(str)

        # Handle common string patterns that should be numeric
        # Replace 's' suffix (like '0s' -> '0')
        col_series = col_series.str.replace("s$", "", regex=True)

        # Handle other common patterns if needed
        # col_series = col_series.str.replace('ms$', '', regex=True)  # milliseconds
        # col_series = col_series.str.replace('%$', '', regex=True)   # percentages

        # Try to convert to numeric, replacing any remaining non-numeric with 0
        cleaned_df[col] = pd.to_numeric(col_series, errors="coerce").fillna(0)

    return cleaned_df


def select_best_features(X, y, feature_names, k=None, method="mutual_info"):
    """
    Select the k best features using statistical tests.

    Parameters:
    - X: feature matrix
    - y: target labels
    - feature_names: list of feature names
    - k: number of features to select (if None, use all features)
    - method: 'f_classif', 'mutual_info', or 'random_forest'

    Returns:
    - X_selected: selected features
    - selected_feature_names: names of selected features
    - selector: fitted selector object
    """
    if k is None or k >= len(feature_names):
        info(f"Using all {len(feature_names)} features (no selection)")
        return X, feature_names, None

    progress(f"Selecting {k} best features using {method}...")

    if method == "f_classif":
        selector = SelectKBest(score_func=f_classif, k=k)
    elif method == "mutual_info":
        selector = SelectKBest(score_func=mutual_info_classif, k=k)
    elif method == "random_forest":
        # Use RandomForest feature importance for selection
        rf = RandomForestClassifier(n_estimators=100, random_state=42)
        rf.fit(X, y)
        importances = rf.feature_importances_
        indices = np.argsort(importances)[::-1][:k]
        X_selected = X[:, indices]
        selected_feature_names = [feature_names[i] for i in indices]
        info(f"Selected features: {selected_feature_names}")
        return X_selected, selected_feature_names, indices
    else:
        error(f"Unknown feature selection method: {method}")
        return X, feature_names, None

    X_selected = selector.fit_transform(X, y)
    selected_indices = selector.get_support(indices=True)
    selected_feature_names = [feature_names[i] for i in selected_indices]

    info(f"Selected {len(selected_feature_names)} features: {selected_feature_names}")
    return X_selected, selected_feature_names, selector


def optimize_hyperparameters(X_train, y_train, kernel="rbf", cv_folds=5):
    """
    Perform grid search to find optimal hyperparameters.

    Parameters:
    - X_train: training features
    - y_train: training labels
    - kernel: SVM kernel type
    - cv_folds: number of cross-validation folds

    Returns:
    - best_params: dictionary of best parameters
    - best_score: best cross-validation F1 score
    """
    progress(f"Optimizing hyperparameters with {cv_folds}-fold cross-validation...")

    # Define parameter grids for different kernels
    if kernel == "rbf":
        param_grid = {
            "C": [0.1, 1, 10, 100],
            "gamma": ["scale", "auto", 0.001, 0.01, 0.1, 1.0],
        }
    elif kernel == "linear":
        param_grid = {"C": [0.1, 1, 10, 100]}
    elif kernel == "poly":
        param_grid = {
            "C": [0.1, 1, 10, 100],
            "gamma": ["scale", "auto", 0.001, 0.01, 0.1],
            "degree": [2, 3, 4],
        }
    else:
        param_grid = {"C": [0.1, 1, 10, 100]}

    # Use F1 score as the optimization metric
    f1_scorer = make_scorer(f1_score, average="weighted")

    svm = SVC(kernel=kernel, probability=True, random_state=42)

    grid_search = GridSearchCV(
        svm,
        param_grid,
        cv=StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42),
        scoring=f1_scorer,
        n_jobs=-1,
        verbose=1,
    )

    grid_search.fit(X_train, y_train)

    info(f"Best parameters: {grid_search.best_params_}")
    info(f"Best cross-validation F1 score: {grid_search.best_score_:.4f}")

    return grid_search.best_params_, grid_search.best_score_


def create_features_and_labels(
    df,
    allowed_features=None,
):
    """
    Takes a combined dataframe and prepares the feature matrix (X),
    label vector (y), and other metadata for training.

    Parameters:
    - df: pandas DataFrame
    - allowed_features: list of column names to allow as features (optional)

    Returns:
    - X_features: feature matrix (numpy array)
    - y_encoded: encoded labels
    - feature_names: list of feature column names
    - le: fitted LabelEncoder
    - scaler: fitted StandardScaler
    """
    if "label" not in df.columns:
        error(
            "The combined CSV data must contain a 'label' column for classification ('benign'/'malicious')."
        )
        return None, None, None, None, None

    if "package" not in df.columns:
        error(
            "Combined CSV data must contain a 'package' column to be used as an identifier."
        )
        return None, None, None, None, None

    y_labels = df["label"]

    # Determine which features to keep
    if allowed_features is not None:
        missing = [col for col in allowed_features if col not in df.columns]
        if missing:
            warning(f"Some allowed feature columns are missing in the data: {missing}")
        selected_columns = [col for col in allowed_features if col in df.columns]
        X_features_df = df[selected_columns]
    else:
        # Default behavior: drop 'label' and 'package'
        X_features_df = df.drop(["package", "label"], axis=1)

    feature_names = X_features_df.columns.tolist()
    info(f"Using {len(feature_names)} feature columns: {feature_names}")

    # Clean and convert features to numeric before any processing
    progress("Cleaning and converting features to numeric...")
    X_features_df = clean_and_convert_features(X_features_df)

    # Apply standard scaling (always enabled now)
    progress("Applying standard scaling to features...")
    scaler = StandardScaler()
    X_features_scaled = scaler.fit_transform(X_features_df)
    # Convert back to DataFrame to maintain pandas operations
    X_features_df = pd.DataFrame(
        X_features_scaled, columns=feature_names, index=X_features_df.index
    )
    success("Standard scaling applied.")

    # Encode labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y_labels)

    info(f"Encoded {len(le.classes_)} unique labels: {list(le.classes_)}")

    return X_features_df.values, y_encoded, feature_names, le, scaler


def save_training_metrics(output_path, metrics_data):
    """Save training metrics summary to a file in the same directory as the model."""
    model_dir = os.path.dirname(output_path)
    metrics_filename = (
        os.path.splitext(os.path.basename(output_path))[0] + "_training_metrics.txt"
    )
    metrics_path = os.path.join(model_dir, metrics_filename)

    with open(metrics_path, "w") as f:
        f.write("Training Metrics Summary\n")
        f.write("=" * 40 + "\n")
        for key, value in metrics_data.items():
            if isinstance(value, float):
                f.write(f"{key}: {value:.4f}\n")
            else:
                f.write(f"{key}: {value}\n")
        f.write("=" * 40 + "\n")
        f.write("Training completed successfully\n")

    info(f"Training metrics saved to: {metrics_path}")


def main():
    """Main function to parse arguments and run the training pipeline."""
    # Record start time
    start_time = time.time()
    training_start_datetime = datetime.now()

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
        default="malwi_models/svm_layer.pkl",
        help="Path to save the trained SVM model (default: 'malwi_models/svm_layer.pkl').",
    )

    # --- Arguments for model tuning ---
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Proportion of the dataset for the test split (default: 0.2).",
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
    parser.add_argument(
        "--optimize",
        action="store_true",
        help="Enable hyperparameter optimization using grid search.",
    )
    parser.add_argument(
        "--feature-selection",
        type=str,
        choices=["f_classif", "mutual_info", "random_forest"],
        help="Enable feature selection using the specified method.",
    )
    parser.add_argument(
        "--k-features",
        type=int,
        help="Number of best features to select (requires --feature-selection).",
    )
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        help="Number of cross-validation folds for hyperparameter optimization (default: 5).",
    )

    args = parser.parse_args()

    # Configure messaging system
    configure_messaging(quiet=False)

    if not args.benign and not args.malicious:
        parser.error(
            "At least one of --benign or --malicious input files must be provided."
        )

    # --- 1. Prepare Dataset ---
    progress("Step 1: Loading and preparing dataset from CSV files...")
    combined_data = load_and_prepare_data(args.benign, args.malicious)

    if combined_data is None or combined_data.empty:
        error("Halting due to data loading errors or no data found.")
        return

    # --- 2. Create Features and Labels ---
    progress("Step 2: Creating features and labels...")
    X, y, feature_names, label_encoder, scaler = create_features_and_labels(
        combined_data,
    )

    if X is None:
        error("Halting due to feature creation errors.")
        return

    # --- 3. Feature Selection (Optional) ---
    feature_selector = None
    if args.feature_selection:
        progress(f"Step 3: Feature selection using {args.feature_selection}...")
        X, feature_names, feature_selector = select_best_features(
            X, y, feature_names, k=args.k_features, method=args.feature_selection
        )
        info(f"Features reduced from {len(feature_names)} to {X.shape[1]}")

    # --- 4. Split Data ---
    step_num = 4 if args.feature_selection else 3
    progress(f"Step {step_num}: Splitting data (test size: {args.test_size})...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )
    info(f"Training set: {len(X_train)} samples | Testing set: {len(X_test)} samples")

    # --- 5. Hyperparameter Optimization (Optional) ---
    best_params = None
    step_num += 1
    if args.optimize:
        progress(f"Step {step_num}: Hyperparameter optimization...")
        best_params, best_cv_score = optimize_hyperparameters(
            X_train, y_train, kernel=args.kernel, cv_folds=args.cv_folds
        )
        step_num += 1

    # --- 6. Train SVM Model ---
    progress(f"Step {step_num}: Training SVM model...")

    if best_params:
        # Use optimized parameters
        model = SVC(
            kernel=args.kernel, probability=True, random_state=42, **best_params
        )
        info(f"Using optimized parameters: {best_params}")
    else:
        # Use provided or default parameters
        gamma_value = (
            float(args.gamma)
            if args.gamma.replace(".", "", 1).isdigit()
            else args.gamma
        )
        model = SVC(
            kernel=args.kernel,
            C=args.C,
            gamma=gamma_value,
            probability=True,
            random_state=100,
        )
        info(f"Model parameters: kernel={args.kernel}, C={args.C}, gamma={gamma_value}")

    model.fit(X_train, y_train)
    success("SVM model training completed")

    # --- Evaluate Model ---
    step_num += 1
    progress(f"Step {step_num}: Evaluating model performance...")
    y_pred = model.predict(X_test)

    # --- Overall Performance Metrics ---
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    info("--- Overall Model Performance ---")
    info(f"Accuracy:           {accuracy * 100:.2f}%")
    info(f"Weighted Precision: {precision:.2f}")
    info(f"Weighted Recall:    {recall:.2f}")
    info(f"Weighted F1-Score:  {f1:.2f}")

    # --- Detailed Per-Class Report ---
    info("--- Detailed Classification Report ---")
    try:
        report = classification_report(
            y_test, y_pred, target_names=label_encoder.classes_, zero_division=0
        )
        info(report)
    except ValueError:
        warning(
            "Could not generate classification report. Some classes in the test set may have no predicted samples."
        )

    # --- Save Model using Pickle ---
    step_num += 1
    progress(f"Step {step_num}: Saving model to '{args.output}'...")

    # Create directory if it doesn't exist
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        success(f"Created directory: {output_dir}")

    model_payload = {
        "model": model,
        "feature_names": feature_names,
        "label_encoder": label_encoder,
        "scaler": scaler,
        "feature_selector": feature_selector,  # Include feature selector if used
        "optimization_params": best_params,  # Include optimized parameters if used
    }

    with open(args.output, "wb") as f:
        pickle.dump(model_payload, f)

    success("Model saved successfully.")
    info("Saved components: model, feature_names, label_encoder, scaler")
    warning("Only load .pkl files from trusted sources")

    # --- 7. Save Training Metrics Summary ---
    end_time = time.time()
    training_duration = end_time - start_time

    metrics_data = {
        "training_start_time": training_start_datetime.strftime("%Y-%m-%d %H:%M:%S"),
        "training_duration_seconds": training_duration,
        "training_duration_minutes": training_duration / 60,
        "total_samples": len(combined_data),
        "training_samples": len(X_train),
        "test_samples": len(X_test),
        "num_features": len(feature_names),
        "kernel": args.kernel,
        "C_parameter": best_params.get("C", args.C) if best_params else args.C,
        "gamma_parameter": (
            str(best_params.get("gamma", args.gamma))
            if best_params
            else str(args.gamma)
        ),
        "test_size_ratio": args.test_size,
        "accuracy": accuracy,
        "weighted_precision": precision,
        "weighted_recall": recall,
        "weighted_f1_score": f1,
        "label_classes": list(label_encoder.classes_),
        "model_output_path": args.output,
    }

    save_training_metrics(args.output, metrics_data)


if __name__ == "__main__":
    main()
