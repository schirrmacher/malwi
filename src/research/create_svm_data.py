import csv
import argparse

from pathlib import Path

from research.disassemble_python import MalwiObject, process_files


def create_svm_data():
    """
    Main function to process directories, collect dynamic features,
    and save them to a CSV file.
    """
    parser = argparse.ArgumentParser(
        description="Process project directories to generate a dynamic feature CSV for SVM training."
    )
    parser.add_argument(
        "--dir",
        "-d",
        type=str,
        required=True,
        help="Path to the parent directory containing project subdirectories to scan.",
    )
    parser.add_argument(
        "--label",
        "-l",
        type=str,
        required=True,
        help="Label (e.g., 'malicious', 'benign') to assign to all processed packages.",
    )
    parser.add_argument(
        "--save",
        "-s",
        type=str,
        required=True,
        help="Path for the output CSV file (e.g., 'svm_data.csv').",
    )

    # Add arguments required by `process_files`
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=["py"],
        help="List of file extensions to process (e.g., .py .js).",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Maliciousness threshold for prediction (default: 0.5).",
    )

    parser.add_argument("--quiet", action="store_true", help="Run in silent mode.")

    args = parser.parse_args()

    parent_dir = Path(args.dir)
    if not parent_dir.is_dir():
        print(f"Error: Provided path '{parent_dir}' is not a valid directory.")
        return

    # --- Step 1: Process all directories and collect results in memory ---
    # We do this first to discover all possible feature columns before writing the CSV.
    all_package_data = []
    all_feature_keys = set()

    print(f"Scanning subdirectories in '{parent_dir}'...")
    subdirectories = [d for d in parent_dir.iterdir() if d.is_dir()]

    if not subdirectories:
        print(f"No subdirectories found in '{parent_dir}'. Exiting.")
        return

    for child_dir in subdirectories:
        package_name = child_dir.name
        print(f"\n--- Processing package: {package_name} ---")

        try:
            results = process_files(
                input_path=child_dir,
                accepted_extensions=args.extensions,
                predict=False,
                retrieve_source_code=False,
                silent=False,
                show_progress=True,
                malicious_only=False,
                malicious_threshold=args.threshold,
            )

            # This call creates the dictionary of features and their counts
            token_stats = MalwiObject.collect_token_stats(results.malwi_objects)

            if not token_stats:
                print(
                    f"Warning: No token statistics were generated for '{package_name}'. Skipping."
                )
                continue

            # Add the required identifiers for the CSV row
            token_stats["package"] = package_name
            token_stats["label"] = args.label

            all_package_data.append(token_stats)
            all_feature_keys.update(token_stats.keys())
            print(
                f"Finished processing '{package_name}'. Found {len(token_stats) - 2} unique features."
            )

        except Exception as e:
            print(f"An error occurred while processing directory '{package_name}': {e}")
            print("This package will be skipped.")

    # --- Step 2: Write the collected data to a CSV file ---
    if not all_package_data:
        print("\nAnalysis complete, but no data was successfully generated to save.")
        return

    print("\nConsolidating results and writing to CSV...")

    # Prepare the final header for the CSV file
    # We remove 'package' and 'label' as they are not features, then add them to the front.
    all_feature_keys.discard("package")
    all_feature_keys.discard("label")

    # Sort the feature keys alphabetically for consistent column order
    header = ["package", "label"] + sorted(list(all_feature_keys))

    try:
        with open(args.save, "w", newline="", encoding="utf-8") as f:
            # DictWriter is perfect for this task, as it handles missing keys automatically
            writer = csv.DictWriter(f, fieldnames=header)

            # Write the header row
            writer.writeheader()

            # Write all the data rows
            for row_data in all_package_data:
                # For any feature not present in a given package, DictWriter will write an empty cell
                writer.writerow(row_data)

        print(f"\n✅ Success! Analysis complete. Data saved to '{args.save}'")
        print(f"   - Processed {len(all_package_data)} packages.")
        print(f"   - Generated {len(header) - 2} unique feature columns.")

    except IOError as e:
        print(f"\nError: Could not write to file '{args.save}': {e}")


if __name__ == "__main__":
    create_svm_data()
