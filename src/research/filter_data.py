import argparse
import pandas as pd
import os


def process_csv_files(benign, malicious):
    """
    Processes two CSV files, assumed to be a benign set (file_path1_benign)
    and a malicious set (file_path2_malicious).
    1. Removes intra-file duplicates (based on 'hash') from both files.
    2. Identifies rows with common 'hash' values between the two files.
    3. Removes these common rows ONLY from the malicious set (file_path2_malicious).
       Rows in the benign set (file_path1_benign) that have hashes common
       with the malicious set are KEPT.

    Args:
        file_path1_benign (str): Path to the CSV file considered the 'benign' set.
        file_path2_malicious (str): Path to the CSV file considered the 'malicious' set.
    """
    try:
        # Read the CSV files
        print(f"Reading BENIGN CSV file: {benign}")
        df1_benign = pd.read_csv(benign)
        print(f"Successfully read {benign}. Shape: {df1_benign.shape}")

        print(f"\nReading MALICIOUS CSV file: {malicious}")
        df2_malicious = pd.read_csv(malicious)
        print(f"Successfully read {malicious}. Shape: {df2_malicious.shape}")

    except FileNotFoundError as e:
        print(f"Error: File not found. {e}")
        return
    except pd.errors.EmptyDataError as e:
        print(f"Error: File is empty. {e}")
        return
    except Exception as e:
        print(f"An error occurred while reading the files: {e}")
        return

    # --- Step 1: Remove duplicates within each file based on 'hash' ---
    print(f"\nProcessing {benign} (benign) for internal duplicates...")
    initial_rows_df1 = len(df1_benign)
    df1_benign_deduplicated = df1_benign.drop_duplicates(subset=["hash"], keep="first")
    deduplicated_rows_df1 = initial_rows_df1 - len(df1_benign_deduplicated)
    print(
        f"Removed {deduplicated_rows_df1} duplicate rows from {benign} (based on 'hash')."
    )
    print(
        f"Shape of {os.path.basename(benign)} after internal deduplication: {df1_benign_deduplicated.shape}"
    )

    print(f"\nProcessing {malicious} (malicious) for internal duplicates...")
    initial_rows_df2 = len(df2_malicious)
    df2_malicious_deduplicated = df2_malicious.drop_duplicates(
        subset=["hash"], keep="first"
    )
    deduplicated_rows_df2 = initial_rows_df2 - len(df2_malicious_deduplicated)
    print(
        f"Removed {deduplicated_rows_df2} duplicate rows from {malicious} (based on 'hash')."
    )
    print(
        f"Shape of {os.path.basename(malicious)} after internal deduplication: {df2_malicious_deduplicated.shape}"
    )

    # --- Step 2: Identify common hashes and process according to benign/malicious sets ---
    print("\nIdentifying common hashes between the benign and malicious sets...")
    hashes_benign = set(df1_benign_deduplicated["hash"])
    hashes_malicious = set(df2_malicious_deduplicated["hash"])

    common_hashes = hashes_benign.intersection(hashes_malicious)
    print(f"Found {len(common_hashes)} common hashes between the two sets.")

    # Process benign set (df1_benign_deduplicated): Keep all rows after intra-file deduplication.
    # Common hashes with the malicious set are NOT removed from the benign set.
    df1_benign_final = df1_benign_deduplicated
    print(
        f"The benign set ({os.path.basename(benign)}) retains all {len(df1_benign_final)} rows after its internal deduplication."
    )
    if common_hashes:
        print(
            f"This includes {len(df1_benign_final[df1_benign_final['hash'].isin(common_hashes)])} rows with hashes also found in the malicious set (before its inter-file deduplication)."
        )

    # Process malicious set (df2_malicious_deduplicated): Remove rows with hashes common to the benign set.
    if common_hashes:
        df2_malicious_final = df2_malicious_deduplicated[
            ~df2_malicious_deduplicated["hash"].isin(common_hashes)
        ]
        removed_common_from_malicious = len(df2_malicious_deduplicated) - len(
            df2_malicious_final
        )
        print(
            f"Removed {removed_common_from_malicious} rows from the malicious set ({os.path.basename(malicious)}) that had hashes common with the benign set."
        )
    else:
        # If no common hashes, the malicious set is also just its internally deduplicated version.
        df2_malicious_final = df2_malicious_deduplicated
        print(
            f"No common hashes found. The malicious set ({os.path.basename(malicious)}) remains unchanged by inter-file comparison (it only underwent internal deduplication)."
        )

    print(
        f"\nFinal shape of {os.path.basename(benign)} (benign) data: {df1_benign_final.shape}"
    )
    print(
        f"Final shape of {os.path.basename(malicious)} (malicious) data: {df2_malicious_final.shape}"
    )

    # --- Step 3: Save the processed DataFrames to new CSV files ---
    base1, ext1 = os.path.splitext(benign)
    output_path1 = f"{base1}_processed{ext1}"

    base2, ext2 = os.path.splitext(malicious)
    output_path2 = f"{base2}_processed{ext2}"

    try:
        print(
            f"\nSaving processed data for {os.path.basename(benign)} (benign) to: {output_path1}"
        )
        df1_benign_final.to_csv(output_path1, index=False)
        print(f"Successfully saved {output_path1}")

        print(
            f"\nSaving processed data for {os.path.basename(malicious)} (malicious) to: {output_path2}"
        )
        df2_malicious_final.to_csv(output_path2, index=False)
        print(f"Successfully saved {output_path2}")

    except Exception as e:
        print(f"An error occurred while saving the processed files: {e}")


if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Processes two CSV files (benign and malicious). Removes intra-file duplicates from both. Removes inter-file duplicates (common hashes) ONLY from the malicious file, keeping them in the benign file."
    )
    parser.add_argument(
        "--benign",
        "-b",
        metavar="BENIGN_CSV_PATH",
        type=str,
        help="Path to the benign CSV file. Duplicates common with the malicious file will be KEPT in this file.",
    )
    parser.add_argument(
        "--malicious",
        "-m",
        metavar="MALICIOUS_CSV_PATH",
        type=str,
        help="Path to the malicious CSV file. Duplicates common with the benign file will be REMOVED from this file.",
    )

    # Parse arguments
    args = parser.parse_args()

    # Call the processing function
    process_csv_files(benign=args.benign, malicious=args.malicious)
