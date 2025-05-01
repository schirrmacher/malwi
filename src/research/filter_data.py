import argparse
import pandas as pd
import os


def process_csv_files(file_path1, file_path2):
    """
    Processes two CSV files to remove intra-file duplicates by hash
    and then inter-file common rows by hash.

    Args:
        file_path1 (str): Path to the first CSV file.
        file_path2 (str): Path to the second CSV file.
    """
    try:
        # Read the CSV files
        print(f"Reading CSV file: {file_path1}")
        df1 = pd.read_csv(file_path1)
        print(f"Successfully read {file_path1}. Shape: {df1.shape}")

        print(f"\nReading CSV file: {file_path2}")
        df2 = pd.read_csv(file_path2)
        print(f"Successfully read {file_path2}. Shape: {df2.shape}")

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
    print(f"\nProcessing {file_path1} for internal duplicates...")
    initial_rows_df1 = len(df1)
    df1_deduplicated = df1.drop_duplicates(subset=["hash"], keep="first")
    deduplicated_rows_df1 = initial_rows_df1 - len(df1_deduplicated)
    print(
        f"Removed {deduplicated_rows_df1} duplicate rows from {file_path1} (based on 'hash')."
    )
    print(
        f"Shape of {os.path.basename(file_path1)} after deduplication: {df1_deduplicated.shape}"
    )

    print(f"\nProcessing {file_path2} for internal duplicates...")
    initial_rows_df2 = len(df2)
    df2_deduplicated = df2.drop_duplicates(subset=["hash"], keep="first")
    deduplicated_rows_df2 = initial_rows_df2 - len(df2_deduplicated)
    print(
        f"Removed {deduplicated_rows_df2} duplicate rows from {file_path2} (based on 'hash')."
    )
    print(
        f"Shape of {os.path.basename(file_path2)} after deduplication: {df2_deduplicated.shape}"
    )

    # --- Step 2: Identify and remove rows with common hashes between the two files ---
    print("\nIdentifying common hashes between the two files...")
    hashes_df1 = set(df1_deduplicated["hash"])
    hashes_df2 = set(df2_deduplicated["hash"])

    common_hashes = hashes_df1.intersection(hashes_df2)
    print(f"Found {len(common_hashes)} common hashes between the two files.")

    if common_hashes:
        # Remove common rows from df1_deduplicated
        df1_final = df1_deduplicated[~df1_deduplicated["hash"].isin(common_hashes)]
        removed_common_from_df1 = len(df1_deduplicated) - len(df1_final)
        print(
            f"Removed {removed_common_from_df1} rows from {os.path.basename(file_path1)} that had hashes common with {os.path.basename(file_path2)}."
        )

        # Remove common rows from df2_deduplicated
        df2_final = df2_deduplicated[~df2_deduplicated["hash"].isin(common_hashes)]
        removed_common_from_df2 = len(df2_deduplicated) - len(df2_final)
        print(
            f"Removed {removed_common_from_df2} rows from {os.path.basename(file_path2)} that had hashes common with {os.path.basename(file_path1)}."
        )
    else:
        print(
            "No common hashes found. Files will only have internal duplicates removed."
        )
        df1_final = df1_deduplicated
        df2_final = df2_deduplicated

    print(f"\nFinal shape of {os.path.basename(file_path1)} data: {df1_final.shape}")
    print(f"Final shape of {os.path.basename(file_path2)} data: {df2_final.shape}")

    # --- Step 3: Save the processed DataFrames to new CSV files ---
    base1, ext1 = os.path.splitext(file_path1)
    output_path1 = f"{base1}_processed{ext1}"

    base2, ext2 = os.path.splitext(file_path2)
    output_path2 = f"{base2}_processed{ext2}"

    try:
        print(
            f"\nSaving processed data for {os.path.basename(file_path1)} to: {output_path1}"
        )
        df1_final.to_csv(output_path1, index=False)
        print(f"Successfully saved {output_path1}")

        print(
            f"\nSaving processed data for {os.path.basename(file_path2)} to: {output_path2}"
        )
        df2_final.to_csv(output_path2, index=False)
        print(f"Successfully saved {output_path2}")

    except Exception as e:
        print(f"An error occurred while saving the processed files: {e}")


if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Process two CSV files to remove duplicates and common rows based on the 'hash' column."
    )
    parser.add_argument(
        "file1",
        metavar="FILE1_PATH",
        type=str,
        help="Path to the first input CSV file.",
    )
    parser.add_argument(
        "file2",
        metavar="FILE2_PATH",
        type=str,
        help="Path to the second input CSV file.",
    )

    # Parse arguments
    args = parser.parse_args()

    # Call the processing function
    process_csv_files(args.file1, args.file2)
