import os
import argparse
import pandas as pd

from typing import Dict, Optional
from research.disassemble_python import MalwiObject


def enrich_dataframe_with_triage(
    df: pd.DataFrame, triage_subfolder: str
) -> pd.DataFrame:
    rows = []

    # Load enrichment data from all triage files
    for filename in os.listdir(triage_subfolder):
        filepath = os.path.join(triage_subfolder, filename)
        try:
            objs = MalwiObject.from_file(filepath, language="python")
            print(f"Loaded {len(objs)} objects from {filepath}")
            for obj in objs:
                h = obj.to_string_hash()
                row = {
                    "hash": h,
                    "tokens": obj.to_token_string(),
                    "filepath": obj.file_path,
                    # Add any other relevant fields from obj here
                }
                rows.append(row)
        except Exception as e:
            print(f"Warning: Failed to process triage file {filepath}: {e}")
            continue

    # Create a DataFrame from the enrichment rows
    enrichment_df = pd.DataFrame(rows)

    # Append the enrichment DataFrame to the original
    df_appended = pd.concat([df, enrichment_df], ignore_index=True)

    # Optionally, remove duplicates based on hash or other columns:
    df_appended = df_appended.drop_duplicates(subset=["hash"])

    return df_appended


def process_csv_files(benign, malicious, triage_dir=None):
    """
    Process benign and malicious CSV files:
    - Remove internal duplicates (by 'hash') in each file.
    - Remove rows from malicious that have hashes common with benign.
    - If triage_dir given, enrich both DataFrames with MalwiObject data.
    """

    try:
        print(f"Reading BENIGN CSV file: {benign}")
        df_benign = pd.read_csv(benign)
        print(f"Read {benign} - shape: {df_benign.shape}")

        print(f"Reading MALICIOUS CSV file: {malicious}")
        df_malicious = pd.read_csv(malicious)
        print(f"Read {malicious} - shape: {df_malicious.shape}")

    except Exception as e:
        print(f"Error reading files: {e}")
        return

    # Enrich with triage data if folder provided
    if triage_dir:
        benign_triage_path = os.path.join(triage_dir, "benign")
        malicious_triage_path = os.path.join(triage_dir, "malicious")

        if os.path.isdir(benign_triage_path):
            print(f"Enriching benign data with files from: {benign_triage_path}")
            df_benign = enrich_dataframe_with_triage(df_benign, benign_triage_path)

        if os.path.isdir(malicious_triage_path):
            print(f"Enriching malicious data with files from: {malicious_triage_path}")
            df_malicious = enrich_dataframe_with_triage(
                df_malicious, malicious_triage_path
            )

    # Remove internal duplicates in each CSV by 'hash'
    initial_benign = len(df_benign)
    df_benign = df_benign.drop_duplicates(subset=["hash"], keep="first")
    print(f"Removed {initial_benign - len(df_benign)} duplicate rows from benign set")

    initial_malicious = len(df_malicious)
    df_malicious = df_malicious.drop_duplicates(subset=["hash"], keep="first")
    print(
        f"Removed {initial_malicious - len(df_malicious)} duplicate rows from malicious set"
    )

    # Identify common hashes between the two sets
    hashes_benign = set(df_benign["hash"])
    hashes_malicious = set(df_malicious["hash"])
    common_hashes = hashes_benign.intersection(hashes_malicious)
    print(f"Found {len(common_hashes)} common hashes between benign and malicious sets")

    # Remove common hashes ONLY from malicious set
    if common_hashes:
        df_malicious = df_malicious[~df_malicious["hash"].isin(common_hashes)]
        print(
            f"Removed {len(common_hashes)} rows from malicious set with common hashes"
        )

    print(f"Final benign set shape: {df_benign.shape}")
    print(f"Final malicious set shape: {df_malicious.shape}")

    # Save outputs
    base_benign, ext_benign = os.path.splitext(benign)
    output_benign = f"{base_benign}_processed{ext_benign}"

    base_malicious, ext_malicious = os.path.splitext(malicious)
    output_malicious = f"{base_malicious}_processed{ext_malicious}"

    try:
        df_benign.to_csv(output_benign, index=False)
        print(f"Saved processed benign CSV to: {output_benign}")

        df_malicious.to_csv(output_malicious, index=False)
        print(f"Saved processed malicious CSV to: {output_malicious}")

    except Exception as e:
        print(f"Error saving processed CSVs: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Process two CSV files (benign and malicious). Removes intra-file duplicates from both. "
            "Removes duplicates common with the benign file ONLY from the malicious file. "
            "Optionally enriches CSV data from a triaging folder containing 'benign' and/or 'malicious' subfolders."
        )
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
    parser.add_argument(
        "--triaging",
        "-t",
        metavar="TRIAGING_FOLDER",
        type=str,
        help="Folder containing 'benign' and/or 'malicious' subfolders to enrich CSV data by parsing files.",
    )

    args = parser.parse_args()

    if args.benign and args.malicious:
        process_csv_files(args.benign, args.malicious, triage_dir=args.triaging)
    else:
        print(
            "Error: Both --benign and --malicious CSV file paths must be provided to process."
        )
