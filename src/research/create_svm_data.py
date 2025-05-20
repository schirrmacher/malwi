import os
import csv
import argparse
from pathlib import Path

from research.normalize_data import MalwiNode
from cli.entry import file_or_dir_to_nodes

from research.predict import initialize_models


def main():
    parser = argparse.ArgumentParser(
        description="Run AI training analysis on immediate child directories of a parent folder and save results to CSV."
    )
    parser.add_argument(
        "--dir",
        "-d",
        type=str,
        required=True,
        help="Path to the parent directory containing immediate child directories to scan.",
    )
    parser.add_argument(
        "--label",
        "-l",
        type=str,
        required=True,
        choices=["malicious", "benign"],
        help="Label (e.g., malicious, benign) to include as a column in the CSV output.",
    )
    parser.add_argument(
        "--save",
        "-s",
        type=str,
        metavar="FILENAME",
        default=None,
        help="Path to the CSV output file. If provided, results will be saved.",
    )
    parser.add_argument(
        "--threshold",
        "-mt",
        metavar="FLOAT",
        type=float,
        default=0.5,
        help="Specify the threshold for classifying nodes as malicious (default: 0.5).",
    )
    parser.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Specify the custom tokenizer directory.",
        default=None,
    )
    parser.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="Specify the custom model path directory.",
        default=None,
    )

    args = parser.parse_args()

    try:
        initialize_models(
            model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
    except Exception as e:
        print(f"Warning: Could not initialize models: {e}")

    parent_dir_path = args.dir

    if not os.path.isdir(parent_dir_path):
        print(f"Error: Provided path '{parent_dir_path}' is not a valid directory.")
        return

    output_csv_filename = args.save
    csv_writer = None
    csv_file_handle = None

    if output_csv_filename:
        try:
            csv_file_handle = open(output_csv_filename, "w", newline="")
            csv_writer = csv.writer(csv_file_handle)
            header = [
                "files_count",
                "entities_count",
                "malicious_percentage",
                "dir_name",
                "label",
            ]
            csv_writer.writerow(header)
            csv_file_handle.flush()
            print(f"Results will be saved to: {output_csv_filename}")
        except IOError as e:
            print(
                f"Error: Could not open file '{output_csv_filename}' for writing: {e}"
            )
            if csv_file_handle:
                csv_file_handle.close()
            csv_file_handle = None
            csv_writer = None

    print(f"\nScanning immediate subdirectories of: {parent_dir_path}")
    processed_dirs_count = 0

    for item_name in os.listdir(parent_dir_path):
        child_dir_path = os.path.join(parent_dir_path, item_name)

        if os.path.isdir(child_dir_path):
            dir_name = item_name
            processed_dirs_count += 1
            print(f"\nProcessing directory: {dir_name} (Path: {child_dir_path})")

            try:
                malicious_nodes, benign_nodes = file_or_dir_to_nodes(
                    path=Path(child_dir_path), threshold=args.threshold
                )

                analysis_result_dict = MalwiNode.nodes_to_dict(
                    malicious_nodes=malicious_nodes, benign_nodes=benign_nodes
                )

                files_count = analysis_result_dict.get("files_count", 0)
                entities_count = analysis_result_dict.get("entities_count", 0)
                malicious_percentage = float(
                    analysis_result_dict.get("malicious_percentage", 0.0)
                )

                print(f"  Files Count: {files_count}")
                print(f"  Entities Count: {entities_count}")
                print(f"  Malicious Percentage: {malicious_percentage:.2f}%")

                if csv_writer and csv_file_handle:
                    csv_writer.writerow(
                        [
                            files_count,
                            entities_count,
                            f"{malicious_percentage:.2f}",
                            dir_name,
                            args.label,
                        ]
                    )
                    csv_file_handle.flush()

            except Exception as e:
                print(f"An error occurred while processing directory '{dir_name}': {e}")
                if csv_writer and csv_file_handle:
                    csv_writer.writerow(
                        ["ERROR", "ERROR", "ERROR", dir_name, args.label]
                    )
                    csv_file_handle.flush()

    if processed_dirs_count == 0:
        print(f"\nNo subdirectories found in '{parent_dir_path}'.")

    if csv_file_handle:
        csv_file_handle.close()
        if csv_writer:
            print(f"\nAnalysis complete. Results saved to '{output_csv_filename}'.")
    elif output_csv_filename:
        print(
            f"\nAnalysis complete, but failed to save results to '{output_csv_filename}' (could not be opened/written)."
        )
    else:
        print(
            "\nAnalysis complete. Results were not saved (use the --save FILENAME option)."
        )


if __name__ == "__main__":
    main()
