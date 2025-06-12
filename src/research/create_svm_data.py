import os
import csv
import random
import logging
import argparse
import tempfile
import shutil

from pathlib import Path
from typing import List, Optional, Set

from research.disassemble_python import MalwiObject, process_files


class RandomFilePicker:
    """
    A class that scans a directory once, caches the file list, and allows for
    repeated, fast selection of random files.
    """

    def __init__(self, directory: str, extensions: Optional[List[str]] = None):
        if not os.path.isdir(directory):
            raise FileNotFoundError(f"Directory not found: {directory}")
        self.directory = directory
        self.file_list: List[str] = []
        self._normalized_extensions: Optional[Set[str]] = None

        if extensions:
            self._normalized_extensions = {
                ext.lower() if ext.startswith(".") else "." + ext.lower()
                for ext in extensions
            }
        self.rescan()

    def _scan(self):
        self.file_list.clear()
        for root, _, files in os.walk(self.directory):
            for name in files:
                if self._normalized_extensions:
                    file_ext = os.path.splitext(name)[1].lower()
                    if file_ext in self._normalized_extensions:
                        self.file_list.append(os.path.join(root, name))
                else:
                    self.file_list.append(os.path.join(root, name))

    def rescan(self):
        self._scan()

    def get_random_files(self, n: int) -> List[str]:
        if n > len(self.file_list):
            return self.file_list.copy()
        return random.sample(self.file_list, n)


def _write_row_to_csv(row_data: dict, output_file: Path):
    """
    Handles the logic for incrementally saving a row of data to a CSV file.
    It will rewrite the entire file with a new header if new columns are found.
    """
    file_exists = output_file.is_file() and output_file.stat().st_size > 0
    on_disk_header = []
    if file_exists:
        with open(output_file, "r", newline="", encoding="utf-8") as f_read:
            reader = csv.reader(f_read)
            try:
                on_disk_header = next(reader)
            except StopIteration:
                file_exists = False

    current_row_keys = set(row_data.keys())
    on_disk_header_set = set(on_disk_header)

    if current_row_keys.issubset(on_disk_header_set):
        with open(output_file, "a", newline="", encoding="utf-8") as f_append:
            writer = csv.DictWriter(f_append, fieldnames=on_disk_header)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row_data)
        print(f"Appended results for '{row_data['package']}' to {output_file}")
    else:
        print(
            f"New feature columns found. Rewriting {output_file} with updated header..."
        )
        all_data = []
        if file_exists:
            with open(output_file, "r", newline="", encoding="utf-8") as f_read:
                reader = csv.DictReader(f_read)
                all_data.extend(list(reader))
        all_data.append(row_data)
        new_header_set = on_disk_header_set.union(current_row_keys)
        final_header = ["package", "label"] + sorted(
            list(new_header_set - {"package", "label"})
        )
        with open(output_file, "w", newline="", encoding="utf-8") as f_write:
            writer = csv.DictWriter(f_write, fieldnames=final_header)
            writer.writeheader()
            writer.writerows(all_data)
        print(f"Rewrote {output_file} and saved results for '{row_data['package']}'")


def process_benign_packages(
    parent_dir: Path, args: argparse.Namespace, output_file: Path
):
    """
    Creates a fixed number of artificial benign samples by sampling files
    from a master list and processing them in temporary directories.
    """
    print("--- Benign Processing Mode ---")
    print("Scanning all subdirectories to create a master list of benign files...")
    master_picker = RandomFilePicker(
        directory=str(parent_dir), extensions=args.extensions
    )

    if not master_picker.file_list:
        print(
            "Error: No benign files with specified extensions found to sample from. Exiting."
        )
        return 0

    print(f"Found {len(master_picker.file_list)} total benign files.")
    print(f"Creating {args.benign_samples} artificial samples...")

    processed_count = 0
    for i in range(args.benign_samples):
        package_name = f"benign_sample_{i + 1}"
        print(f"\n--- Processing {package_name} ---")
        temp_dir = None
        try:
            # Determine how many files to select for this sample
            max_files_for_this_sample = min(
                args.max_files_per_sample, len(master_picker.file_list)
            )
            num_files_to_select = random.randint(1, max_files_for_this_sample)

            sample_of_files = master_picker.get_random_files(num_files_to_select)

            # Create a temporary directory and copy the sampled files into it
            temp_dir = tempfile.mkdtemp(prefix="benign_sample_")
            for file_path in sample_of_files:
                shutil.copy(file_path, temp_dir)

            print(
                f"Selected {len(sample_of_files)} files and copied to temporary dir: {temp_dir}"
            )

            print(f"look for maliciousness score {args.threshold}")

            # Process the temporary directory
            results = process_files(
                input_path=Path(temp_dir),
                accepted_extensions=args.extensions,
                predict=True,
                retrieve_source_code=False,
                silent=args.quiet,
                show_progress=not args.quiet,
                malicious_threshold=args.threshold,
            )

            print(f"Identified {len(results.objects)} malicious objects")

            for o in results.objects:
                print(o.maliciousness)

            token_stats = MalwiObject.collect_token_stats(results.objects)
            if not token_stats:
                print(
                    f"Warning: No token statistics generated for '{package_name}'. Skipping."
                )
                continue

            token_stats["package"] = package_name
            token_stats["label"] = args.label
            processed_count += 1

            _write_row_to_csv(token_stats, output_file)

        except Exception as e:
            print(
                f"An error occurred while processing '{package_name}': {e}. Skipping."
            )
        finally:
            # Ensure the temporary directory is always cleaned up
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    return processed_count


def process_malicious_packages(
    subdirectories: List[Path], args: argparse.Namespace, output_file: Path
):
    """
    Processes each subdirectory as a distinct malicious package.
    """
    print("--- Malicious Processing Mode ---")
    processed_count = 0
    for child_dir in subdirectories:
        package_name = child_dir.name
        print(f"\n--- Processing package: {package_name} ---")
        try:
            results = process_files(
                input_path=child_dir,
                accepted_extensions=args.extensions,
                predict=True,
                retrieve_source_code=False,
                silent=args.quiet,
                show_progress=not args.quiet,
                malicious_threshold=args.threshold,
            )

            token_stats = MalwiObject.collect_token_stats(results.objects)
            if not token_stats:
                print(
                    f"Warning: No token statistics generated for '{package_name}'. Skipping."
                )
                continue

            token_stats["package"] = package_name
            token_stats["label"] = args.label
            processed_count += 1

            _write_row_to_csv(token_stats, output_file)

        except Exception as e:
            print(
                f"An error occurred while processing '{package_name}': {e}. Skipping."
            )

    return processed_count


def create_svm_data():
    """
    Main function to process directories, collect dynamic features,
    and save them to a CSV file after each package is processed.
    """
    parser = argparse.ArgumentParser(
        description="Process project directories to generate a dynamic feature CSV for SVM training."
    )
    parser.add_argument(
        "--dir", "-d", type=str, required=True, help="Path to the parent directory."
    )
    parser.add_argument(
        "--label", "-l", type=str, required=True, help="Label ('malicious', 'benign')."
    )
    parser.add_argument(
        "--save", "-s", type=str, required=True, help="Path for the output CSV file."
    )
    parser.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Custom tokenizer directory.",
        default=None,
    )
    parser.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="Custom model path directory.",
        default=None,
    )
    parser.add_argument(
        "--extensions", nargs="+", default=[".py"], help="File extensions to process."
    )
    parser.add_argument(
        "--threshold", type=float, default=0.7, help="Maliciousness threshold."
    )
    parser.add_argument("--quiet", action="store_true", help="Run in silent mode.")

    # --- NEW CLI ARGUMENTS ---
    benign_group = parser.add_argument_group("Benign Sampling Options")
    benign_group.add_argument(
        "--benign-samples",
        type=int,
        default=10000,
        help="Number of artificial benign samples to create. Used only if --label is 'benign'.",
    )
    benign_group.add_argument(
        "--max-files-per-sample",
        type=int,
        default=100,
        help="Maximum number of files to include in each artificial benign sample.",
    )

    args = parser.parse_args()

    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
    except Exception as e:
        if not args.quiet:
            logging.error(
                f"Warning: Could not initialize ML models: {e}. Prediction will be disabled."
            )

    parent_dir = Path(args.dir)
    if not parent_dir.is_dir():
        print(f"Error: Provided path '{parent_dir}' is not a valid directory.")
        return

    output_file = Path(args.save)
    processed_count = 0

    if args.label.lower() == "benign":
        processed_count = process_benign_packages(parent_dir, args, output_file)
    else:
        print(f"Scanning subdirectories in '{parent_dir}'...")
        subdirectories = [d for d in parent_dir.iterdir() if d.is_dir()]
        if not subdirectories:
            print(f"No subdirectories found in '{parent_dir}'. Exiting.")
            return
        processed_count = process_malicious_packages(subdirectories, args, output_file)

    print(
        f"\n✅ Success! Analysis complete. Processed {processed_count} packages/samples."
    )
    print(f"Final data saved to '{args.save}'")


if __name__ == "__main__":
    try:
        create_svm_data()
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user. Partial results are saved.")
