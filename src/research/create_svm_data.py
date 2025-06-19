import os
import csv
import random
import argparse
import tempfile
import shutil

from pathlib import Path
from typing import List, Optional, Set

from research.disassemble_python import MalwiObject, process_files
from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
)


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
        success(f"Appended results for '{row_data['package']}' to {output_file}")
    else:
        info(
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
        success(f"Rewrote {output_file} and saved results for '{row_data['package']}'")


def process_random_samples(
    parent_dir: Path, args: argparse.Namespace, output_file: Path, label: str
):
    """
    Creates a fixed number of artificial samples by sampling files
    from a master list and processing them in temporary directories.
    """
    info(f"--- {label.capitalize()} Processing Mode (Random Sampling) ---")
    progress(
        "Scanning all subdirectories to create a master list of files for sampling..."
    )
    master_picker = RandomFilePicker(
        directory=str(parent_dir), extensions=args.extensions
    )

    if not master_picker.file_list:
        error("No files with specified extensions found to sample from. Exiting.")
        return 0

    success(f"Found {len(master_picker.file_list)} total files for sampling.")
    info(f"Creating {args.samples} artificial samples...")

    processed_count = 0
    for i in range(args.samples):
        package_name = f"{label}_sample_{i + 1}"
        info(f"--- Processing {package_name} ---")
        temp_dir = None
        try:
            # Determine how many files to select for this sample
            max_files_for_this_sample = min(
                args.max_files_per_sample, len(master_picker.file_list)
            )
            num_files_to_select = random.randint(1, max_files_for_this_sample)

            sample_of_files = master_picker.get_random_files(num_files_to_select)

            # Create a temporary directory and copy the sampled files into it
            temp_dir = tempfile.mkdtemp(prefix=f"{label}_sample_")
            for file_path in sample_of_files:
                shutil.copy(file_path, temp_dir)

            info(
                f"Selected {len(sample_of_files)} files and copied to temporary dir: {temp_dir}"
            )

            info(f"Processing with maliciousness threshold: {args.threshold}")

            # Process the temporary directory
            results = process_files(
                input_path=Path(temp_dir),
                accepted_extensions=args.extensions,
                predict=True,
                retrieve_source_code=False,
                silent=args.quiet,
                malicious_threshold=args.threshold,
            )

            info(
                f"Found {len(results.all_objects)} objects above maliciousness threshold"
            )

            if results.all_objects:
                avg_maliciousness = sum(
                    o.maliciousness for o in results.all_objects
                ) / len(results.all_objects)
                info(f"Average maliciousness score: {avg_maliciousness:.3f}")

            token_stats = MalwiObject.collect_token_stats(results.malicious_objects)
            if not token_stats:
                warning(
                    f"No token statistics generated for '{package_name}'. Skipping."
                )
                continue

            token_stats["package"] = package_name
            token_stats["label"] = label
            processed_count += 1

            _write_row_to_csv(token_stats, output_file)

        except Exception as e:
            error(
                f"An error occurred while processing '{package_name}': {e}. Skipping."
            )
        finally:
            # Ensure the temporary directory is always cleaned up
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)

    return processed_count


def process_package_directories(
    subdirectories: List[Path], args: argparse.Namespace, output_file: Path, label: str
):
    """
    Processes each subdirectory as a distinct package.
    """
    info(f"--- {label.capitalize()} Processing Mode (Package Directories) ---")
    processed_count = 0
    for child_dir in subdirectories:
        package_name = child_dir.name
        info(f"--- Processing package: {package_name} ---")
        try:
            results = process_files(
                input_path=child_dir,
                accepted_extensions=args.extensions,
                predict=True,
                retrieve_source_code=False,
                silent=args.quiet,
                malicious_threshold=args.threshold,
            )

            token_stats = MalwiObject.collect_token_stats(results.malicious_objects)
            if not token_stats:
                warning(
                    f"No token statistics generated for '{package_name}'. Skipping."
                )
                continue

            token_stats["package"] = package_name
            token_stats["label"] = label
            processed_count += 1

            _write_row_to_csv(token_stats, output_file)

        except Exception as e:
            error(
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

    # --- Group for Sampling Options ---
    sampling_options_group = parser.add_argument_group("Sampling Options")
    sampling_options_group.add_argument(
        "--samples",
        type=int,
        default=10000,
        help="Number of artificial samples to create when random sampling is enabled.",
    )
    sampling_options_group.add_argument(
        "--max-files-per-sample",
        type=int,
        default=100,
        help="Maximum number of files to include in each artificial sample when random sampling is enabled.",
    )
    sampling_options_group.add_argument(
        "--use-random-sampling",
        action="store_true",
        help="Use random file sampling to create artificial packages. If not set, each subdirectory in the provided parent directory will be treated as a separate package.",
    )

    args = parser.parse_args()

    # Configure messaging system
    configure_messaging(quiet=args.quiet)

    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
    except Exception as e:
        warning(f"Could not initialize ML models: {e}. Prediction will be disabled.")

    parent_dir = Path(args.dir)
    if not parent_dir.is_dir():
        error(f"Provided path '{parent_dir}' is not a valid directory.")
        return

    output_file = Path(args.save)
    processed_count = 0

    # Determine the actual label to be used (e.g., 'malicious' or 'benign')
    processing_label = args.label.lower()

    if args.use_random_sampling:
        processed_count = process_random_samples(
            parent_dir, args, output_file, processing_label
        )
    else:
        info(
            f"Scanning subdirectories in '{parent_dir}' for {processing_label} packages..."
        )
        subdirectories = [d for d in parent_dir.iterdir() if d.is_dir()]
        if not subdirectories:
            error(f"No subdirectories found in '{parent_dir}'. Exiting.")
            return
        processed_count = process_package_directories(
            subdirectories, args, output_file, processing_label
        )

    success(f"Analysis complete. Processed {processed_count} packages/samples.")
    success(f"Final data saved to '{args.save}'")


if __name__ == "__main__":
    try:
        create_svm_data()
    except KeyboardInterrupt:
        info("Interrupted by user. Partial results are saved.")
