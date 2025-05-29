#!/usr/bin/env python

import os
import sys
import csv
import types
import hashlib
import warnings
import argparse
import questionary

from tqdm import tqdm
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Set, Optional, TextIO


from research.mapping import SpecialCases
from research.malwi_object import MalwiObject


class OutputFormatter:
    """Handles different output formats for MalwiObject data."""

    @staticmethod
    def format_csv(objects_data: List[MalwiObject], output_stream: TextIO) -> None:
        """Format objects as CSV."""
        writer = csv.writer(output_stream)
        writer.writerow(["tokens", "hash", "filepath"])
        for obj in objects_data:
            writer.writerow(
                [
                    obj.to_token_string(),
                    obj.to_string_hash(),
                    obj.file_path,
                ]
            )

    @staticmethod
    def format_json(
        objects_data: List[MalwiObject],
        output_stream: TextIO,
        malicious_threshold: float = 0.5,
        malicious_only: bool = False,
    ) -> None:
        """Format objects as JSON report."""
        report_json = MalwiObject.to_report_json(
            objects_data, [], malicious_threshold, 0, malicious_only
        )
        output_stream.write(report_json + "\n")

    @staticmethod
    def format_yaml(
        objects_data: List[MalwiObject],
        output_stream: TextIO,
        malicious_threshold: float = 0.5,
        malicious_only: bool = False,
    ) -> None:
        """Format objects as YAML report."""
        report_yaml = MalwiObject.to_report_yaml(
            objects_data, [], malicious_threshold, 0, malicious_only
        )
        output_stream.write(report_yaml + "\n")


class CSVWriter:
    """Handles CSV output operations."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.file_handle = None
        self.writer = None
        self._initialize_file()

    def _initialize_file(self):
        """Initialize CSV file with headers if needed."""
        file_exists_before_open = self.file_path.is_file()
        is_empty = not file_exists_before_open or self.file_path.stat().st_size == 0

        self.file_handle = open(
            self.file_path, "a", newline="", encoding="utf-8", errors="replace"
        )
        self.writer = csv.writer(self.file_handle)

        if is_empty:
            self.writer.writerow(["tokens", "hash", "filepath"])

    def write_objects(self, objects_data: List[MalwiObject]) -> None:
        """Write MalwiObject data to CSV."""
        for obj in objects_data:
            self.writer.writerow(
                [
                    obj.to_token_string(),
                    obj.to_string_hash(),
                    obj.file_path,
                ]
            )

    def close(self):
        """Close the CSV file."""
        if self.file_handle:
            self.file_handle.close()


def recursively_disassemble_python(
    file_path: str,
    source_code: str,
    language: str,
    code_obj: Optional[types.CodeType],
    all_objects_data: List[MalwiObject],
    visited_code_ids: Optional[Set[int]] = None,
    errors: Optional[List[str]] = None,
) -> None:
    current_errors = list(errors) if errors is not None else []

    if current_errors or not code_obj:
        for err_msg in current_errors:
            object_data = MalwiObject(
                name=err_msg,
                language=language,
                file_path=file_path,
                codeType=None,
                file_source_code="",
                warnings=[err_msg],
            )
            all_objects_data.append(object_data)
        if not code_obj and not current_errors:
            all_objects_data.append(
                MalwiObject(
                    name=SpecialCases.MALFORMED_FILE.value,
                    language=language,
                    file_path=file_path,
                    file_source_code="",
                    warnings=[SpecialCases.MALFORMED_FILE.value],
                )
            )
        return

    if visited_code_ids is None:
        visited_code_ids = set()

    if id(code_obj) in visited_code_ids:
        return
    visited_code_ids.add(id(code_obj))

    object_data = MalwiObject(
        name=code_obj.co_name,
        language=language,
        file_path=file_path,
        codeType=code_obj,
        file_source_code=source_code,
    )
    all_objects_data.append(object_data)

    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            recursively_disassemble_python(
                file_path=file_path,
                source_code=source_code,
                language=language,
                code_obj=const,
                all_objects_data=all_objects_data,
                visited_code_ids=visited_code_ids,
            )


def disassemble_python_file(file_path_str: str) -> List[MalwiObject]:
    all_disassembled_data: List[MalwiObject] = []
    source_code: Optional[str] = None
    current_file_errors: List[str] = []

    try:
        with open(file_path_str, "r", encoding="utf-8", errors="replace") as f:
            source_code = f.read()
    except Exception:
        current_file_errors.append(SpecialCases.FILE_READING_ISSUES.value)

    top_level_code_object = None
    if source_code is not None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                top_level_code_object = compile(source_code, file_path_str, "exec")
        except UnicodeDecodeError:
            current_file_errors.append(SpecialCases.MALFORMED_FILE.value)
        except SyntaxError:
            current_file_errors.append(SpecialCases.MALFORMED_SYNTAX.value)
        except Exception:
            current_file_errors.append(SpecialCases.MALFORMED_FILE.value)
    else:
        if not current_file_errors:
            current_file_errors.append(SpecialCases.FILE_READING_ISSUES.value)

    recursively_disassemble_python(
        file_path=file_path_str,
        source_code=source_code,
        language="python",
        code_obj=top_level_code_object,
        all_objects_data=all_disassembled_data,
        errors=current_file_errors,
    )
    return all_disassembled_data


def process_single_py_file(
    py_file: Path, predict: bool = True, retrieve_source_code: bool = True
) -> Optional[List[MalwiObject]]:
    try:
        disassembled_data: List[MalwiObject] = disassemble_python_file(str(py_file))
        if predict:
            for d in disassembled_data:
                d.predict()
        if retrieve_source_code:
            for d in disassembled_data:
                d.retrieve_source_code()
        return disassembled_data if disassembled_data else None
    except Exception as e:
        print(
            f"An unexpected error occurred while processing {py_file}: {e}",
            file=sys.stderr,
        )
    return None


@dataclass
class ProcessingResult:
    """Result of processing files from a path."""

    malwi_objects: List[MalwiObject]
    all_files: List[Path]
    skipped_files: List[Path]
    processed_files: int


def collect_files_by_extension(
    input_path: Path,
    accepted_extensions: Optional[List[str]] = None,
    silent: bool = False,
) -> Tuple[List[Path], List[Path]]:
    """
    Collect files from the input path, filtering by accepted extensions.

    Args:
        input_path: Path to file or directory
        accepted_extensions: List of file extensions to accept (without dots)
        silent: If True, suppress error messages

    Returns:
        Tuple of (accepted_files, skipped_files)
    """
    if accepted_extensions is None:
        accepted_extensions = ["py"]

    normalized_extensions = [ext.lower().lstrip(".") for ext in accepted_extensions]
    accepted_files = []
    skipped_files = []

    if not input_path.exists():
        if not silent:
            print(f"Error: Path does not exist: {input_path}", file=sys.stderr)
        return accepted_files, skipped_files

    if input_path.is_file():
        file_extension = input_path.suffix.lstrip(".").lower()
        if file_extension in normalized_extensions:
            accepted_files.append(input_path)
        else:
            skipped_files.append(input_path)

    elif input_path.is_dir():
        for file_path in input_path.rglob("*"):
            if file_path.is_file():
                file_extension = file_path.suffix.lstrip(".").lower()
                if file_extension in normalized_extensions:
                    accepted_files.append(file_path)
                else:
                    skipped_files.append(file_path)

    else:
        skipped_files.append(input_path)

    return accepted_files, skipped_files


def process_files(
    input_path: Path,
    accepted_extensions: Optional[List[str]] = None,
    predict: bool = False,
    retrieve_source_code: bool = False,
    silent: bool = False,
    show_progress: bool = True,
    interactive_triaging: bool = False,
) -> ProcessingResult:
    accepted_files, skipped_files = collect_files_by_extension(
        input_path, accepted_extensions, silent
    )

    all_files = accepted_files + skipped_files
    all_objects: List[MalwiObject] = []
    files_processed_count = 0

    if not accepted_files:
        return ProcessingResult(
            malwi_objects=all_objects,
            all_files=all_files,
            skipped_files=skipped_files,
            processed_files=files_processed_count,
        )

    # Configure progress bar
    tqdm_desc = (
        f"Processing directory '{input_path.name}'"
        if input_path.is_dir() and len(accepted_files) > 1
        else f"Processing '{input_path.name}'"
    )

    disable_tqdm = not show_progress or (
        len(accepted_files) <= 1 and input_path.is_file()
    )

    for file_path in tqdm(
        accepted_files,
        desc=tqdm_desc,
        unit="file",
        ncols=100,
        disable=disable_tqdm,
        leave=False,
    ):
        try:
            file_objects: List[MalwiObject] = process_single_py_file(
                file_path, predict=predict, retrieve_source_code=retrieve_source_code
            )
            if file_objects:
                files_processed_count += 1
                all_objects.extend(file_objects)
            if interactive_triaging:
                triage(file_objects)

        except Exception as e:
            if not silent:
                print(
                    f"Critical error processing file {file_path}: {e}", file=sys.stderr
                )

    if files_processed_count == 0 and accepted_files and not silent:
        print(
            "No files were successfully processed to produce data from the input path.",
            file=sys.stderr,
        )

    return ProcessingResult(
        malwi_objects=all_objects,
        all_files=all_files,
        skipped_files=skipped_files,
        processed_files=files_processed_count,
    )


def triage(all_objects: List["MalwiObject"]):
    benign_dir = os.path.join("triaging", "benign")
    malicious_dir = os.path.join("triaging", "malicious")

    os.makedirs(benign_dir, exist_ok=True)
    os.makedirs(malicious_dir, exist_ok=True)

    for obj in all_objects:
        obj.retrieve_source_code()

        if not hasattr(obj, "code") or not obj.code:
            print(
                "Object has no source code or 'retrieve_source_code' was not effective, skipping..."
            )
            continue

        code_hash = hashlib.sha1(obj.code.encode("utf-8")).hexdigest()

        file_extension = ".yaml"
        benign_path = os.path.join(benign_dir, f"{code_hash}{file_extension}")
        malicious_path = os.path.join(malicious_dir, f"{code_hash}{file_extension}")

        if os.path.exists(benign_path) or os.path.exists(malicious_path):
            print(f"Hash {code_hash} (JSON data) already exists, skipping...")
            continue

        triage_result = questionary.select(
            f"Is the following code malicious?\n\n# Original Maliciousness: {obj.maliciousness}\n\n{obj.code}\n\n",
            use_shortcuts=True,
            choices=["yes", "no", "skip", "exit"],
        ).ask()

        output_path: str = ""
        if triage_result == "yes":
            output_path = malicious_path
        elif triage_result == "no":
            output_path = benign_path
        elif triage_result == "skip":
            print(f"Skipping sample {code_hash}...")
            continue
        elif triage_result == "exit" or triage_result is None:
            print("Exiting triage process.")
            exit(0)
        else:
            print(
                f"Unknown triage result '{triage_result}', skipping sample {code_hash}."
            )
            continue

        if output_path:
            try:
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(
                        MalwiObject.to_report_yaml(
                            [obj],
                            [obj.file_path],
                            malicious_threshold=0.0,
                            number_of_skipped_files=0.0,
                            malicious_only=False,
                        )
                    )
                print(f"Saved data for hash {code_hash} to {output_path}")
            except IOError as e:
                print(
                    f"Error writing JSON file {output_path} for hash {code_hash}: {e}"
                )
            except Exception as e:
                print(
                    f"An unexpected error occurred while saving JSON for hash {code_hash}: {e}"
                )


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Recursively disassemble Python files",
        epilog="Example: python %(prog)s your_script.or_directory --format txt --save output.txt",
    )
    parser.add_argument(
        "path", metavar="PATH", help="The Python file or directory to process."
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        choices=["txt", "csv", "json", "yaml"],
        default="txt",
        help="Output format (default: txt). 'json' and 'yaml' are report formats.",
    )
    parser.add_argument(
        "-s",
        "--save",
        type=str,
        default=None,
        metavar="FILEPATH",
        help="Path to save the output. If not provided, output goes to stdout.",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default=None,
        help="Path to the ML model for maliciousness prediction.",
    )
    parser.add_argument(
        "--tokenizer-path",
        type=str,
        default=None,
        help="Path to the tokenizer for the ML model.",
    )
    parser.add_argument(
        "--malicious-threshold",
        type=float,
        default=0.5,
        help="Threshold for classifying as malicious in reports (0.0 to 1.0).",
    )
    parser.add_argument(
        "--malicious-only",
        action="store_true",
        help="In reports, include only files deemed malicious.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 2.6")

    args: argparse.Namespace = parser.parse_args()
    input_path_obj: Path = Path(args.path)

    try:
        MalwiObject.load_models_into_memory(
            model_path=args.model_path, tokenizer_path=args.tokenizer_path
        )
    except Exception as e:
        print(
            f"Warning: Could not initialize ML models: {e}. Maliciousness prediction will be disabled.",
            file=sys.stderr,
        )

    if not input_path_obj.exists():
        print(f"Error: Input path does not exist: {input_path_obj}", file=sys.stderr)
        sys.exit(1)

    # Process input and collect all data
    collected_data: List[MalwiObject] = []
    csv_writer_instance: Optional[CSVWriter] = None

    try:
        # Handle CSV output separately for streaming
        if args.format == "csv" and args.save:
            save_path = Path(args.save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            csv_writer_instance = CSVWriter(save_path)
            print(
                f"CSV output will be appended to: {save_path.resolve()}",
                file=sys.stderr,
            )

            # Process files and write directly to CSV
            result = process_files(
                input_path_obj,
                accepted_extensions=["py"],
                predict=False,
                retrieve_source_code=False,
                silent=False,
                show_progress=True,
            )

            if result.malwi_objects:
                csv_writer_instance.write_objects(result.malwi_objects)

            csv_writer_instance.close()

        else:
            # For all other formats, collect data first
            result = process_files(
                input_path_obj,
                accepted_extensions=["py"],
                predict=False,
                retrieve_source_code=False,
                silent=False,
                show_progress=True,
            )
            collected_data = result.malwi_objects

            # Handle output
            output_stream = sys.stdout
            output_file = None

            if args.save:
                save_path = Path(args.save)
                save_path.parent.mkdir(parents=True, exist_ok=True)
                output_file = open(save_path, "w", encoding="utf-8", errors="replace")
                output_stream = output_file
                print(
                    f"Output will be saved to: {save_path.resolve()}", file=sys.stderr
                )

            try:
                if args.format == "csv":
                    OutputFormatter.format_csv(collected_data, output_stream)
                elif args.format == "json":
                    OutputFormatter.format_json(
                        collected_data,
                        output_stream,
                        args.malicious_threshold,
                        args.malicious_only,
                    )
                elif args.format == "yaml":
                    OutputFormatter.format_yaml(
                        collected_data,
                        output_stream,
                        args.malicious_threshold,
                        args.malicious_only,
                    )
            finally:
                if output_file:
                    output_file.close()

    except Exception as e:
        print(f"A critical error occurred: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc(file=sys.stderr)
        if csv_writer_instance:
            csv_writer_instance.close()
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
