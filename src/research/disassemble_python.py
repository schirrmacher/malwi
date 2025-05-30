#!/usr/bin/env python

import os
import sys
import csv
import yaml
import json
import types
import base64
import types
import inspect
import hashlib
import warnings
import argparse
import questionary

from tqdm import tqdm
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Set, Optional, TextIO


from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional, Any, Dict, Union

from research.mapping import SpecialCases, tokenize_code_type, COMMON_TARGET_FILES
from research.predict import get_node_text_prediction, initialize_models


class OutputFormatter:
    """Handles different output formats for MalwiObject data."""

    @staticmethod
    def format_csv(objects_data: List["MalwiObject"], output_stream: TextIO) -> None:
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
        objects_data: List["MalwiObject"],
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
        objects_data: List["MalwiObject"],
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

    def write_objects(self, objects_data: List["MalwiObject"]) -> None:
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
    all_objects_data: List["MalwiObject"],
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
        name=code_obj.co_qualname,
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


def find_code_object_by_name(
    code: types.CodeType, target_name: str
) -> Optional[types.CodeType]:
    if code.co_qualname == target_name:
        return code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            result = find_code_object_by_name(const, target_name)
            if result:
                return result
    return None


def disassemble_python_file(
    source_code: str, file_path: str, target_object_name: Optional[str] = None
) -> List["MalwiObject"]:
    all_objects: List[MalwiObject] = []
    current_file_errors: List[str] = []

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            code_object = compile(source_code, file_path, "exec")

        if target_object_name:
            target_code = find_code_object_by_name(code_object, target_object_name)
            if target_code:
                return [
                    MalwiObject(
                        name=target_code.co_qualname,
                        language="python",
                        file_path=file_path,
                        file_source_code=source_code,
                        codeType=target_code,
                    )
                ]

    except UnicodeDecodeError:
        current_file_errors.append(SpecialCases.MALFORMED_FILE.value)
        code_object = None
    except SyntaxError:
        current_file_errors.append(SpecialCases.MALFORMED_SYNTAX.value)
        code_object = None
    except Exception:
        current_file_errors.append(SpecialCases.MALFORMED_FILE.value)
        code_object = None

    # If compilation failed and no errors were caught, add fallback error
    if code_object is None and not current_file_errors:
        current_file_errors.append(SpecialCases.FILE_READING_ISSUES.value)

    recursively_disassemble_python(
        file_path=file_path,
        source_code=source_code,
        language="python",
        code_obj=code_object,
        all_objects_data=all_objects,
        errors=current_file_errors,
    )

    return all_objects


def process_python_file(
    file_path: Path, predict: bool = True, retrieve_source_code: bool = True
) -> Optional[List["MalwiObject"]]:
    try:
        source_code = file_path.read_text(encoding="utf-8", errors="replace")
        objects: List[MalwiObject] = disassemble_python_file(
            source_code, file_path=str(file_path)
        )

        if predict:
            for obj in objects:
                obj.predict()

        if retrieve_source_code:
            for obj in objects:
                obj.retrieve_source_code()

        return objects or None

    except Exception as e:
        print(
            f"[Error] Failed to process {file_path} ({type(e).__name__}): {e}",
            file=sys.stderr,
        )
        return None


@dataclass
class ProcessingResult:
    """Result of processing files from a path."""

    malwi_objects: List["MalwiObject"]
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
            file_objects: List[MalwiObject] = process_python_file(
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
            obj.maliciousness = 1.0
            output_path = malicious_path
        elif triage_result == "no":
            obj.maliciousness = 0.0
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


class LiteralStr(str):
    pass


def literal_str_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, literal_str_representer)


@dataclass
class MalwiObject:
    name: str
    file_path: str
    warnings: List[str]
    file_source_code: str
    code: Optional[str] = None
    maliciousness: Optional[float] = None
    codeType: Optional[types.CodeType] = None

    def __init__(
        self,
        name: str,
        language: str,
        file_path: str,
        file_source_code: str,
        codeType: types.CodeType = None,
        warnings: List[str] = [],
    ):
        self.name = name
        self.file_path = file_path
        self.warnings = list(warnings)
        self.maliciousness = None
        self.codeType = codeType
        self.file_source_code = file_source_code

        if Path(self.file_path).name in COMMON_TARGET_FILES.get(language, []):
            self.warnings += [SpecialCases.TARGETED_FILE.value]

    @classmethod
    def load_models_into_memory(
        cls, model_path: Optional[str] = None, tokenizer_path: Optional[str] = None
    ) -> None:
        initialize_models(model_path=model_path, tokenizer_path=tokenizer_path)

    def to_tokens(self, map_special_tokens: bool = True) -> List[str]:
        all_token_parts: List[str] = []
        all_token_parts.extend(self.warnings)
        generated_instructions = tokenize_code_type(
            code_type=self.codeType, map_special_tokens=map_special_tokens
        )
        all_token_parts.extend(generated_instructions)
        return all_token_parts

    def to_token_string(self, map_special_tokens: bool = True) -> str:
        return " ".join(self.to_tokens(map_special_tokens=map_special_tokens))

    def to_string_hash(self) -> str:
        tokens = self.to_token_string()
        encoded_string = tokens.encode("utf-8")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

    def retrieve_source_code(self) -> Optional[str]:
        try:
            self.code = inspect.getsource(self.codeType)
            return self.code
        except Exception:
            pass
        return None

    def predict(self) -> Optional[dict]:
        prediction = get_node_text_prediction(self.to_token_string())
        if prediction and "probabilities" in prediction:
            self.maliciousness = prediction["probabilities"][1]
        return prediction

    def to_dict(self) -> dict:
        code_display_value = self.code
        if code_display_value is None:
            code_display_value = "<source not available>"

        if isinstance(code_display_value, str) and "\n" in code_display_value:
            final_code_value = LiteralStr(code_display_value.strip())
        else:
            final_code_value = code_display_value

        return {
            "path": str(self.file_path),
            "contents": [
                {
                    "name": self.name,
                    "score": self.maliciousness,
                    "code": final_code_value,
                    "tokens": self.to_token_string(),
                    "hash": self.to_string_hash(),
                }
            ],
        }

    def to_yaml(self) -> str:
        return yaml.dump(
            self.to_dict(),
            sort_keys=False,
            width=float("inf"),
            default_flow_style=False,
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=4)

    @staticmethod
    def _generate_report_data(
        malwi_files: List["MalwiObject"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
        include_source_files: bool = True,
    ) -> Dict[str, Any]:
        processed_objects_count = len(malwi_files)
        total_maliciousness_score = 0.0
        malicious_objects_count = 0
        files_with_scores_count = 0

        for mf in malwi_files:
            if mf.maliciousness is None:
                mf.predict()

            if mf.maliciousness is not None:
                total_maliciousness_score += mf.maliciousness
                files_with_scores_count += 1
                if mf.maliciousness > malicious_threshold:
                    malicious_objects_count += 1

        summary_statistics = {
            "total_files": len(all_files),
            "skipped_files": number_of_skipped_files,
            "processed_objects": processed_objects_count,
            "malicious_objects": malicious_objects_count,
        }

        report_data = {
            "statistics": summary_statistics,
            "details": [],
        }

        if include_source_files:
            report_data["sources"] = {}

        for mf in malwi_files:
            is_malicious = (
                mf.maliciousness is not None and mf.maliciousness > malicious_threshold
            )
            include = (
                is_malicious
                or (not malicious_only and mf.maliciousness is None)
                or (not malicious_only and mf.maliciousness is not None)
            )

            if include:
                mf.retrieve_source_code()
                report_data["details"].append(mf.to_dict())

                if include_source_files:
                    report_data["sources"][mf.file_path] = base64.b64encode(
                        mf.file_source_code.encode("utf-8")
                    ).decode("utf-8")

        return report_data

    @classmethod
    def to_report_json(
        cls,
        malwi_files: List["MalwiObject"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
        include_source_files: bool = True,
    ) -> str:
        report_data = cls._generate_report_data(
            malwi_files,
            all_files,
            malicious_threshold,
            number_of_skipped_files,
            malicious_only=malicious_only,
            include_source_files=include_source_files,
        )
        return json.dumps(report_data, indent=4)

    @classmethod
    def to_report_yaml(
        cls,
        malwi_files: List["MalwiObject"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
        include_source_files: bool = True,
    ) -> str:
        report_data = cls._generate_report_data(
            malwi_files,
            all_files,
            malicious_threshold,
            number_of_skipped_files,
            malicious_only=malicious_only,
            include_source_files=include_source_files,
        )
        return yaml.dump(
            report_data, sort_keys=False, width=float("inf"), default_flow_style=False
        )

    @classmethod
    def to_report_markdown(
        cls,
        malwi_files: List["MalwiObject"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
    ) -> str:
        report_data = cls._generate_report_data(
            malwi_files,
            all_files,
            malicious_threshold,
            number_of_skipped_files,
            malicious_only=malicious_only,
        )

        stats = report_data["statistics"]

        txt = "# Malwi Report\n\n"
        txt += f"- Files: {stats['total_files']}\n"
        txt += f"- Skipped: {stats['skipped_files']}\n"
        txt += f"- Processed Objects: {stats['processed_objects']}\n"
        txt += f"- Malicious Objects: {stats['malicious_objects']}\n\n"

        for file in report_data["details"]:
            txt += f"## {file['path']}\n"

            for object in file["contents"]:
                name = object["name"] if object["name"] else "<object>"
                score = object["score"]
                if score > malicious_threshold:
                    maliciousness = f"👹 {score}"
                else:
                    maliciousness = f"🟢 {score}"
                txt += f"- Object: {name}\n"
                txt += f"- Maliciousness: {maliciousness}\n\n"
                txt += "### Code\n"
                txt += f"```\n{object['code']}\n```\n\n"
                txt += "### Tokens\n"
                txt += f"```\n{object['tokens']}\n```\n"
            txt += "\n\n"

        return txt

    @classmethod
    def from_file(
        cls, file_path: Union[str, Path], language: str = "python"
    ) -> List["MalwiObject"]:
        file_path = Path(file_path)
        malwi_objects: List[MalwiObject] = []

        with file_path.open("r", encoding="utf-8") as f:
            if file_path.suffix in [".yaml", ".yml"]:
                # Load all YAML documents in the file
                documents = yaml.safe_load_all(f)
            elif file_path.suffix == ".json":
                # JSON normally single doc; for multiple JSON objects in one file,
                # you could do more advanced parsing, but here just one load:
                documents = [json.load(f)]
            else:
                raise ValueError(f"Unsupported file type: {file_path.suffix}")

            for data in documents:
                if not data:
                    continue
                details = data.get("details", [])
                for detail in details:
                    if not details:
                        continue
                    file_path = detail.get("path", "") or ""
                    raw_source = data.get("sources", {}).get(file_path)
                    source = base64.b64decode(raw_source).decode("utf-8")
                    contents = detail.get("contents", [])

                    if not contents:
                        continue
                    for item in contents:
                        name = item.get("name")
                        file_path_val = file_path
                        warnings = item.get("warnings", [])

                        matchingCodeType = disassemble_python_file(
                            source_code=source,
                            file_path=file_path,
                            target_object_name=name,
                        )

                        malwi_object = cls(
                            name=name,
                            file_source_code=source,
                            language=language,
                            file_path=file_path_val,
                            warnings=warnings,
                            codeType=matchingCodeType[0].codeType,
                        )
                        malwi_objects.append(malwi_object)

        return malwi_objects


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
