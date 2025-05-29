#!/usr/bin/env python

import os
import dis
import sys
import csv
import yaml
import json
import types
import base64
import inspect
import pathlib
import marshal
import hashlib
import warnings
import argparse
import binascii
import questionary

from tqdm import tqdm
from enum import Enum
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Set, Optional, Any, Dict, TextIO, Union

from research.mapping import (
    map_entropy_to_token,
    map_string_length_to_token,
    calculate_shannon_entropy,
    is_file_path,
    is_valid_ip,
    is_valid_url,
    is_escaped_hex,
    is_base64,
    is_hex,
)
from research.predict import get_node_text_prediction, initialize_models
from common.files import read_json_from_file


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
SENSITIVE_PATHS: Set[str] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "sensitive_files.json"
)
FUNCTION_MAPPING: Dict[str, Any] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "function_mapping.json"
)
IMPORT_MAPPING: Dict[str, Any] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "import_mapping.json"
)
COMMON_TARGET_FILES: Dict[str, Set[str]] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "target_files.json"
)


class SpecialCases(Enum):
    STRING_MAX_LENGTH = 15
    STRING_SENSITIVE_FILE_PATH = "STRING_SENSITIVE_FILE_PATH"
    STRING_URL = "STRING_URL"
    STRING_FILE_PATH = "STRING_FILE_PATH"
    STRING_IP = "STRING_IP"
    STRING_BASE64 = "STRING_BASE64"
    STRING_HEX = "STRING_HEX"
    STRING_ESCAPED_HEX = "STRING_ESCAPED_HEX"
    MALFORMED_FILE = "MALFORMED_FILE"
    MALFORMED_SYNTAX = "MALFORMED_SYNTAX"
    FILE_READING_ISSUES = "FILE_READING_ISSUES"
    TARGETED_FILE = "TARGETED_FILE"
    INTEGER = "INTEGER"
    FLOAT = "FLOAT"


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
    maliciousness: Optional[float] = None
    code: Optional[str] = None
    codeType: Optional[types.CodeType] = None

    def __init__(
        self,
        name: str,
        language: str,
        file_path: str,
        codeType: types.CodeType = None,
        warnings: List[str] = [],
    ):
        self.name = name
        self.file_path = file_path
        self.warnings = list(warnings)
        self.maliciousness = None
        self.codeType = codeType

        if Path(self.file_path).name in COMMON_TARGET_FILES.get(language, []):
            self.warnings += [SpecialCases.TARGETED_FILE.value]

    @classmethod
    def load_models_into_memory(
        cls, model_path: Optional[str] = None, tokenizer_path: Optional[str] = None
    ) -> None:
        initialize_models(model_path=model_path, tokenizer_path=tokenizer_path)

    @staticmethod
    def tokenize_code_type(
        code_type: Optional[types.CodeType], map_special_tokens: bool = True
    ) -> List[str]:
        if not code_type:
            return []

        flat_instructions: List[str] = []
        all_instructions: List[Tuple[str, str]] = []

        all_instructions = dis.get_instructions(code_type)

        for instruction in all_instructions:
            opname: str = instruction.opname.lower()
            argval: Any = instruction.argval
            original_argrepr: str = (
                instruction.argrepr if instruction.argrepr is not None else ""
            )

            if not map_special_tokens:
                flat_instructions.append(opname)
                flat_instructions.append(str(argval))
                continue

            final_value: str = ""

            if instruction.opcode in dis.hasjabs or instruction.opcode in dis.hasjrel:
                final_value = map_jump_instruction_arg(instruction)
            elif instruction.opname == "LOAD_CONST":
                final_value = map_load_const_number_arg(
                    instruction, argval, original_argrepr
                )
            elif isinstance(argval, str):
                final_value = map_string_arg(argval, original_argrepr)
            elif isinstance(argval, types.CodeType):
                final_value = map_code_object_arg(argval, original_argrepr)
            elif isinstance(argval, tuple):
                final_value = map_tuple_arg(argval, original_argrepr)
            elif isinstance(argval, frozenset):
                final_value = map_frozenset_arg(argval, original_argrepr)
            else:
                final_value = original_argrepr

            flat_instructions.append(opname)
            # Only add final_value if it's meaningful (not None and not an empty string)
            if final_value is not None and str(final_value) != "":
                flat_instructions.append(str(final_value))
        return flat_instructions

    def to_tokens(self, map_special_tokens: bool = True) -> List[str]:
        all_token_parts: List[str] = []
        all_token_parts.extend(self.warnings)
        generated_instructions = MalwiObject.tokenize_code_type(
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
            "path": self.file_path,
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
    ) -> Dict[str, Any]:
        processed_objects_count = len(malwi_files)
        total_maliciousness_score = 0.0
        malicious_objects_count = 0
        files_with_scores_count = 0

        for mf in malwi_files:
            mf.retrieve_source_code()
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

        for mf in malwi_files:
            if mf.maliciousness is not None:
                if mf.maliciousness > malicious_threshold:
                    report_data["details"].append(mf.to_dict())
                elif not malicious_only:
                    report_data["details"].append(mf.to_dict())
            elif not malicious_only:
                report_data["details"].append(mf.to_dict())

        return report_data

    @classmethod
    def to_report_json(
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
        return json.dumps(report_data, indent=4)

    @classmethod
    def to_report_yaml(
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

    @staticmethod
    def _decode_code_object(encoded: str) -> types.CodeType:
        try:
            raw_bytes = base64.b64decode(encoded)
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"Failed to decode base64 string: {e}") from e

        try:
            code_obj = marshal.loads(raw_bytes)
        except (ValueError, TypeError, EOFError) as e:
            raise ValueError(f"Failed to unmarshal code object: {e}") from e

        if not isinstance(code_obj, types.CodeType):
            raise TypeError("Decoded object is not a code object")

        return code_obj

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
                    detail_path = detail.get("path", "") or ""
                    contents = detail.get("contents", [])
                    if not contents:
                        continue
                    for item in contents:
                        name = item.get("name")
                        file_path_val = detail_path
                        instructions = item.get("instructions", [])
                        warnings = item.get("warnings", [])
                        # Normalize instructions to list of str tuples
                        instructions = [(str(op), str(arg)) for op, arg in instructions]

                        codeType = None
                        marshalled_code = item.get("marshalled")
                        if marshalled_code:
                            try:
                                codeType = cls._decode_code_object(marshalled_code)
                            except Exception as e:
                                print(f"Failed to decode code object: {str(e)}")

                        malwi_object = cls(
                            name=name,
                            language=language,
                            file_path=file_path_val,
                            instructions=instructions,
                            warnings=warnings,
                            codeType=codeType,
                        )
                        malwi_objects.append(malwi_object)

        return malwi_objects


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


def map_string_arg(argval: str, original_argrepr: str) -> str:
    prefix = "STRING"
    python_function_mapping = FUNCTION_MAPPING.get("python", {})
    python_import_mapping = IMPORT_MAPPING.get("python", {})

    if argval in python_function_mapping:
        return python_function_mapping.get(argval)
    elif argval in python_import_mapping:
        return argval
    elif argval in SENSITIVE_PATHS:
        return f"{SpecialCases.STRING_SENSITIVE_FILE_PATH.value}"
    elif is_valid_ip(argval):
        return f"{SpecialCases.STRING_IP.value}"
    elif is_valid_url(argval):
        return f"{SpecialCases.STRING_URL.value}"
    elif is_file_path(argval):
        return f"{SpecialCases.STRING_FILE_PATH.value}"
    else:
        if len(argval) <= SpecialCases.STRING_MAX_LENGTH.value:
            return argval
        if is_escaped_hex(argval):
            prefix = SpecialCases.STRING_ESCAPED_HEX.value
        elif is_hex(argval):
            prefix = SpecialCases.STRING_HEX.value
        elif is_base64(argval):
            prefix = SpecialCases.STRING_BASE64.value

        length_suffix = map_string_length_to_token(len(argval))
        try:
            entropy = calculate_shannon_entropy(argval.encode("utf-8", errors="ignore"))
        except Exception:
            entropy = 0.0
        entropy_suffix = map_entropy_to_token(entropy)
        return f"{prefix}_{length_suffix}_{entropy_suffix}"


def map_code_object_arg(argval: types.CodeType, original_argrepr: str) -> str:
    return "OBJECT"


def map_tuple_arg(argval: tuple, original_argrepr: str) -> str:
    result = set()
    for item in argval:
        if isinstance(item, str):
            result.add(str(item))
        elif isinstance(item, int):
            result.add(SpecialCases.INTEGER.value)
        elif isinstance(item, float):
            result.add(SpecialCases.FLOAT.value)
    if not result:
        return ""
    ordered = list(result)
    ordered.sort()
    return " ".join(ordered)


def map_frozenset_arg(argval: frozenset, original_argrepr: str) -> str:
    result = set()
    for item in argval:
        if isinstance(item, str):
            result.add(str(item))
        elif isinstance(item, int):
            result.add(SpecialCases.INTEGER.value)
        elif isinstance(item, float):
            result.add(SpecialCases.FLOAT.value)
    if not result:
        return ""
    ordered = list(result)
    ordered.sort()
    return " ".join(ordered)


def map_jump_instruction_arg(instruction: dis.Instruction) -> Optional[str]:
    return "TO_NUMBER"


def map_load_const_number_arg(
    instruction: dis.Instruction, argval: Any, original_argrepr: str
) -> Optional[str]:
    if isinstance(argval, int):
        return SpecialCases.INTEGER.value
    elif isinstance(argval, float):
        return SpecialCases.FLOAT.value
    elif isinstance(argval, types.CodeType):
        return map_code_object_arg(argval, original_argrepr)
    elif isinstance(argval, str):
        return map_string_arg(argval, original_argrepr)
    return None


def recursively_disassemble_python(
    file_path: str,
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
                warnings=[err_msg],
            )
            all_objects_data.append(object_data)
        if not code_obj and not current_errors:
            all_objects_data.append(
                MalwiObject(
                    name=SpecialCases.MALFORMED_FILE.value,
                    language=language,
                    file_path=file_path,
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
    )
    all_objects_data.append(object_data)

    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            recursively_disassemble_python(
                file_path=file_path,
                language=language,
                code_obj=const,
                all_objects_data=all_objects_data,
                visited_code_ids=visited_code_ids,
            )


def disassemble_python_file(
    file_path_str: str, retrieve_source_code: bool = True
) -> List[MalwiObject]:
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
        disassembled_data: List[MalwiObject] = disassemble_python_file(
            str(py_file), retrieve_source_code=retrieve_source_code
        )
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
