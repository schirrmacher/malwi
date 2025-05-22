#!/usr/bin/env python

import re
import dis
import sys
import csv
import math
import yaml
import json
import types
import socket
import urllib
import inspect
import pathlib
import hashlib
import warnings
import argparse
import collections

from tqdm import tqdm
from enum import Enum
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Set, Optional, Any, Dict


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
    STRING_MAX_LENGTH = 10
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
class MalwiFile:
    name: str
    id_hex: Optional[str]
    file_path: str
    firstlineno: Optional[int]
    instructions: List[Tuple[str, str]]
    warnings: List[str]
    maliciousness: Optional[float] = None
    code: Optional[str] = None

    def __init__(
        self,
        name: str,
        language: str,
        id_hex: Optional[str],
        file_path: str,
        firstlineno: Optional[int],
        instructions: List[Tuple[str, str]],
        warnings: List[str] = [],
        code: Optional[str] = None,
    ):
        self.name = name
        self.id_hex = id_hex
        self.file_path = file_path
        self.firstlineno = firstlineno
        self.instructions = instructions
        self.warnings = list(warnings)
        self.maliciousness = None
        self.code = code

        if Path(self.file_path).name in COMMON_TARGET_FILES.get(language, []):
            self.warnings += [SpecialCases.TARGETED_FILE.value]

    @classmethod
    def load_models_into_memory(
        cls, model_path: Optional[str] = None, tokenizer_path: Optional[str] = None
    ):
        initialize_models(model_path=model_path, tokenizer_path=tokenizer_path)

    def to_tokens(self) -> List[str]:
        instructions: List[Tuple[str, str]] = self.instructions
        all_token_parts: List[str] = []
        all_token_parts.extend(self.warnings)
        for opname, argrepr_val in instructions:
            all_token_parts.append(opname)
            if argrepr_val:
                all_token_parts.append(argrepr_val)
        return all_token_parts

    def to_token_string(self) -> str:
        return " ".join(self.to_tokens())

    def to_string_hash(self) -> str:
        tokens = self.to_token_string()
        encoded_string = tokens.encode("utf-8")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

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
        malwi_files: List["MalwiFile"],
        all_files: List[str],
        malicious_threshold: float = 0.5,
        number_of_skipped_files: int = 0,
        malicious_only: bool = False,
    ) -> Dict[str, Any]:
        """
        Internal helper to compute report data.
        """
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
        malwi_files: List["MalwiFile"],
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
        malwi_files: List["MalwiFile"],
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


def sanitize_identifier(identifier: Optional[str]) -> str:
    if identifier is None:
        return ""
    sanitized_name = re.sub(r"[^a-zA-Z0-9]", ".", identifier)
    sanitized_name = re.sub(r"\.{2,}", ".", sanitized_name)
    sanitized_name = sanitized_name.strip(".")
    return sanitized_name


def map_identifier(
    identifier: Optional[str], language: str, mapping_table: dict
) -> Optional[str]:
    if identifier is None:
        return None
    parts = identifier.split(".")
    for i in range(len(parts)):
        key = ".".join(parts[i:])
        if key in mapping_table.get(language, {}):
            return mapping_table[language].get(key)
    return None


def map_entropy_to_token(entropy: float):
    if entropy <= 1.0:
        return "ENT_LOW"
    elif entropy <= 2.5:
        return "ENT_MED"
    elif entropy <= 5.0:
        return "ENT_HIGH"
    else:
        return "ENT_VHIGH"


def map_string_length_to_token(str_len: int):
    if str_len <= 10:
        return "LEN_XS"
    elif str_len <= 100:
        return "LEN_S"
    elif str_len <= 1000:
        return "LEN_M"
    elif str_len <= 10000:
        return "LEN_L"
    elif str_len <= 100000:
        return "LEN_XL"
    else:
        return "LEN_XXL"


def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    byte_counts = collections.Counter(data)
    entropy = -sum(
        (count / length) * math.log2(count / length) for count in byte_counts.values()
    )
    return entropy


def is_valid_ip(content: str) -> bool:
    if not content or "%" in content:
        return False
    try:
        socket.inet_pton(socket.AF_INET, content)
        return True
    except (socket.error, OSError):
        try:
            socket.inet_pton(socket.AF_INET6, content)
            return True
        except (socket.error, OSError):
            return False
    except Exception:
        return False


def is_valid_url(content: str) -> bool:
    if not content or (":" not in content and "." not in content):
        return False

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", content):
        if content.startswith(("www.", "http.", "https.")):
            content_with_scheme = "http://" + content
        else:
            return False
    else:
        content_with_scheme = content

    try:
        result = urllib.parse.urlparse(content_with_scheme)
        return bool(result.scheme and result.netloc)
    except Exception:
        return False


def is_escaped_hex(s: str) -> bool:
    pattern = re.compile(r"^(?:\\x[0-9a-fA-F]{2})+$")
    return bool(pattern.match(s))


def is_base64(s: str) -> bool:
    base64_char_pattern = re.compile(r"^[A-Za-z0-9+/]*(={0,2})$")
    if not s:
        return False
    return bool(base64_char_pattern.match(s)) and len(s) % 4 == 0


def is_hex(s: str) -> bool:
    hex_char_pattern_strict = re.compile(r"^[A-Fa-f0-9]+$")
    return bool(hex_char_pattern_strict.match(s))


def is_file_path(text: str) -> bool:
    if not text or len(text) < 2:
        return False
    has_separator = "/" in text or "\\" in text
    is_common_non_file_url = text.startswith(
        (
            "http://",
            "https://",
            "ftp://",
            "sftp://",
            "ws://",
            "wss://",
            "mailto:",
            "tel:",
            "data:",
        )
    )
    is_unix_like_start = text.startswith(("/", "~", "./", "../"))
    is_win_drive_start = (
        len(text) > 2
        and text[1] == ":"
        and text[0].isalpha()
        and text[2] in ("\\", "/")
    )
    is_win_unc_start = text.startswith("\\\\")
    return (
        has_separator or is_unix_like_start or is_win_drive_start or is_win_unc_start
    ) and not is_common_non_file_url


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
    all_objects_data: List[MalwiFile] = [],
    visited_code_ids: Optional[Set[int]] = None,
    errors: List[str] = [],
) -> None:
    if errors or not code_obj:
        for err_msg in errors:
            object_data = MalwiFile(
                name=err_msg,
                language=language,
                id_hex=None,
                file_path=file_path,
                firstlineno=None,
                instructions=[],
                warnings=[err_msg],
                code=f"<Not applicable: file error '{err_msg}'>",
            )
            all_objects_data.append(object_data)
        if not code_obj and not errors:
            all_objects_data.append(
                MalwiFile(
                    name=SpecialCases.MALFORMED_FILE.value,
                    language=language,
                    id_hex=None,
                    file_path=file_path,
                    firstlineno=None,
                    instructions=[],
                    warnings=[SpecialCases.MALFORMED_FILE.value],
                    code="<Not applicable: no code object generated>",
                )
            )
        return

    if visited_code_ids is None:
        visited_code_ids = set()

    if id(code_obj) in visited_code_ids:
        return
    visited_code_ids.add(id(code_obj))

    current_instructions_data: List[Tuple[str, str]] = []
    for instruction in dis.get_instructions(code_obj):
        opname: str = instruction.opname.lower()
        argval: Any = instruction.argval
        original_argrepr: str = (
            instruction.argrepr if instruction.argrepr is not None else ""
        )

        final_value = ""

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

        current_instructions_data.append((opname, final_value))

    code: Optional[str] = None
    if code_obj:
        try:
            lines, _ = inspect.getsourcelines(code_obj)
            code = "".join(lines)
        except (OSError, TypeError, IndexError) as e:
            code = f"<source retrieval failed: {type(e).__name__} on {code_obj.co_name or 'unknown_object'}>"
        except Exception as e:
            code = f"<source retrieval error: {type(e).__name__} on {code_obj.co_name or 'unknown_object'}>"

    object_data = MalwiFile(
        name=code_obj.co_name if code_obj else "UnknownObject",
        language=language,
        id_hex=hex(id(code_obj)) if code_obj else None,
        file_path=(code_obj.co_filename if code_obj else file_path),
        firstlineno=code_obj.co_firstlineno if code_obj else None,
        instructions=current_instructions_data,
        code=code,
        warnings=[],
    )
    all_objects_data.append(object_data)

    if code_obj:  # Only recurse if code_obj is valid
        for const in code_obj.co_consts:
            if isinstance(const, types.CodeType):
                recursively_disassemble_python(
                    file_path=file_path,  # Pass the original file_path for context
                    language=language,
                    code_obj=const,
                    all_objects_data=all_objects_data,
                    visited_code_ids=visited_code_ids,
                    errors=[],
                )


def disassemble_python_file(file_path_str: str) -> List[MalwiFile]:
    all_disassembled_data: List[MalwiFile] = []
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


def print_txt_output(all_objects_data: List[MalwiFile], output_stream: Any) -> None:
    for obj_data in all_objects_data:
        # For error entries, id_hex and firstlineno might be None.
        obj_id_hex = obj_data.id_hex if obj_data.id_hex is not None else "<N/A>"
        obj_firstlineno = (
            obj_data.firstlineno if obj_data.firstlineno is not None else "<N/A>"
        )

        print(
            f"\nDisassembly of <code object {obj_data.name} at {obj_id_hex}>:",
            file=output_stream,
        )
        print(
            f'  (file: "{obj_data.file_path}", line: {obj_firstlineno})',
            file=output_stream,
        )
        if obj_data.code and not obj_data.code.startswith("<Not applicable"):
            indented_source = "\n".join(
                ["    " + line for line in obj_data.code.splitlines()]
            )
            print(f"  Source Code:\n{indented_source}", file=output_stream)
        elif obj_data.code:
            print(f"  Source Code: {obj_data.code}", file=output_stream)

        if obj_data.instructions:
            print(f"{'OPNAME':<25} ARGREPR", file=output_stream)
            print(f"{'-' * 25} {'-' * 20}", file=output_stream)
            for opname, argrepr_val in obj_data.instructions:
                print(f"{opname:<25} {argrepr_val}", file=output_stream)
        elif not obj_data.code or obj_data.code.startswith("<Not applicable"):
            print(
                f"  (No instructions, entry likely represents a file/syntax error: {obj_data.name})",
                file=output_stream,
            )


def get_row_data(obj: MalwiFile) -> List[Any]:
    return [
        obj.to_token_string(),
        obj.to_string_hash(),
        obj.file_path,
    ]


def write_csv_rows_for_file_data(
    file_disassembled_data: List[MalwiFile], csv_writer_obj: csv.writer
) -> None:
    for obj in file_disassembled_data:
        csv_writer_obj.writerow(get_row_data(obj))


def print_csv_output_to_stdout(
    all_objects_data: List[MalwiFile], output_stream: Any
) -> None:
    writer = csv.writer(output_stream)
    writer.writerow(["tokens", "hash", "filepath"])
    for obj in all_objects_data:
        writer.writerow(get_row_data(obj))


def process_single_py_file(
    py_file: Path, predict: bool = True
) -> Optional[List[MalwiFile]]:
    try:
        disassembled_data: List[MalwiFile] = disassemble_python_file(str(py_file))
        if predict:
            for d in disassembled_data:
                if d.instructions:
                    d.predict()
        return disassembled_data if disassembled_data else None
    except Exception as e:
        print(
            f"An unexpected error occurred while processing {py_file}: {e}",
            file=sys.stderr,
        )
    return None


def process_input_path(
    input_path: Path, output_format: str, csv_writer_for_file: Optional[csv.writer]
) -> List[MalwiFile]:
    accumulated_data_for_txt_or_stdout_csv: List[MalwiFile] = []
    files_processed_count = 0
    py_files_list = []

    if input_path.is_file():
        if input_path.suffix == ".py":
            py_files_list.append(input_path)
        else:
            print(f"Skipping non-Python file: {input_path}", file=sys.stderr)
    elif input_path.is_dir():
        print(f"--- Searching directory: {input_path.resolve()} ---", file=sys.stderr)
        py_files_list = list(input_path.rglob("*.py"))
        if not py_files_list:
            print(f"No .py files found in directory: {input_path}", file=sys.stderr)
            return accumulated_data_for_txt_or_stdout_csv  # Return empty list
    else:
        print(f"Error: Path is not a file or directory: {input_path}", file=sys.stderr)
        return accumulated_data_for_txt_or_stdout_csv  # Return empty list

    tqdm_desc = (
        f"Processing directory '{input_path.name}'"  # Changed description for clarity
        if input_path.is_dir() and len(py_files_list) > 1
        else f"Processing '{input_path.name}'"
    )

    disable_tqdm = len(py_files_list) <= 1 and input_path.is_file()

    for py_file in tqdm(
        py_files_list,
        desc=tqdm_desc,
        unit="file",
        ncols=100,
        disable=disable_tqdm,
    ):
        try:
            file_disassembled_data = process_single_py_file(py_file, predict=False)
            if file_disassembled_data:
                files_processed_count += 1
                if output_format == "csv" and csv_writer_for_file:
                    write_csv_rows_for_file_data(
                        file_disassembled_data, csv_writer_for_file
                    )
                else:
                    accumulated_data_for_txt_or_stdout_csv.extend(
                        file_disassembled_data
                    )
        except Exception as e:
            print(f"Critical error processing file {py_file}: {e}", file=sys.stderr)

    if files_processed_count == 0 and py_files_list:
        print(
            "No Python files were successfully processed to produce disassemblies from the input path.",
            file=sys.stderr,
        )

    return accumulated_data_for_txt_or_stdout_csv


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
        MalwiFile.load_models_into_memory(
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

    output_stream_target: Any = sys.stdout
    output_file_obj: Optional[Any] = None
    csv_writer_instance: Optional[csv.writer] = None

    if args.save:
        try:
            save_path = Path(args.save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            if args.format == "csv":
                file_exists_before_open = save_path.is_file()
                is_empty = not file_exists_before_open or save_path.stat().st_size == 0
                output_file_obj = open(
                    save_path, "a", newline="", encoding="utf-8", errors="replace"
                )
                csv_writer_instance = csv.writer(output_file_obj)
                if is_empty:
                    csv_writer_instance.writerow(["tokens", "hash", "filepath"])
            else:
                output_file_obj = open(
                    save_path, "w", encoding="utf-8", errors="replace"
                )
                output_stream_target = output_file_obj

            if args.format not in ["csv"]:
                print(
                    f"Output will be saved to: {save_path.resolve()}", file=sys.stderr
                )
            elif args.format == "csv" and output_file_obj != sys.stdout:
                print(
                    f"CSV output will be appended to: {save_path.resolve()}",
                    file=sys.stderr,
                )

        except IOError as e:
            print(
                f"Error: Could not open save path '{args.save}': {e}", file=sys.stderr
            )
            sys.exit(1)
        except Exception as e:
            print(
                f"An unexpected error occurred while preparing save file '{args.save}': {e}",
                file=sys.stderr,
            )
            sys.exit(1)

    collected_data: List[MalwiFile] = []
    try:
        collected_data = process_input_path(
            input_path_obj,
            args.format,
            csv_writer_instance,
        )
    except Exception as e:
        print(
            f"A critical error occurred during path processing for '{input_path_obj}': {e}",
            file=sys.stderr,
        )
        import traceback

        traceback.print_exc(file=sys.stderr)
        if output_file_obj and output_file_obj != sys.stdout:
            output_file_obj.close()
        sys.exit(1)

    if not csv_writer_instance:
        if not collected_data:
            if args.format == "csv" and output_stream_target == sys.stdout:
                print_csv_output_to_stdout([], output_stream_target)
        else:
            if args.format == "txt":
                print_txt_output(collected_data, output_stream_target)
            elif args.format == "csv":  # CSV to stdout
                print_csv_output_to_stdout(collected_data, output_stream_target)
            elif args.format == "json":
                report_json = MalwiFile.to_report_json(
                    collected_data, args.malicious_threshold, 0, args.malicious_only
                )
                output_stream_target.write(report_json + "\n")
            elif args.format == "yaml":
                report_yaml = MalwiFile.to_report_yaml(
                    collected_data, args.malicious_threshold, 0, args.malicious_only
                )
                output_stream_target.write(report_yaml + "\n")

    if output_file_obj and output_file_obj != sys.stdout:
        try:
            output_file_obj.close()
        except Exception as e:
            print(f"Error closing output file '{args.save}': {e}", file=sys.stderr)

    sys.exit(0)


if __name__ == "__main__":
    main()
