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
import pathlib
import hashlib
import warnings
import argparse
import collections

from tqdm import tqdm
from enum import Enum
from pathlib import Path
from dataclasses import dataclass, field
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
    id_hex: str
    file_path: str
    firstlineno: int
    instructions: List[Tuple[str, str]]
    warnings: List[str]
    maliciousness: Optional[float] = None

    def __init__(
        self,
        name: str,
        language: str,
        id_hex: str,
        filename: str,
        firstlineno: int,
        instructions: List[Tuple[str, str]],
        warnings: List[str] = [],
    ):
        self.name = name
        self.id_hex = id_hex
        self.file_path = filename
        self.firstlineno = firstlineno
        self.instructions = instructions
        self.warnings = list(warnings)  # copy list to prevent list sharing
        if Path(filename).name in COMMON_TARGET_FILES.get(language, []):
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
        return {
            "path": self.file_path,
            "contents": [
                {
                    "name": self.name,
                    "score": self.maliciousness,
                    "tokens": self.to_token_string(),
                    "code": "<tbd>",
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


def map_file_site_to_token(str_len: int):  # Unused function
    if str_len <= 100:
        return "FILE_LEN_XS"
    elif str_len <= 1000:
        return "FILE_LEN_S"
    elif str_len <= 10000:
        return "FILE_LEN_M"
    elif str_len <= 100000:
        return "FILE_LEN_L"
    elif str_len <= 1000000:
        return "FILE_LEN_XL"
    else:
        return "FILE_LEN_XXL"


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


def parse_python_string_literal(
    s: str,
) -> Optional[Tuple[str, str, str]]:  # Unused function
    pattern = re.compile(
        r"""
        ^
        (?P<prefix>[fFrRbBuU]?)
        (?P<quote>'''|\"\"\"|'|\")
        (?P<content>.*?)
        (?P=quote)
        $
        """,
        re.DOTALL | re.VERBOSE,
    )
    match = pattern.match(s)
    if match:
        return match.group("content")
    else:
        return s


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
    if instruction.opcode in dis.hasjabs or instruction.opcode in dis.hasjrel:
        return "TO_NUMBER"
    return None


def map_load_const_number_arg(
    instruction: dis.Instruction, argval: Any, original_argrepr: str
) -> Optional[str]:
    if instruction.opname == "LOAD_CONST":
        if isinstance(argval, int):
            return SpecialCases.INTEGER.value
        elif isinstance(argval, float):
            return SpecialCases.INTEGER.value
        elif isinstance(argval, types.CodeType):
            return map_code_object_arg(argval, original_argrepr)
        else:
            return None
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
        for w in errors:
            object_data = MalwiFile(
                name=w,
                language=language,
                id_hex=None,
                filename=file_path,
                firstlineno=None,
                instructions=[],
            )
            all_objects_data.append(object_data)
        return

    if visited_code_ids is None:
        visited_code_ids = set()

    if id(code_obj) in visited_code_ids:
        return
    visited_code_ids.add(id(code_obj))

    current_instructions_data: List[Tuple[str, str]] = []
    for instruction in dis.get_instructions(code_obj):
        opname: str = instruction.opname
        argval: Any = instruction.argval
        original_argrepr: str = (
            instruction.argrepr if instruction.argrepr is not None else ""
        )
        mapped_value: str

        mapped_by_jump = map_jump_instruction_arg(instruction)
        mapped_by_load_const = map_load_const_number_arg(
            instruction, argval, original_argrepr
        )

        if mapped_by_jump is not None:
            mapped_value = mapped_by_jump
        elif mapped_by_load_const is not None:
            mapped_value = mapped_by_load_const
        elif isinstance(argval, str):
            mapped_value = map_string_arg(argval, original_argrepr)
        elif isinstance(argval, types.CodeType):
            mapped_value = map_code_object_arg(argval, original_argrepr)
        elif isinstance(argval, tuple):
            mapped_value = map_tuple_arg(argval, original_argrepr)
        elif isinstance(argval, frozenset):
            mapped_value = map_frozenset_arg(argval, original_argrepr)
        else:
            mapped_value = original_argrepr
        current_instructions_data.append((opname, mapped_value))

    object_data = MalwiFile(
        name=code_obj.co_name,
        language=language,
        id_hex=hex(id(code_obj)),
        filename=code_obj.co_filename,
        firstlineno=code_obj.co_firstlineno,
        instructions=current_instructions_data,
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


def disassemble_python_file(file_path_str: str) -> List[MalwiFile]:
    all_disassembled_data: List[MalwiFile] = []
    source_code: str

    errors: List[str] = []

    try:
        with open(file_path_str, "r", encoding="utf-8", errors="replace") as f:
            source_code = f.read()
    except Exception:
        errors.append(SpecialCases.FILE_READING_ISSUES.value)

    top_level_code_object = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            top_level_code_object: types.CodeType = compile(
                source_code, file_path_str, "exec"
            )
    except UnicodeDecodeError:
        errors.append(SpecialCases.MALFORMED_FILE.value)
    except SyntaxError:
        errors.append(SpecialCases.MALFORMED_SYNTAX.value)
    except Exception:
        errors.append(SpecialCases.MALFORMED_FILE.value)

    recursively_disassemble_python(
        file_path=file_path_str,
        language="python",
        code_obj=top_level_code_object,
        all_objects_data=all_disassembled_data,
        errors=errors,
    )
    return all_disassembled_data


def print_txt_output(all_objects_data: List[MalwiFile], output_stream: Any) -> None:
    for obj_data in all_objects_data:
        print(
            f"\nDisassembly of <code object {obj_data.name} at {obj_data.id_hex}>:",
            file=output_stream,
        )
        print(
            f'  (file: "{obj_data.file_path}", line: {obj_data.firstlineno})',
            file=output_stream,
        )
        print(f"{'OPNAME':<25} ARGREPR", file=output_stream)
        print(f"{'-' * 25} {'-' * 20}", file=output_stream)
        for opname, argrepr_val in obj_data.instructions:
            print(f"{opname:<25} {argrepr_val}", file=output_stream)


def write_csv_rows_for_file_data(
    file_disassembled_data: List[MalwiFile], csv_writer_obj: csv.writer
) -> None:
    """Writes CSV rows for the disassembled data of a single file."""
    if not file_disassembled_data:
        return
    for obj_data in file_disassembled_data:
        concatenated_tokens_string = obj_data.to_token_string()
        sha256_hash: str = obj_data.to_string_hash()
        csv_writer_obj.writerow(
            [concatenated_tokens_string, sha256_hash, obj_data.file_path]
        )


def print_csv_output_to_stdout(
    all_objects_data: List[MalwiFile], output_stream: Any
) -> None:
    """Prints all collected disassembled data to a CSV stream (typically stdout)."""
    writer = csv.writer(output_stream)
    writer.writerow(["tokens", "hash", "filepath"])
    if not all_objects_data:
        return
    for obj_data in all_objects_data:
        concatenated_tokens_string = obj_data.to_token_string()
        sha256_hash: str = obj_data.to_string_hash()
        writer.writerow([concatenated_tokens_string, sha256_hash, obj_data.file_path])


def process_single_py_file(py_file: Path) -> Optional[List[MalwiFile]]:
    try:
        disassembled_data: List[MalwiFile] = disassemble_python_file(str(py_file))
        return disassembled_data if disassembled_data else None
    except Exception as e:
        import traceback

        print(
            f"An unexpected error occurred while processing {py_file}: {e}",
            file=sys.stderr,
        )
        traceback.print_exc(file=sys.stderr)
    return None


def process_input_path(
    input_path: Path, output_format: str, csv_writer_for_file: Optional[csv.writer]
) -> List[MalwiFile]:
    """
    Processes a single Python file or all Python files in a directory.
    If csv_writer_for_file is provided, data is written incrementally.
    Otherwise, data is accumulated and returned.
    """
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
            return accumulated_data_for_txt_or_stdout_csv
    else:
        print(f"Error: Path is not a file or directory: {input_path}", file=sys.stderr)
        return accumulated_data_for_txt_or_stdout_csv

    tqdm_desc = (
        f"Processing '{input_path.name}'"
        if len(py_files_list) > 1 or input_path.is_dir()
        else "Processing file"
    )

    for py_file in tqdm(
        py_files_list,
        desc=tqdm_desc,
        unit="file",
        ncols=100,
        disable=len(py_files_list) <= 1 and not input_path.is_dir(),
    ):
        if input_path.is_file() and len(py_files_list) == 1:
            print(f"--- Analyzing file: {py_file.resolve()} ---", file=sys.stderr)

        try:
            file_disassembled_data = process_single_py_file(py_file)
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
            print(f"{input_path} {e}")

    if files_processed_count == 0 and py_files_list:
        print(
            "No Python files were successfully processed from the input path.",
            file=sys.stderr,
        )

    return accumulated_data_for_txt_or_stdout_csv


def main() -> None:
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Recursively disassemble Python file(s). Various argreprs are replaced.",
        epilog="Example: python %(prog)s your_script.or_directory --format csv --save output.csv",
    )
    parser.add_argument(
        "path", metavar="PATH", help="The Python file or directory to process."
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        choices=["txt", "csv"],
        default="txt",
        help="Output format (default: txt)",
    )
    parser.add_argument(
        "-s",
        "--save",
        type=str,
        default=None,
        metavar="FILEPATH",
        help="Path to save the output. If not provided, output goes to stdout.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 2.5")

    args: argparse.Namespace = parser.parse_args()
    input_path_obj: Path = Path(args.path)

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
            print(f"Output will be saved to: {save_path.resolve()}", file=sys.stderr)
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

    collected_data_for_final_print: List[MalwiFile] = []
    try:
        collected_data_for_final_print = process_input_path(
            input_path_obj, args.format, csv_writer_instance
        )
    except Exception as e:
        print(
            f"A critical error occurred during path processing: {input_path_obj} {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not csv_writer_instance:
        if not collected_data_for_final_print:
            if args.format == "csv" and output_stream_target == sys.stdout:
                print_csv_output_to_stdout([], output_stream_target)
        else:
            if args.format == "txt":
                print_txt_output(collected_data_for_final_print, output_stream_target)
            elif args.format == "csv":
                print_csv_output_to_stdout(
                    collected_data_for_final_print, output_stream_target
                )

    if output_file_obj:
        output_file_obj.close()
    sys.exit(0)


if __name__ == "__main__":
    main()
