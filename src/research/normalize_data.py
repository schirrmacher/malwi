import re
import csv
import math
import socket
import urllib
import hashlib
import pathlib
import logging
import argparse
import collections
from enum import Enum
from tqdm import tqdm
from pathlib import Path
from tree_sitter import Node
from typing import Set, Optional, Dict, Any, List, Tuple

from tree_sitter import Parser, Language
import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
import tree_sitter_typescript as tstypescript
import tree_sitter_rust as tsrust

from common.files import read_json_from_file

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
SOURCE_DIR = pathlib.Path(__file__).resolve().parent.parent

SENSITIVE_PATHS: Set[str] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "sensitive_files.json"
)

NODE_MAPPING: Dict[str, Any] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "node_mapping.json"
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

COMPRESSION_MAPPING: Dict[Tuple[str, ...], str] = read_json_from_file(
    SCRIPT_DIR / "syntax_mapping" / "compression_mapping.json"
)

NODE_TARGETS: Dict[str, Any] = read_json_from_file(
    SOURCE_DIR / "research" / "syntax_mapping" / "node_targets.json"
)

LANGUAGES = {
    "python": tspython.language(),
    "javascript": tsjavascript.language(),
    "typescript": tstypescript.language_typescript(),
    "rust": tsrust.language(),
}

PARSER_INSTANCE: Optional[Parser] = None
CURRENT_LANGUAGE: Optional[str] = None


class SpecialCases(Enum):
    STRING_SENSITIVE_FILE_PATH = "STRING_SENSITIVE_FILE_PATH"
    STRING_URL = "STRING_URL"
    STRING_FILE_PATH = "STRING_FILE_PATH"
    STRING_IP = "STRING_IP"
    STRING_BASE64 = "STRING_BASE64"
    STRING_HEX = "STRING_HEX"
    VERY_LONG_FUNCTION_NAME = "VERY_LONG_FUNCTION_NAME"
    MALFORMED_FILE = "MALFORMED_FILE"


def get_parser_instance(language_name: str) -> Optional[Parser]:
    global PARSER_INSTANCE, CURRENT_LANGUAGE
    if PARSER_INSTANCE is None or CURRENT_LANGUAGE != language_name:
        language_object = LANGUAGES.get(language_name)
        if language_object is None:
            CURRENT_LANGUAGE = PARSER_INSTANCE = None
            return None
        try:
            PARSER_INSTANCE = Parser(Language(language_object))
            CURRENT_LANGUAGE = language_name
        except Exception as e:
            CURRENT_LANGUAGE = PARSER_INSTANCE = None
            logging.warning(f"{language_name} could not be loaded: {e}")
    return PARSER_INSTANCE


def create_malwi_nodes_from_file(file_path: str) -> List["MalwiNode"]:
    extension_mapping = {
        "js": "javascript",
        "ts": "typescript",
        "rs": "rust",
        "py": "python",
    }

    p_file_path = Path(file_path)
    if not p_file_path.is_file():
        # logging.debug(f"Path provided is not a file: {file_path}")
        return []

    extension = p_file_path.suffix.lstrip(".").lower()
    if extension not in extension_mapping:
        # logging.debug(f"Unsupported extension '{extension}' for file {file_path}")
        return []

    language = extension_mapping[extension]

    try:
        with open(file_path, "rb") as f:
            source_bytes = f.read()
    except Exception as e:
        logging.warning(f"Error reading file {file_path}: {e}")
        return []

    return create_malwi_nodes_from_bytes(
        source_code_bytes=source_bytes, file_path=file_path, language=language
    )


def find_functions_recursive(
    node: Node, source_code_bytes: bytes, functions: List[Node]
):
    if node.type == "function_definition":
        functions.append(node)

    for child in node.children:
        find_functions_recursive(child, source_code_bytes, functions)


def create_malwi_nodes_from_bytes(
    source_code_bytes: bytes, file_path: str, language: str
) -> List["MalwiNode"]:
    parser = get_parser_instance(language)
    if parser is None:
        logging.warning(
            f"No parser available for language: {language} for file {file_path}"
        )
        return []
    try:
        tree = parser.parse(source_code_bytes)
    except Exception as e:
        logging.warning(f"Parsing error of file {file_path}: {e}")
        return []

    all_functions = []
    root_node = tree.root_node
    find_functions_recursive(root_node, source_code_bytes, all_functions)

    malwi_nodes = []
    for f in all_functions:
        node = MalwiNode(node=f, language=language, file_path=file_path)
        malwi_nodes.append(node)

    return malwi_nodes


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


def is_base64(s: str) -> bool:
    base64_char_pattern = re.compile(r"^[A-Za-z0-9+/]*(={0,2})$")
    return bool(base64_char_pattern.match(s))


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


def parse_python_string_literal(s: str) -> Optional[Tuple[str, str, str]]:
    pattern = re.compile(
        r"""
        ^
        (?P<prefix>[fFrRbBuU]?)               # Optional prefix
        (?P<quote>'''|\"\"\"|'|\")            # Opening quote
        (?P<content>.*?)                      # Content
        (?P=quote)                            # Closing quote, must match opening
        $
        """,
        re.DOTALL | re.VERBOSE,
    )
    match = pattern.match(s)
    if match:
        content = match.group("content")
        return content
    else:
        return s


def string_node_to_string(node: Node) -> str:
    content = parse_python_string_literal(node.text.decode("utf-8", errors="ignore"))

    prefix = "STRING"

    if content in SENSITIVE_PATHS:
        return f"{prefix}_{SpecialCases.STRING_SENSITIVE_FILE_PATH.value}"
    elif is_valid_ip(content):
        return f"{prefix}_{SpecialCases.STRING_IP.value}"
    elif is_valid_url(content):
        return f"{prefix}_{SpecialCases.STRING_URL.value}"
    elif is_file_path(content):
        return f"{prefix}_{SpecialCases.STRING_FILE_PATH.value}"
    else:
        if is_hex(content):
            prefix = SpecialCases.STRING_HEX.value
        elif is_base64(content):
            prefix = SpecialCases.STRING_BASE64.value

        length_suffix = map_string_length_to_token(len(content))
        raw_bytes = (
            node.text
            if isinstance(node.text, bytes)
            else content.encode("utf-8", errors="ignore")
        )
        if raw_bytes:
            entropy = calculate_shannon_entropy(raw_bytes)
            entropy_suffix = map_entropy_to_token(entropy)
        return f"{prefix}_{length_suffix}_{entropy_suffix}"


def get_recursive_identifier_text(expression_node: Node, language: str) -> str:
    node_type = expression_node.type
    node_text = expression_node.text.decode("utf8")
    if language == "python":
        if node_type == "identifier":
            return node_text
        elif node_type == "attribute":
            object_node = expression_node.child_by_field_name("value")
            attribute_node = expression_node.child_by_field_name("attribute")
            if object_node and attribute_node:
                base = get_recursive_identifier_text(object_node, language)
                return f"{base}.{attribute_node.text.decode('utf8')}"
    elif language == "javascript":
        if node_type == "identifier":
            return node_text
        elif node_type == "member_expression":
            object_node = expression_node.child_by_field_name("object")
            property_node = expression_node.child_by_field_name("property")
            if object_node and property_node:
                base = get_recursive_identifier_text(object_node, language)
                return f"{base}.{property_node.text.decode('utf8')}"
    return node_text


def call_node_to_parameters_string(
    call_node: Node, language: str, mapping_table: Dict[str, Dict[str, str]]
) -> List[str]:
    processed_args: List[str] = []
    arguments_node = call_node.child_by_field_name("arguments")
    arg_count = None
    if arguments_node:
        arg_count = len(arguments_node.named_children)
        for arg_node in arguments_node.named_children:
            if arg_node.type == "string":
                string = string_node_to_string(arg_node)
                processed_args.append(string)
            elif arg_node.type in ["call"]:
                string, _ = function_node_to_string(
                    arg_node, language=language, mapping_table=mapping_table
                )
                processed_args.append(string)

    return processed_args, arg_count


def function_node_to_string(
    node: Node, language, mapping_table: Dict[str, Dict[str, str]]
) -> Tuple[str, bool]:
    postfix = ""
    param_count = None
    raw_name = ""
    if node.type == "function_definition":
        name_node = node.child_by_field_name("name")
        if not name_node:
            for child in node.named_children:
                if child.type == "identifier":
                    name_node = child
                    break
        if name_node:
            raw_name = name_node.text.decode("utf8")

    elif node.type in ["call", "call_expression"]:
        params, param_count = call_node_to_parameters_string(
            call_node=node, language=language, mapping_table=mapping_table
        )
        postfix = " ".join(params)

        callee_node = node.child_by_field_name("function")
        if not callee_node:
            callee_node = node.child_by_field_name("callee")

        if callee_node:
            raw_name = get_recursive_identifier_text(callee_node, language=language)

    elif node.type in ["lambda", "lambda_expression", "arrow_function"]:
        parent = node.parent
        if (
            language == "python"
            and parent
            and parent.type == "assignment"
            and parent.child_by_field_name("left").type == "identifier"
        ):
            raw_name = parent.child_by_field_name("left").text.decode("utf8")
        elif (
            language == "javascript"
            and parent
            and parent.type == "variable_declarator"
            and parent.child_by_field_name("name").type == "identifier"
        ):
            raw_name = parent.child_by_field_name("name").text.decode("utf8")
        else:
            raw_name = ""

    sanitized_name = sanitize_identifier(raw_name)
    mapped_value = map_identifier(
        identifier=sanitized_name, language=language, mapping_table=mapping_table
    )
    if not param_count:
        param_count = ""
    if mapped_value:
        return f"{mapped_value}{param_count} {postfix}", True
    elif sanitized_name and len(sanitized_name) > 30:
        return (
            f"{SpecialCases.VERY_LONG_FUNCTION_NAME.value}{param_count} {postfix}",
            False,
        )
    elif sanitized_name:
        return f"{sanitized_name}{param_count} {postfix}", False
    else:
        return "", False


def node_to_string_recursive(
    node: Optional[Node],
    language: str,
    indent_level: int = 0,
) -> str:
    if node is None or node.type is None:
        return ""

    node_dict = NODE_MAPPING.get(language, {})
    node_mapping = node_dict.get(node.type)

    if not node_mapping:
        return ""

    final_string = ""
    indent = "  " * indent_level

    if node.type == "string":
        final_string += f"{indent}{string_node_to_string(node)}\n"
    elif node.type in [
        "import_statement",
        "import_from_statement",
        "future_import_statement",
        "import_prefix",
        "relative_import",
        "dotted_name",
        "aliased_import",
        "wildcard_import",
    ]:
        result, mapped = function_node_to_string(
            node, language=language, mapping_table=FUNCTION_MAPPING
        )
        if mapped:
            final_string += f"{indent}{node_mapping}_{result}\n"
        else:
            final_string += f"{indent}{node_mapping} {result}\n"

    elif node.type in ["function_definition", "call", "lambda"]:
        result, mapped = function_node_to_string(
            node, language=language, mapping_table=FUNCTION_MAPPING
        )
        if mapped:
            final_string += f"{indent}{node_mapping}_{result}\n"
        else:
            final_string += f"{indent}{node_mapping} {result}\n"
    else:
        final_string += f"{indent}{node_mapping}\n"

    if hasattr(node, "children"):
        for child in node.children:
            final_string += node_to_string_recursive(
                child,
                language=language,
                indent_level=indent_level + 1,
            )

    return final_string


class MalwiNode:
    def __init__(
        self,
        node: Optional[Node],
        file_path: str,
        language: str = "unknown",
        warnings: List[str] = [],
    ):
        self.node = node
        self.file_path = file_path
        self.language = language
        self.warnings = warnings
        if Path(file_path).name in COMMON_TARGET_FILES.get(language, []):
            self.warnings = warnings + ["TARGET_FILE"]

    def to_string(self, one_line: bool = True) -> str:
        if self.node is None:
            return ""
        result = node_to_string_recursive(self.node, language=self.language)
        if self.warnings:
            warnings = "\n".join(self.warnings)
            result = f"{warnings}\n{result}"
        if one_line:
            return re.sub(r"\s+", " ", result).strip()
        return result

    def to_string_hash(self) -> str:
        node_string = self.to_string(one_line=True)
        encoded_string = node_string.encode("utf-8")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()


def process_source_file(
    file_path: str,
) -> List[MalwiNode]:
    return create_malwi_nodes_from_file(file_path=str(file_path))


def main():
    logging.basicConfig(level=logging.WARNING)

    cli_parser = argparse.ArgumentParser(
        description="Parse source code files and output AST node info to a CSV. Remember to download source files first."
    )
    cli_parser.add_argument(
        "--option",
        "-o",
        required=True,
        choices=["benign", "malicious"],
        help="Specify whether to process benign or malicious repositories. This determines the input directory and output file name.",
    )
    cli_parser.add_argument(
        "-e",
        "--extensions",
        nargs="*",
        default=None,
        help="Filter by specific file extensions (e.g., py js ts). Processes all supported if not specified.",
    )

    args = cli_parser.parse_args()

    if args.option == "benign":
        output_csv_file = "benign.csv"
        input_directory_str = ".repo_cache/benign_repos"
    elif args.option == "malicious":
        output_csv_file = "malicious.csv"
        input_directory_str = ".repo_cache/malicious_repos"
    else:
        print("Error: Invalid --option specified. Choose 'benign' or 'malicious'.")
        return

    input_path = Path(input_directory_str)
    all_collected_nodes: List[MalwiNode] = []

    user_specified_extensions = None
    if args.extensions is not None:
        user_specified_extensions = [ext.lower().lstrip(".") for ext in args.extensions]
        if not user_specified_extensions and args.extensions == []:
            print(
                "Warning: --extensions flag was used with no specific extensions. No files will be processed based on extension filter."
            )

    if not input_path.exists():
        print(f"Error: Path does not exist: {input_path}")
        return

    if not input_path.is_dir():
        print(f"Error: Expected input path to be a directory: {input_path}")
        return

    print(f"Scanning directory: {input_path}...")
    files_to_process = []
    all_items_in_dir = list(input_path.rglob("*"))
    print(f"Found {len(all_items_in_dir)} items. Filtering files...")
    for item_path in tqdm(all_items_in_dir, desc="Discovering files", unit="item"):
        if item_path.is_file():
            files_to_process.append(item_path)

    if not files_to_process:
        print(f"No files found in the specified directory: {input_path}")
        return

    print(
        f"Found {len(files_to_process)} potential files to process from {input_path}."
    )

    processed_files_count = 0
    for p_file_path in tqdm(
        files_to_process, desc="Processing source files", unit="file"
    ):
        file_extension = p_file_path.suffix.lstrip(".").lower()

        if user_specified_extensions is not None:
            if file_extension not in user_specified_extensions:
                continue

        supported_extensions_map = {
            "js": "javascript",
            "ts": "typescript",
            "rs": "rust",
            "py": "python",
        }
        if file_extension not in supported_extensions_map:
            continue

        nodes = process_source_file(file_path=str(p_file_path))
        if nodes:
            all_collected_nodes.extend(nodes)
            processed_files_count += 1

    if not all_collected_nodes:
        print("No processable files found matching criteria or no AST nodes extracted.")
        if (
            processed_files_count == 0
            and user_specified_extensions is not None
            and files_to_process
        ):
            print(
                f"No files matched the specified extensions: {user_specified_extensions} or were supported for processing."
            )
        return

    try:
        print(f"Writing {len(all_collected_nodes)} AST nodes to {output_csv_file}...")
        with open(output_csv_file, "w", newline="", encoding="utf-8") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["ast", "hash", "file"])
            for n in tqdm(all_collected_nodes, desc="Writing CSV", unit="node"):
                csv_writer.writerow([n.to_string(), n.to_string_hash(), n.file_path])
        print(
            f"Successfully wrote AST data from {processed_files_count} file(s) ({len(all_collected_nodes)} nodes) to {output_csv_file}"
        )
    except IOError as e:
        print(f"Error writing to CSV file {output_csv_file}: {e}")


if __name__ == "__main__":
    main()
