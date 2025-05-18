import io
import re
import sys
import csv
import math
import json
import yaml
import string
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
from collections import defaultdict
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
    STRING_ESCAPED_HEX = "STRING_HEX"
    VERY_LONG_FUNCTION_NAME = "VERY_LONG_FUNCTION_NAME"
    VERY_LONG_IMPORT_NAME = "VERY_LONG_IMPORT_NAME"
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
        return []

    extension = p_file_path.suffix.lstrip(".").lower()
    if extension not in extension_mapping:
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


def find_global_scope_function_calls_recursive(
    node: Node,
    source_code_bytes: bytes,
    function_calls_found: List[Node],
    is_currently_inside_function_def: bool,
):
    FUNCTION_CALL_NODE_TYPE = "call"
    FUNCTION_DEFINITION_NODE_TYPE = "function_definition"

    if node.type == FUNCTION_CALL_NODE_TYPE:
        if not is_currently_inside_function_def:
            function_calls_found.append(node)
    pass_down_status = is_currently_inside_function_def
    if node.type == FUNCTION_DEFINITION_NODE_TYPE:
        pass_down_status = True

    for child_node in node.children:
        find_global_scope_function_calls_recursive(
            child_node, source_code_bytes, function_calls_found, pass_down_status
        )


def find_functions_recursive(
    node: Node, source_code_bytes: bytes, functions: List[Node]
):
    if node.type == "function_definition":
        functions.append(node)

    for child in node.children:
        find_functions_recursive(child, source_code_bytes, functions)


def find_calls_outside_functions_recursive(
    node: Node, source_code_bytes: bytes, imports: List[Node]
):
    if node.type in [
        "import_statement",
        "import_from_statement",
        "future_import_statement",
        "import_prefix",
        "relative_import",
        "dotted_name",
        "aliased_import",
        "wildcard_import",
    ]:
        imports.append(node)

    for child in node.children:
        find_imports_recursive(child, source_code_bytes, imports)


def find_imports_recursive(node: Node, source_code_bytes: bytes, imports: List[Node]):
    if node.type in [
        "import_statement",
        "import_from_statement",
        "future_import_statement",
        "import_prefix",
        "relative_import",
        "dotted_name",
        "aliased_import",
        "wildcard_import",
    ]:
        imports.append(node)

    for child in node.children:
        find_imports_recursive(child, source_code_bytes, imports)


ALL_PYTHON_IDENTIFIERS = set(
    [
        "aliased_import",
        "argument_list",
        "as_pattern_target",
        "as_pattern",
        "as",
        "assert_statement",
        "assignment",
        "attribute",
        "augmented_assignment",
        "await",
        "binary_operator",
        "block",
        "boolean_operator",
        "break_statement",
        "call",
        "case_clause",
        "case_pattern",
        "chevron",
        "class_definition",
        "class_pattern",
        "comment",
        "comparison_operator",
        "complex_pattern",
        "concatenated_string",
        "conditional_expression",
        "constrained_type",
        "continue_statement",
        "decorated_definition",
        "decorator",
        "default_parameter",
        "delete_statement",
        "dict_pattern",
        "dictionary_comprehension",
        "dictionary_splat_pattern",
        "dictionary_splat",
        "dictionary",
        "dotted_name",
        "elif_clause",
        "ellipsis",
        "else_clause",
        "escape_interpolation",
        "escape_sequence",
        "except_clause",
        "except_group_clause",
        "exec_statement",
        "expression_list",
        "expression_statement",
        "expression",
        "false",
        "finally_clause",
        "float",
        "for_in_clause",
        "for_statement",
        "format_specifier",
        "function_definition",
        "future_import_statement",
        "generator_expression",
        "generic_type",
        "global_statement",
        "identifier",
        "if_clause",
        "if_statement",
        "import_from_statement",
        "import_prefix",
        "import_statement",
        "integer",
        "interpolation",
        "keyword_argument",
        "keyword_identifier",
        "keyword_pattern",
        "keyword_separator",
        "lambda_parameters",
        "lambda_within_for_in_clause",
        "lambda",
        "line_continuation",
        "list_comprehension",
        "list_pattern",
        "list_splat_pattern",
        "list_splat",
        "list",
        "match_statement",
        "member_type",
        "module",
        "named_expression",
        "none",
        "nonlocal_statement",
        "not_operator",
        "pair",
        "parameter",
        "parameters",
        "parenthesized_expression",
        "parenthesized_list_splat",
        "pass_statement",
        "pattern_list",
        "pattern",
        "positional_separator",
        "primary_expression",
        "print_statement",
        "raise_statement",
        "relative_import",
        "return_statement",
        "set_comprehension",
        "set",
        "slice",
        "splat_pattern",
        "splat_type",
        "string_content",
        "string_end",
        "string_start",
        "string",
        "subscript",
        "true",
        "try_statement",
        "tuple_pattern",
        "tuple",
        "type_alias_statement",
        "type_conversion",
        "type_parameter",
        "type",
        "typed_default_parameter",
        "typed_parameter",
        "unary_operator",
        "union_pattern",
        "union_type",
        "while_statement",
        "wildcard_import",
        "with_clause",
        "with_item",
        "with_statement",
        "yield",
    ]
)


def syntax_tree_to_tokens(node: Node, language=str, _result_list=None):
    sys.setrecursionlimit(100000)

    if _result_list is None:
        _result_list = []

    allow_list = [
        "string_content",
        "integer",
        "lambda",
        "lambda_within_for_in_clause",
        "identifier",
        "float",
        "true",
        "false",
        "none",
        "yield",
    ]

    def process_child(child_node):
        child_tokens = []
        syntax_tree_to_tokens(child_node, language=language, _result_list=child_tokens)
        merged_token = "".join(str(token) for token in child_tokens)

        if len(merged_token) < 43:
            _result_list.append(merged_token)
        else:
            _result_list.extend(child_tokens)

    if node.type == ",":
        # To make CSV files parsable
        _result_list.append(";")
    elif node.type == "call":
        result, mapped = function_node_to_string(
            node, language=language, mapping_table=FUNCTION_MAPPING
        )
        _result_list.append(result if mapped else "F")

    elif node.type == "identifier":
        try:
            token = "V"
            _result_list.append(token)
        except AttributeError:
            _result_list.append(SpecialCases.MALFORMED_FILE)
        except UnicodeDecodeError:
            _result_list.append(SpecialCases.MALFORMED_FILE)
    elif node.type == "string_content":
        try:
            token = string_node_to_string(node)
            _result_list.append(token)
        except AttributeError:
            _result_list.append(SpecialCases.MALFORMED_FILE)
        except UnicodeDecodeError:
            _result_list.append(SpecialCases.MALFORMED_FILE)
    elif node.type not in ALL_PYTHON_IDENTIFIERS.difference(allow_list):
        _result_list.append(node.type)

    children_processed_specially = False
    if node.type in ["assignment", "pair"] and node.child_count >= 2:
        left_child = node.child_by_field_name("left")
        right_child = node.child_by_field_name("right")
        if left_child and right_child:
            process_child(left_child)
            process_child(right_child)
            children_processed_specially = True
        else:
            key_child = node.child_by_field_name("key")
            value_child = node.child_by_field_name("value")
            if key_child and value_child:
                process_child(key_child)
                process_child(value_child)
                children_processed_specially = True

    elif node.type == "class_definition":
        name_node = node.child_by_field_name("name")
        body_node = node.child_by_field_name("body")
        if name_node:
            process_child(name_node)
        if body_node:
            process_child(body_node)
        children_processed_specially = True

    elif node.type == "function_definition":
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        body_node = node.child_by_field_name("body")
        if name_node:
            process_child(name_node)
        if params_node:
            process_child(params_node)
        if body_node:
            process_child(body_node)
        children_processed_specially = True

    if not children_processed_specially:
        for child in node.children:
            process_child(child)

    return _result_list


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

    root_node = tree.root_node

    all_functions = []
    find_functions_recursive(root_node, source_code_bytes, all_functions)

    all_global_func_calls = []
    find_global_scope_function_calls_recursive(
        root_node,
        source_code_bytes,
        all_global_func_calls,
        is_currently_inside_function_def=False,
    )

    all_imports = []
    find_imports_recursive(root_node, source_code_bytes, all_imports)

    malwi_nodes = []

    for f in all_global_func_calls:
        node = MalwiNode(
            node=f,
            language=language,
            file_byte_size=len(source_code_bytes),
            file_path=file_path,
            imports=all_imports,
        )
        malwi_nodes.append(node)

    for f in all_functions:
        node = MalwiNode(
            node=f,
            language=language,
            file_byte_size=len(source_code_bytes),
            file_path=file_path,
            imports=all_imports,
        )
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


def map_file_site_to_token(str_len: int):
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
    content = parse_python_string_literal(_get_node_text(node))

    prefix = "STRING"

    if content in SENSITIVE_PATHS:
        return f"{SpecialCases.STRING_SENSITIVE_FILE_PATH.value}"
    elif is_valid_ip(content):
        return f"{SpecialCases.STRING_IP.value}"
    elif is_valid_url(content):
        return f"{SpecialCases.STRING_URL.value}"
    elif is_file_path(content):
        return f"{SpecialCases.STRING_FILE_PATH.value}"
    else:
        if is_escaped_hex(_get_node_text(node)):
            prefix = SpecialCases.STRING_ESCAPED_HEX.value
        elif is_hex(content):
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
    node_text = _get_node_text(expression_node)
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


def _get_node_text(node: Optional[Node]) -> str:
    """Safely get text from a node."""
    try:
        if node:
            return node.text.decode("utf8")
    except Exception:
        return ""
    return ""


def _get_node_name(node: Optional[Node]):
    name_node = node.child_by_field_name("name")
    if name_node:
        return _get_node_text(name_node)
    return ""


def import_node_to_string(
    node: Node,
    language: str,
    mapping_table: Dict[str, Dict[str, str]],
    disable_import_names: bool = False,
) -> Tuple[str, bool]:
    collected_raw_names: List[str] = []

    if node.type == "import_statement":
        # For "import a, b.c as d":
        # node.named_children usually gives the sequence of imported items.
        # These are already the original module names.
        for item_node in node.named_children:
            raw_item_name = ""
            if item_node.type == "aliased_import":
                original_name_node = item_node.child_by_field_name("name")
                raw_item_name = _get_node_text(original_name_node)
            elif item_node.type in ["dotted_name", "identifier"]:
                raw_item_name = _get_node_text(item_node)

            if raw_item_name:
                collected_raw_names.append(raw_item_name)

    elif node.type == "import_from_statement":
        module_name_node = node.child_by_field_name("module_name")
        raw_module_name = ""
        # This flag is True if module_name_node.type is 'relative_import'
        # e.g., for "from . import X" or "from ..sub import Y"
        is_module_name_explicitly_relative = False

        if module_name_node:
            raw_module_name = _get_node_text(module_name_node)
            # The type 'relative_import' is standard in tree-sitter Python grammar
            # for parts like '.', '..', '.module', '..module'.
            if module_name_node.type == "relative_import":
                is_module_name_explicitly_relative = True

        # Use the original robust check for wildcard imports
        is_wildcard = any(child.type == "wildcard_import" for child in node.children)

        if is_wildcard:
            # For "from module import *", add "module".
            # For "from .module import *", add ".module".
            # For "from . import *" or "from .. import *", raw_module_name would be "." or "..".
            # We add raw_module_name unless it's purely "." or "..", as these don't usually represent
            # the kind of "original module name like os, logging" the user is after.
            if raw_module_name and raw_module_name not in [".", ".."]:
                collected_raw_names.append(raw_module_name)
        else:  # Not a wildcard import (e.g., "from module import name1, name2 as alias2")
            imported_names_structure_node = node.child_by_field_name("name")

            if imported_names_structure_node:
                items_to_extract_from: List[Node] = []
                node_type = imported_names_structure_node.type

                # Use your original logic for populating items_to_extract_from,
                # as it's tailored to your AST structure.
                if node_type in ["identifier", "dotted_name", "aliased_import"]:
                    items_to_extract_from.append(imported_names_structure_node)
                elif node_type == "import_list":
                    items_to_extract_from.extend(
                        imported_names_structure_node.named_children
                    )
                elif node_type == "parenthesized_import_list":
                    actual_list_node = imported_names_structure_node
                    if imported_names_structure_node.named_child_count > 0:
                        potential_inner_list = (
                            imported_names_structure_node.named_child(0)
                        )
                        if (
                            potential_inner_list
                            and potential_inner_list.type == "import_list"
                        ):
                            actual_list_node = potential_inner_list
                    items_to_extract_from.extend(actual_list_node.named_children)

                for item_node in items_to_extract_from:
                    # Skip non-node elements like commas if they appear in named_children
                    # (defensive check, depends on specific tree-sitter grammar details)
                    if item_node.type in [",", "(", ")"]:
                        continue

                    raw_item_name = ""  # This will be the original imported name, e.g., 'name' from 'name as alias'
                    if item_node.type == "aliased_import":
                        original_name_node = item_node.child_by_field_name("name")
                        raw_item_name = _get_node_text(original_name_node)
                    elif item_node.type in ["identifier", "dotted_name"]:
                        raw_item_name = _get_node_text(item_node)

                    if raw_item_name:
                        # CORE CHANGE: Add the module name first, then the item name,
                        # but only if the module name was specified (raw_module_name is not empty)
                        # AND it was not an explicitly relative import (like "from .something ...").
                        if raw_module_name and not is_module_name_explicitly_relative:
                            collected_raw_names.append(raw_module_name)
                        collected_raw_names.append(raw_item_name)

    # Process collected names (sanitization, mapping, handling long names)
    # This part of your logic remains unchanged.
    processed_final_names: List[str] = []
    overall_was_mapped = False

    for rn in collected_raw_names:
        sanitized_name = sanitize_identifier(rn)  # Your sanitize_identifier
        if not sanitized_name:
            continue

        mapped_value = map_identifier(  # Your map_identifier
            identifier=sanitized_name,
            language=language,
            mapping_table=mapping_table,
        )

        if mapped_value:
            processed_final_names.append(mapped_value)
            overall_was_mapped = True
        elif sanitized_name and not disable_import_names:
            processed_final_names.append(sanitized_name)

    final_joined_str = " ".join(processed_final_names)
    return final_joined_str, overall_was_mapped


def function_node_to_string(
    node: Node,
    language,
    mapping_table: Dict[str, Dict[str, str]],
    disable_function_names: bool = False,
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
            raw_name = _get_node_text(name_node)

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
            raw_name = _get_node_text(parent.child_by_field_name("left"))
        elif (
            language == "javascript"
            and parent
            and parent.type == "variable_declarator"
            and parent.child_by_field_name("name").type == "identifier"
        ):
            raw_name = _get_node_text(parent.child_by_field_name("name"))
        else:
            raw_name = ""

    sanitized_name = sanitize_identifier(raw_name)
    mapped_value = map_identifier(
        identifier=sanitized_name, language=language, mapping_table=mapping_table
    )

    if mapped_value:
        return f"{mapped_value} {postfix}", True
    elif sanitized_name:
        if disable_function_names:
            return f"{postfix}", False
        else:
            return f"{sanitized_name} {postfix}", False

    return "", False


def node_to_string_recursive(
    node: Optional[Node],
    language: str,
    indent_level: int = 0,
    disable_import_names: bool = True,
    disable_function_names: bool = False,
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
        result, _ = import_node_to_string(
            node,
            language=language,
            mapping_table=IMPORT_MAPPING,
            disable_import_names=disable_import_names,
        )
        final_string += f"{indent}{node_mapping} {result}\n"

    elif node.type in ["function_definition", "call", "lambda"]:
        result, mapped = function_node_to_string(
            node,
            language=language,
            mapping_table=FUNCTION_MAPPING,
            disable_function_names=disable_function_names,
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


def compress_tokens(tokens: List[str], mapping_rules: Dict[str, str]) -> List[str]:
    if not mapping_rules:
        return list(tokens)

    sorted_rules: List[tuple[str, str]] = sorted(
        mapping_rules.items(), key=lambda item: len(item[0].split()), reverse=True
    )

    compressed_tokens_list: List[str] = list(tokens)

    made_change_in_pass: bool = True
    while made_change_in_pass:
        made_change_in_pass = False
        temp_new_tokens: List[str] = []
        i: int = 0
        while i < len(compressed_tokens_list):
            matched: bool = False
            for rule_key, rule_value in sorted_rules:
                rule_key_tokens: List[str] = rule_key.split()
                rule_key_len: int = len(rule_key_tokens)

                if i + rule_key_len <= len(compressed_tokens_list):
                    # Check if the current slice of tokens matches the rule key
                    if compressed_tokens_list[i : i + rule_key_len] == rule_key_tokens:
                        temp_new_tokens.append(rule_value)
                        i += rule_key_len
                        matched = True
                        made_change_in_pass = True
                        break  # Break from inner loop (rules) once a match is found
            if not matched:
                temp_new_tokens.append(compressed_tokens_list[i])
                i += 1
        compressed_tokens_list = temp_new_tokens

    return compressed_tokens_list


# Helps to output code in yaml and handling new lines properly
class LiteralStr(str):
    pass


def literal_str_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, literal_str_representer)


class MalwiNode:
    def __init__(
        self,
        node: Optional[Node],
        file_path: str,
        file_byte_size: int,
        language: str = "unknown",
        warnings: List[str] = [],
        maliciousness: Optional[float] = None,
        imports: List[Node] = [],
    ):
        self.node = node
        self.file_path = file_path
        self.file_byte_size = file_byte_size
        self.language = language
        self.warnings = warnings
        self.maliciousness = maliciousness
        if Path(file_path).name in COMMON_TARGET_FILES.get(language, []):
            self.warnings = warnings + ["TARGET_FILE"]
        self.name = _get_node_text(self.node)
        self.imports = imports

    def to_string(
        self,
        one_line: bool = True,
        compression: bool = False,
        disable_function_names: bool = True,
        disable_import_names: bool = True,
        disable_imports: bool = False,
    ) -> str:
        return " ".join(syntax_tree_to_tokens(self.node, language=self.language))

    def to_string_hash(self) -> str:
        # Disable function names for hashing to detect functions with similar structures
        node_string = self.to_string(
            one_line=True,
            disable_function_names=True,
            disable_import_names=True,
            disable_imports=True,
        )
        encoded_string = node_string.encode("utf-8")
        sha256_hash = hashlib.sha256()
        sha256_hash.update(encoded_string)
        return sha256_hash.hexdigest()

    def _map_file_site_to_string(size: int):
        return ""

    def _to_json_data(self) -> dict:
        return {
            "path": self.file_path,
            "contents": [
                {
                    "type": "function",
                    "name": _get_node_name(self.node),
                    "score": self.maliciousness,
                    "tokens": self.to_string(),
                    "code": LiteralStr(_get_node_text(node=self.node)),
                    "hash": self.to_string_hash(),
                }
            ],
        }

    def to_yaml(self) -> str:
        malicious_data = {
            "format": 1,
            "malicious": [self._to_json_data()],
        }
        return yaml.dump(
            malicious_data, sort_keys=False, width=float("inf"), default_flow_style=None
        )

    def to_json(self) -> str:
        malicious_data = {
            "format": 1,
            "malicious": [self._to_json_data()],
        }
        return json.dumps(malicious_data, indent=4)

    @classmethod
    def _group_nodes(cls, nodes: List["MalwiNode"]) -> Tuple[List[dict], Set[str]]:
        grouped: dict[str, List["MalwiNode"]] = defaultdict(list)
        for node in nodes:
            grouped[node.file_path].append(node)

        entries = []
        files = set()
        for file_path, node_group in grouped.items():
            contents = []
            files.add(file_path)
            for node in node_group:
                contents.extend(node._to_json_data()["contents"])
            entries.append(
                {
                    "path": file_path,
                    "contents": contents,
                }
            )
        return entries, files

    @classmethod
    def nodes_to_dict(
        cls,
        malicious_nodes: List["MalwiNode"],
        benign_nodes: List["MalwiNode"],
        malicious_only: bool = False,
    ):
        malicious_entries, malicious_files = cls._group_nodes(malicious_nodes)
        benign_entries, benign_files = cls._group_nodes(benign_nodes)

        nodes_count = len(benign_nodes) + len(malicious_nodes)
        if nodes_count == 0:
            malicious_percentage = 0.0
        else:
            malicious_percentage = len(malicious_nodes) / (
                len(benign_nodes) + len(malicious_nodes)
            )

        return {
            "format": 1,
            "files_count": len(benign_files | malicious_files),
            "entities_count": len(benign_nodes) + len(malicious_nodes),
            "malicious_percentage": malicious_percentage,
            "malicious": malicious_entries,
            "benign": None if malicious_only else benign_entries,
        }

    @classmethod
    def nodes_to_json(
        cls,
        malicious_nodes: List["MalwiNode"],
        benign_nodes: List["MalwiNode"],
        malicious_only: bool = False,
    ) -> str:
        return json.dumps(
            cls.nodes_to_dict(
                malicious_nodes=malicious_nodes,
                benign_nodes=benign_nodes,
                malicious_only=malicious_only,
            ),
            indent=4,
        )

    @classmethod
    def nodes_to_yaml(
        cls,
        malicious_nodes: List["MalwiNode"],
        benign_nodes: List["MalwiNode"],
        malicious_only: bool = False,
    ) -> str:
        return yaml.dump(
            cls.nodes_to_dict(
                malicious_nodes=malicious_nodes,
                benign_nodes=benign_nodes,
                malicious_only=malicious_only,
            ),
            sort_keys=False,
        )

    @classmethod
    def nodes_to_csv(
        cls,
        malicious_nodes: List["MalwiNode"],
        benign_nodes: List["MalwiNode"],
        malicious_only: bool = False,
    ) -> str:
        data_dict = cls.nodes_to_dict(
            malicious_nodes=malicious_nodes,
            benign_nodes=benign_nodes,
            malicious_only=malicious_only,
        )

        output = io.StringIO()
        writer = csv.writer(output)

        header = ["files_count", "entities_count", "malicious_percentage"]
        writer.writerow(header)

        writer.writerow(
            [
                data_dict["files_count"],
                data_dict["entities_count"],
                f"{data_dict['malicious_percentage']:.6f}",
            ]
        )
        return output.getvalue()


def process_source_file(
    file_path: str,
) -> List[MalwiNode]:
    return create_malwi_nodes_from_file(file_path=str(file_path))


DEFAULT_BATCH_SIZE = 1000


def write_nodes_to_csv(nodes: List[MalwiNode], csv_file_path: str, write_header: bool):
    """
    Writes or appends a list of MalwiNode objects to a CSV file.

    Args:
        nodes: A list of MalwiNode objects to write.
        csv_file_path: The path to the CSV file.
        write_header: Boolean indicating whether to write the CSV header.
    """
    if not nodes:
        return

    mode = "w" if write_header else "a"
    try:
        with open(csv_file_path, mode, newline="", encoding="utf-8") as csvfile:
            csv_writer = csv.writer(csvfile)
            if write_header:
                csv_writer.writerow(["ast", "hash", "file"])
            for n in nodes:
                csv_writer.writerow([n.to_string(), n.to_string_hash(), n.file_path])
    except IOError as e:
        logging.error(f"Error writing to CSV file {csv_file_path}: {e}")
        # Consider re-raising or implementing more sophisticated error handling if needed


def main():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

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
    cli_parser.add_argument(
        "--batch-size",
        "-bs",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Number of files to process in each batch before writing to CSV (default: {DEFAULT_BATCH_SIZE}).",
    )

    args = cli_parser.parse_args()

    if args.option == "benign":
        output_csv_file = "benign.csv"
        input_directory_str = ".repo_cache/benign_repos"
    elif args.option == "malicious":
        output_csv_file = "malicious.csv"
        input_directory_str = ".repo_cache/malicious_repos"
    else:
        # Argparse 'choices' should prevent this, but as a safeguard:
        logging.error(
            "Critical Error: Invalid --option specified. This should not happen."
        )
        return

    input_path = Path(input_directory_str)
    batch_size = args.batch_size

    user_specified_extensions = None
    if args.extensions is not None:
        user_specified_extensions = [ext.lower().lstrip(".") for ext in args.extensions]
        if (
            not user_specified_extensions and args.extensions == []
        ):  # Check if --extensions was passed with no values
            logging.warning(
                "Warning: --extensions flag was used with no specific extensions. No files will be processed based on extension filter."
            )

    if not input_path.exists():
        logging.error(f"Error: Input path does not exist: {input_path}")
        return

    if not input_path.is_dir():
        logging.error(f"Error: Expected input path to be a directory: {input_path}")
        return

    logging.info(f"Scanning directory: {input_path}...")

    # Discovering files:
    # Note: list(input_path.rglob("*")) can be memory-intensive if there are millions of items (files+dirs).
    # If this step itself becomes a bottleneck, file discovery might need to be streamed or optimized.
    all_items_in_dir_paths = []
    try:
        all_items_in_dir_paths = list(input_path.rglob("*"))
    except Exception as e:
        logging.error(f"Error during initial scan of {input_path}: {e}")
        return

    logging.info(
        f"Found {len(all_items_in_dir_paths)} total items (files and directories). Filtering for files..."
    )

    files_to_process = []
    for item_path in tqdm(
        all_items_in_dir_paths, desc="Discovering files", unit="item"
    ):
        if item_path.is_file():
            files_to_process.append(item_path)

    if not files_to_process:
        logging.warning(f"No files found in the specified directory: {input_path}")
        return

    logging.info(
        f"Found {len(files_to_process)} potential files to process from {input_path}."
    )

    # Batch processing variables
    total_nodes_written_to_csv = 0
    files_yielding_nodes_count = (
        0  # Counts files that were processed and actually produced nodes
    )
    csv_header_written = False

    # Optional: Clean up existing output file before starting a fresh run
    # import os
    # if os.path.exists(output_csv_file):
    #     logging.info(f"Removing existing output file: {output_csv_file}")
    #     os.remove(output_csv_file)

    supported_extensions_map = {
        "js": "javascript",
        "ts": "typescript",
        "rs": "rust",
        "py": "python",
    }

    # Process files in batches
    for i in tqdm(
        range(0, len(files_to_process), batch_size),
        desc="Processing batches",
        unit="batch",
    ):
        current_batch_file_paths = files_to_process[i : i + batch_size]
        nodes_for_current_batch: List[MalwiNode] = []

        for (
            p_file_path
        ) in (
            current_batch_file_paths
        ):  # No inner tqdm here to keep batch progress output cleaner
            file_extension = p_file_path.suffix.lstrip(".").lower()

            # Apply extension filtering
            if user_specified_extensions is not None:
                if file_extension not in user_specified_extensions:
                    continue  # Skip file if not in user-specified extensions

            if file_extension not in supported_extensions_map:
                continue  # Skip file if not a supported extension

            # At this point, the file is relevant for processing
            try:
                extracted_nodes = process_source_file(file_path=str(p_file_path))
                if extracted_nodes:
                    nodes_for_current_batch.extend(extracted_nodes)
                    files_yielding_nodes_count += 1
            except Exception as e:
                logging.error(f"Error processing file {p_file_path}: {e}")
                # Decide if you want to skip this file or halt execution based on error severity

        if nodes_for_current_batch:
            write_nodes_to_csv(
                nodes_for_current_batch, output_csv_file, not csv_header_written
            )
            if (
                not csv_header_written
            ):  # Mark header as written after the first successful write
                csv_header_written = True
            total_nodes_written_to_csv += len(nodes_for_current_batch)

    # Final summary
    if total_nodes_written_to_csv == 0:
        logging.warning(
            "Processing complete. No AST nodes were extracted or matched the criteria."
        )
        # More detailed reason why no nodes might have been written:
        if files_yielding_nodes_count == 0 and len(files_to_process) > 0:
            if user_specified_extensions is not None:
                logging.warning(
                    f"This might be because no files matched the specified extensions filter: {user_specified_extensions} AND were of a supported type, or processed files yielded no AST nodes."
                )
            else:
                logging.warning(
                    "This might be because no processable files (matching supported extensions) were found, or such files yielded no AST nodes."
                )
    else:
        logging.info(
            f"Successfully wrote AST data from {files_yielding_nodes_count} file(s) "
            f"({total_nodes_written_to_csv} nodes in total) to {output_csv_file}"
        )


if __name__ == "__main__":
    main()
