import re
import dis
import math
import types
import socket
import urllib
import pathlib
import collections

from enum import Enum
from typing import List, Tuple, Optional, Any, Dict, Set

from common.files import read_json_from_file

STRING_MAX_LENGTH = 15


class SpecialCases(Enum):
    STRING_SENSITIVE_FILE_PATH = "STRING_SENSITIVE_FILE_PATH"
    STRING_URL = "STRING_URL"
    CONTAINS_URL = "CONTAINS_URL"
    STRING_LOCALHOST = "STRING_LOCALHOST"
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


def contains_url(text: str) -> bool:
    """Check if a string contains a URL pattern."""
    if not text or len(text) < 8:  # Minimum URL length
        return False

    # Simple pattern to detect URLs within text
    url_patterns = [
        "http://",
        "https://",
        "ftp://",
        "ftps://",
        "ssh://",
        "telnet://",
        "file://",
        "data:",
        "javascript:",
        "vbscript:",
    ]

    for pattern in url_patterns:
        if pattern in text.lower():
            return True

    return False


def is_localhost(text: str) -> bool:
    """Check if a string represents localhost or local network addresses."""
    if not text:
        return False

    text_lower = text.lower().strip()

    # Direct localhost patterns
    localhost_patterns = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "local",
        "loopback",
    ]

    # Check if text is exactly one of these patterns
    if text_lower in localhost_patterns:
        return True

    # Check for localhost with port
    if text_lower.startswith("localhost:") or text_lower.startswith("127.0.0.1:"):
        return True

    # Check for localhost in URLs
    if ("localhost" in text_lower or "127.0.0.1" in text_lower) and (
        "http" in text_lower or "ftp" in text_lower
    ):
        return True

    # Check for private network ranges (RFC 1918)
    import re

    # Match 192.168.x.x, 10.x.x.x, 172.16-31.x.x
    private_ip_patterns = [
        r"^192\.168\.\d{1,3}\.\d{1,3}",
        r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}",
    ]

    for pattern in private_ip_patterns:
        if re.match(pattern, text_lower):
            return True

    return False


def is_file_path(text: str) -> bool:
    if not text or len(text) < 2:
        return False

    # Exclude URLs and other non-file patterns first
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
    if is_common_non_file_url:
        return False

    # Check for common file extensions
    common_extensions = (
        ".py",
        ".js",
        ".txt",
        ".json",
        ".xml",
        ".html",
        ".css",
        ".java",
        ".cpp",
        ".c",
        ".h",
        ".hpp",
        ".sh",
        ".bat",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".zip",
        ".tar",
        ".gz",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".csv",
        ".log",
        ".conf",
        ".cfg",
        ".ini",
        ".yaml",
        ".yml",
        ".md",
        ".rst",
        ".tex",
        ".tmp",
        ".bak",
    )
    has_file_extension = any(text.lower().endswith(ext) for ext in common_extensions)

    # Specific file path patterns
    is_unix_like_start = text.startswith(("/", "~", "./", "../"))
    is_win_drive_start = (
        len(text) > 2
        and text[1] == ":"
        and text[0].isalpha()
        and text[2] in ("\\", "/")
    )
    is_win_unc_start = text.startswith("\\\\")

    # Must either:
    # 1. Start with a clear path pattern (absolute or relative)
    # 2. Have a file extension
    # 3. Match specific path patterns (but not generic strings with slashes)
    if is_unix_like_start or is_win_drive_start or is_win_unc_start:
        return True

    # For other cases, require both a separator and a file extension
    # or a very specific path pattern
    has_separator = "/" in text or "\\" in text
    if has_separator and has_file_extension:
        return True

    # Simple filename with extension (no path separators)
    if not has_separator and has_file_extension and "." in text:
        # Make sure it's not something like "example.com"
        # by checking it doesn't look like a domain
        if not (
            text.count(".") == 1
            and text.split(".")[1]
            in ("com", "org", "net", "edu", "gov", "io", "co", "uk")
        ):
            return True

    # Check for specific path patterns without extensions
    # (like bin paths or specific directories)
    specific_patterns = (
        "/bin/",
        "/usr/",
        "/etc/",
        "/var/",
        "/tmp/",
        "/home/",
        "/opt/",
        "/dev/",
        "/proc/",
        "/sys/",
        "C:\\Windows",
        "C:\\Program",
        "/Applications/",
        "/Library/",
        "/System/",
    )
    if any(pattern in text for pattern in specific_patterns):
        return True

    return False


def remove_newlines(text: str) -> str:
    return text.replace("\n", "").replace("\r", "")


def reduce_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


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


def map_string_arg(argval: str, original_argrepr: str) -> str:
    prefix = "STRING"
    python_function_mapping = FUNCTION_MAPPING.get("python", {})
    python_import_mapping = IMPORT_MAPPING.get("python", {})

    # Sanitize argval to ensure it's a well-formed Unicode string
    try:
        # Encode to UTF-8 and decode back, replacing any bytes that
        # result in ill-formed Unicode (like lone surrogates) with U+FFFD.
        sanitized_argval = argval.encode("utf-8", errors="replace").decode(
            "utf-8", errors="replace"
        )
    except Exception:
        sanitized_argval = str(argval)

    argval = sanitized_argval
    argval = reduce_whitespace(remove_newlines(argval))

    if argval in python_function_mapping:
        return python_function_mapping.get(argval)
    elif argval in python_import_mapping:
        return python_import_mapping.get(argval)
    elif argval in SENSITIVE_PATHS:
        return f"{SpecialCases.STRING_SENSITIVE_FILE_PATH.value}"
    elif is_localhost(argval):
        return f"{SpecialCases.STRING_LOCALHOST.value}"
    elif is_valid_ip(argval):
        return f"{SpecialCases.STRING_IP.value}"
    elif is_valid_url(argval):
        return f"{SpecialCases.STRING_URL.value}"
    elif contains_url(argval):
        return f"{SpecialCases.CONTAINS_URL.value}"
    elif is_file_path(argval):
        return f"{SpecialCases.STRING_FILE_PATH.value}"
    else:
        if len(argval) <= STRING_MAX_LENGTH:
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


def map_argument(arg: Any, language: str = "python") -> str:
    """
    Maps instruction arguments to semantic tokens using mapping.py logic with language support.
    """
    if isinstance(arg, str):
        # Use sophisticated string mapping with proper language support
        return map_string_argument(arg, language)
    elif isinstance(arg, bool):
        return "BOOLEAN"
    elif isinstance(arg, int):
        return "INTEGER"
    elif isinstance(arg, float):
        return "FLOAT"
    elif isinstance(arg, (list, tuple)):
        return "LIST"
    elif isinstance(arg, dict):
        return "DICT"
    elif hasattr(arg, "__class__"):
        return arg.__class__.__name__.upper()
    else:
        return str(arg)


def map_string_argument(argval: str, language: str = "python") -> str:
    """
    Advanced string argument mapping using language-specific mappings.
    Based on map_string_arg logic but with proper language parameter support.
    """
    prefix = "STRING"

    # Get language-specific mappings
    lang_function_mapping = FUNCTION_MAPPING.get(language, {})
    lang_import_mapping = IMPORT_MAPPING.get(language, {})

    # Sanitize argval to ensure it's a well-formed Unicode string
    try:
        sanitized_argval = argval.encode("utf-8", errors="replace").decode(
            "utf-8", errors="replace"
        )
    except Exception:
        sanitized_argval = str(argval)

    argval = reduce_whitespace(remove_newlines(sanitized_argval))

    # Check language-specific mappings first
    if argval in lang_function_mapping:
        return lang_function_mapping.get(argval)
    elif argval in lang_import_mapping:
        return lang_import_mapping.get(argval)
    elif argval in SENSITIVE_PATHS:
        return "STRING_SENSITIVE_FILE_PATH"
    elif is_localhost(argval):
        return "STRING_LOCALHOST"
    elif is_valid_ip(argval):
        return "STRING_IP"
    elif is_valid_url(argval):
        return "STRING_URL"
    elif contains_url(argval):
        return "CONTAINS_URL"
    elif is_file_path(argval):
        return "STRING_FILE_PATH"
    else:
        # Short strings are returned as-is
        if len(argval) <= STRING_MAX_LENGTH:
            return argval

        # Analyze content type for longer strings
        if is_escaped_hex(argval):
            prefix = "STRING_ESCAPED_HEX"
        elif is_hex(argval):
            prefix = "STRING_HEX"
        elif is_base64(argval):
            prefix = "STRING_BASE64"

        # Add length and entropy analysis
        length_suffix = map_string_length_to_token(len(argval))
        try:
            entropy = calculate_shannon_entropy(argval.encode("utf-8", errors="ignore"))
        except Exception:
            entropy = 0.0
        entropy_suffix = map_entropy_to_token(entropy)
        return f"{prefix}_{length_suffix}_{entropy_suffix}"


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
        elif instruction.opname in ["IMPORT_NAME", "IMPORT_FROM"]:
            final_value = map_string_arg(argval, original_argrepr)
        elif instruction.opname in [
            "LOAD_GLOBAL",
            "LOAD_NAME",
            "LOAD_METHOD",
            "LOAD_ATTR",
        ]:
            final_value = map_string_arg(argval, original_argrepr)
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

        if final_value is not None and str(final_value) != "":
            flat_instructions.append(str(final_value))
    return flat_instructions
