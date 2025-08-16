import re
import dis
import math
import types
import socket
import urllib
import codecs
import pathlib
import collections

from enum import Enum
from packaging.version import Version, InvalidVersion
from typing import Optional, Any, Dict, Set

from common.files import read_json_from_file

STRING_MAX_LENGTH = 15


class SpecialCases(Enum):
    STRING_SENSITIVE_FILE_PATH = "STRING_SENSITIVE_FILE_PATH"
    STRING_URL = "STRING_URL"
    STRING_CONTAINS_URL = "STRING_CONTAINS_URL"
    STRING_VERSION = "STRING_VERSION"
    STRING_ENCODING = "STRING_ENCODING"
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
    BOOLEAN = "BOOLEAN"
    INTEGER = "INTEGER"
    FLOAT = "FLOAT"
    OBJECT = "OBJECT"

    # STRING prefix combinations (4 prefixes × 6 lengths × 4 entropies = 96 combinations)
    STRING_LEN_XS_ENT_LOW = "STRING_LEN_XS_ENT_LOW"
    STRING_LEN_XS_ENT_MED = "STRING_LEN_XS_ENT_MED"
    STRING_LEN_XS_ENT_HIGH = "STRING_LEN_XS_ENT_HIGH"
    STRING_LEN_XS_ENT_VHIGH = "STRING_LEN_XS_ENT_VHIGH"
    STRING_LEN_S_ENT_LOW = "STRING_LEN_S_ENT_LOW"
    STRING_LEN_S_ENT_MED = "STRING_LEN_S_ENT_MED"
    STRING_LEN_S_ENT_HIGH = "STRING_LEN_S_ENT_HIGH"
    STRING_LEN_S_ENT_VHIGH = "STRING_LEN_S_ENT_VHIGH"
    STRING_LEN_M_ENT_LOW = "STRING_LEN_M_ENT_LOW"
    STRING_LEN_M_ENT_MED = "STRING_LEN_M_ENT_MED"
    STRING_LEN_M_ENT_HIGH = "STRING_LEN_M_ENT_HIGH"
    STRING_LEN_M_ENT_VHIGH = "STRING_LEN_M_ENT_VHIGH"
    STRING_LEN_L_ENT_LOW = "STRING_LEN_L_ENT_LOW"
    STRING_LEN_L_ENT_MED = "STRING_LEN_L_ENT_MED"
    STRING_LEN_L_ENT_HIGH = "STRING_LEN_L_ENT_HIGH"
    STRING_LEN_L_ENT_VHIGH = "STRING_LEN_L_ENT_VHIGH"
    STRING_LEN_XL_ENT_LOW = "STRING_LEN_XL_ENT_LOW"
    STRING_LEN_XL_ENT_MED = "STRING_LEN_XL_ENT_MED"
    STRING_LEN_XL_ENT_HIGH = "STRING_LEN_XL_ENT_HIGH"
    STRING_LEN_XL_ENT_VHIGH = "STRING_LEN_XL_ENT_VHIGH"
    STRING_LEN_XXL_ENT_LOW = "STRING_LEN_XXL_ENT_LOW"
    STRING_LEN_XXL_ENT_MED = "STRING_LEN_XXL_ENT_MED"
    STRING_LEN_XXL_ENT_HIGH = "STRING_LEN_XXL_ENT_HIGH"
    STRING_LEN_XXL_ENT_VHIGH = "STRING_LEN_XXL_ENT_VHIGH"

    # STRING_BASE64 prefix combinations
    STRING_BASE64_LEN_XS_ENT_LOW = "STRING_BASE64_LEN_XS_ENT_LOW"
    STRING_BASE64_LEN_XS_ENT_MED = "STRING_BASE64_LEN_XS_ENT_MED"
    STRING_BASE64_LEN_XS_ENT_HIGH = "STRING_BASE64_LEN_XS_ENT_HIGH"
    STRING_BASE64_LEN_XS_ENT_VHIGH = "STRING_BASE64_LEN_XS_ENT_VHIGH"
    STRING_BASE64_LEN_S_ENT_LOW = "STRING_BASE64_LEN_S_ENT_LOW"
    STRING_BASE64_LEN_S_ENT_MED = "STRING_BASE64_LEN_S_ENT_MED"
    STRING_BASE64_LEN_S_ENT_HIGH = "STRING_BASE64_LEN_S_ENT_HIGH"
    STRING_BASE64_LEN_S_ENT_VHIGH = "STRING_BASE64_LEN_S_ENT_VHIGH"
    STRING_BASE64_LEN_M_ENT_LOW = "STRING_BASE64_LEN_M_ENT_LOW"
    STRING_BASE64_LEN_M_ENT_MED = "STRING_BASE64_LEN_M_ENT_MED"
    STRING_BASE64_LEN_M_ENT_HIGH = "STRING_BASE64_LEN_M_ENT_HIGH"
    STRING_BASE64_LEN_M_ENT_VHIGH = "STRING_BASE64_LEN_M_ENT_VHIGH"
    STRING_BASE64_LEN_L_ENT_LOW = "STRING_BASE64_LEN_L_ENT_LOW"
    STRING_BASE64_LEN_L_ENT_MED = "STRING_BASE64_LEN_L_ENT_MED"
    STRING_BASE64_LEN_L_ENT_HIGH = "STRING_BASE64_LEN_L_ENT_HIGH"
    STRING_BASE64_LEN_L_ENT_VHIGH = "STRING_BASE64_LEN_L_ENT_VHIGH"
    STRING_BASE64_LEN_XL_ENT_LOW = "STRING_BASE64_LEN_XL_ENT_LOW"
    STRING_BASE64_LEN_XL_ENT_MED = "STRING_BASE64_LEN_XL_ENT_MED"
    STRING_BASE64_LEN_XL_ENT_HIGH = "STRING_BASE64_LEN_XL_ENT_HIGH"
    STRING_BASE64_LEN_XL_ENT_VHIGH = "STRING_BASE64_LEN_XL_ENT_VHIGH"
    STRING_BASE64_LEN_XXL_ENT_LOW = "STRING_BASE64_LEN_XXL_ENT_LOW"
    STRING_BASE64_LEN_XXL_ENT_MED = "STRING_BASE64_LEN_XXL_ENT_MED"
    STRING_BASE64_LEN_XXL_ENT_HIGH = "STRING_BASE64_LEN_XXL_ENT_HIGH"
    STRING_BASE64_LEN_XXL_ENT_VHIGH = "STRING_BASE64_LEN_XXL_ENT_VHIGH"

    # STRING_HEX prefix combinations
    STRING_HEX_LEN_XS_ENT_LOW = "STRING_HEX_LEN_XS_ENT_LOW"
    STRING_HEX_LEN_XS_ENT_MED = "STRING_HEX_LEN_XS_ENT_MED"
    STRING_HEX_LEN_XS_ENT_HIGH = "STRING_HEX_LEN_XS_ENT_HIGH"
    STRING_HEX_LEN_XS_ENT_VHIGH = "STRING_HEX_LEN_XS_ENT_VHIGH"
    STRING_HEX_LEN_S_ENT_LOW = "STRING_HEX_LEN_S_ENT_LOW"
    STRING_HEX_LEN_S_ENT_MED = "STRING_HEX_LEN_S_ENT_MED"
    STRING_HEX_LEN_S_ENT_HIGH = "STRING_HEX_LEN_S_ENT_HIGH"
    STRING_HEX_LEN_S_ENT_VHIGH = "STRING_HEX_LEN_S_ENT_VHIGH"
    STRING_HEX_LEN_M_ENT_LOW = "STRING_HEX_LEN_M_ENT_LOW"
    STRING_HEX_LEN_M_ENT_MED = "STRING_HEX_LEN_M_ENT_MED"
    STRING_HEX_LEN_M_ENT_HIGH = "STRING_HEX_LEN_M_ENT_HIGH"
    STRING_HEX_LEN_M_ENT_VHIGH = "STRING_HEX_LEN_M_ENT_VHIGH"
    STRING_HEX_LEN_L_ENT_LOW = "STRING_HEX_LEN_L_ENT_LOW"
    STRING_HEX_LEN_L_ENT_MED = "STRING_HEX_LEN_L_ENT_MED"
    STRING_HEX_LEN_L_ENT_HIGH = "STRING_HEX_LEN_L_ENT_HIGH"
    STRING_HEX_LEN_L_ENT_VHIGH = "STRING_HEX_LEN_L_ENT_VHIGH"
    STRING_HEX_LEN_XL_ENT_LOW = "STRING_HEX_LEN_XL_ENT_LOW"
    STRING_HEX_LEN_XL_ENT_MED = "STRING_HEX_LEN_XL_ENT_MED"
    STRING_HEX_LEN_XL_ENT_HIGH = "STRING_HEX_LEN_XL_ENT_HIGH"
    STRING_HEX_LEN_XL_ENT_VHIGH = "STRING_HEX_LEN_XL_ENT_VHIGH"
    STRING_HEX_LEN_XXL_ENT_LOW = "STRING_HEX_LEN_XXL_ENT_LOW"
    STRING_HEX_LEN_XXL_ENT_MED = "STRING_HEX_LEN_XXL_ENT_MED"
    STRING_HEX_LEN_XXL_ENT_HIGH = "STRING_HEX_LEN_XXL_ENT_HIGH"
    STRING_HEX_LEN_XXL_ENT_VHIGH = "STRING_HEX_LEN_XXL_ENT_VHIGH"

    # STRING_ESCAPED_HEX prefix combinations
    STRING_ESCAPED_HEX_LEN_XS_ENT_LOW = "STRING_ESCAPED_HEX_LEN_XS_ENT_LOW"
    STRING_ESCAPED_HEX_LEN_XS_ENT_MED = "STRING_ESCAPED_HEX_LEN_XS_ENT_MED"
    STRING_ESCAPED_HEX_LEN_XS_ENT_HIGH = "STRING_ESCAPED_HEX_LEN_XS_ENT_HIGH"
    STRING_ESCAPED_HEX_LEN_XS_ENT_VHIGH = "STRING_ESCAPED_HEX_LEN_XS_ENT_VHIGH"
    STRING_ESCAPED_HEX_LEN_S_ENT_LOW = "STRING_ESCAPED_HEX_LEN_S_ENT_LOW"
    STRING_ESCAPED_HEX_LEN_S_ENT_MED = "STRING_ESCAPED_HEX_LEN_S_ENT_MED"
    STRING_ESCAPED_HEX_LEN_S_ENT_HIGH = "STRING_ESCAPED_HEX_LEN_S_ENT_HIGH"
    STRING_ESCAPED_HEX_LEN_S_ENT_VHIGH = "STRING_ESCAPED_HEX_LEN_S_ENT_VHIGH"
    STRING_ESCAPED_HEX_LEN_M_ENT_LOW = "STRING_ESCAPED_HEX_LEN_M_ENT_LOW"
    STRING_ESCAPED_HEX_LEN_M_ENT_MED = "STRING_ESCAPED_HEX_LEN_M_ENT_MED"
    STRING_ESCAPED_HEX_LEN_M_ENT_HIGH = "STRING_ESCAPED_HEX_LEN_M_ENT_HIGH"
    STRING_ESCAPED_HEX_LEN_M_ENT_VHIGH = "STRING_ESCAPED_HEX_LEN_M_ENT_VHIGH"
    STRING_ESCAPED_HEX_LEN_L_ENT_LOW = "STRING_ESCAPED_HEX_LEN_L_ENT_LOW"
    STRING_ESCAPED_HEX_LEN_L_ENT_MED = "STRING_ESCAPED_HEX_LEN_L_ENT_MED"
    STRING_ESCAPED_HEX_LEN_L_ENT_HIGH = "STRING_ESCAPED_HEX_LEN_L_ENT_HIGH"
    STRING_ESCAPED_HEX_LEN_L_ENT_VHIGH = "STRING_ESCAPED_HEX_LEN_L_ENT_VHIGH"
    STRING_ESCAPED_HEX_LEN_XL_ENT_LOW = "STRING_ESCAPED_HEX_LEN_XL_ENT_LOW"
    STRING_ESCAPED_HEX_LEN_XL_ENT_MED = "STRING_ESCAPED_HEX_LEN_XL_ENT_MED"
    STRING_ESCAPED_HEX_LEN_XL_ENT_HIGH = "STRING_ESCAPED_HEX_LEN_XL_ENT_HIGH"
    STRING_ESCAPED_HEX_LEN_XL_ENT_VHIGH = "STRING_ESCAPED_HEX_LEN_XL_ENT_VHIGH"
    STRING_ESCAPED_HEX_LEN_XXL_ENT_LOW = "STRING_ESCAPED_HEX_LEN_XXL_ENT_LOW"
    STRING_ESCAPED_HEX_LEN_XXL_ENT_MED = "STRING_ESCAPED_HEX_LEN_XXL_ENT_MED"
    STRING_ESCAPED_HEX_LEN_XXL_ENT_HIGH = "STRING_ESCAPED_HEX_LEN_XXL_ENT_HIGH"
    STRING_ESCAPED_HEX_LEN_XXL_ENT_VHIGH = "STRING_ESCAPED_HEX_LEN_XXL_ENT_VHIGH"


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


def is_version(version_string):
    """
    Checks if a given string is a valid version string according to PEP 440.

    Args:
        version_string (str): The string to check.

    Returns:
        bool: True if the string is a valid version, False otherwise.
    """
    try:
        # Attempt to parse the string as a Version object.
        # If it's not a valid version, InvalidVersion will be raised.
        Version(version_string)
        return True
    except InvalidVersion:
        return False


def is_valid_encoding_name(encoding_name):
    """
    Checks if a given string is a recognized Python encoding name.

    Args:
        encoding_name (str): The string to check (e.g., 'utf-8', 'latin-1').

    Returns:
        bool: True if the encoding name is recognized, False otherwise.
    """
    try:
        # Attempt to get an encoder for the given name.
        # If the name is not recognized, a LookupError will be raised.
        codecs.lookup(encoding_name)
        return True
    except LookupError:
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


def clean_string_literal(url_string):
    """
    Cleans a URL string by removing various forms of quotation marks and
    the 'f' prefix from f-string literals, ensuring matching quotes.

    Args:
        url_string (str): The input string potentially containing a URL.

    Returns:
        str: The cleaned URL string.
    """

    # --- Handle f-string literal representations ---
    # Case: f"..."
    if url_string.startswith('f"') and url_string.endswith('"'):
        # Remove 'f' and the outer double quotes
        return url_string[2:-1]  # Slice off 'f"' and '"'
    # Case: f'...'
    elif url_string.startswith("f'") and url_string.endswith("'"):
        # Remove 'f' and the outer single quotes
        return url_string[2:-1]  # Slice off "f'" and "'"
    # Case: f"""...""" (less common but possible)
    elif url_string.startswith('f"""') and url_string.endswith('"""'):
        return url_string[4:-3]  # Slice off 'f"""' and '"""'
    # Case: f'''...''' (less common but possible)
    elif url_string.startswith("f'''") and url_string.endswith("'''"):
        return url_string[4:-3]  # Slice off "f'''" and "'''"

    # --- Handle standard string literal representations (after f-string checks) ---
    # Case: "..."
    if url_string.startswith('"') and url_string.endswith('"'):
        return url_string[1:-1]
    # Case: '...'
    elif url_string.startswith("'") and url_string.endswith("'"):
        return url_string[1:-1]
    # Case: """..."""
    elif url_string.startswith('"""') and url_string.endswith('"""'):
        return url_string[3:-3]
    # Case: '''...'''
    elif url_string.startswith("'''") and url_string.endswith("'''"):
        return url_string[3:-3]

    # If no matching quotes or f-string patterns are found, return the original string
    return url_string


def get_combined_string_token(prefix: str, length: int, entropy: float) -> str:
    """
    Get the complete enum token for a string with given prefix, length, and entropy.

    Args:
        prefix: One of "STRING", "STRING_BASE64", "STRING_HEX", "STRING_ESCAPED_HEX"
        length: String length
        entropy: Shannon entropy value

    Returns:
        Complete token from SpecialCases enum
    """
    # Map length to suffix
    if length <= 10:
        len_suffix = "LEN_XS"
    elif length <= 100:
        len_suffix = "LEN_S"
    elif length <= 1000:
        len_suffix = "LEN_M"
    elif length <= 10000:
        len_suffix = "LEN_L"
    elif length <= 100000:
        len_suffix = "LEN_XL"
    else:
        len_suffix = "LEN_XXL"

    # Map entropy to suffix
    if entropy <= 1.0:
        ent_suffix = "ENT_LOW"
    elif entropy <= 2.5:
        ent_suffix = "ENT_MED"
    elif entropy <= 5.0:
        ent_suffix = "ENT_HIGH"
    else:
        ent_suffix = "ENT_VHIGH"

    # Build complete token name
    token_name = f"{prefix}_{len_suffix}_{ent_suffix}"

    # Return the enum value
    try:
        return getattr(SpecialCases, token_name).value
    except AttributeError:
        # Fallback to concatenated string if enum doesn't exist
        return token_name


def map_entropy_to_token(entropy: float):
    """Legacy function - use get_combined_string_token instead"""
    if entropy <= 1.0:
        return "ENT_LOW"
    elif entropy <= 2.5:
        return "ENT_MED"
    elif entropy <= 5.0:
        return "ENT_HIGH"
    else:
        return "ENT_VHIGH"


def map_string_length_to_token(str_len: int):
    """Legacy function - use get_combined_string_token instead"""
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
