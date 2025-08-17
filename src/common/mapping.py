import re

import math

import socket
import urllib
import codecs
import pathlib
import collections
import base64
import binascii
from enum import Enum
from packaging.version import Version, InvalidVersion
from typing import Any, Dict, Set

from common.files import read_json_from_file


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


def is_base64(text: str) -> bool:
    """
    Checks if a given string is a valid Base64 encoded value.

    Args:
        text (str): The input string to check.

    Returns:
        bool: True if the string is valid Base64, False otherwise.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    try:
        # The input to b64decode must be ASCII bytes.
        # If the string contains non-ASCII characters, it's not Base64.
        text_as_bytes = text.encode("ascii")

        # The decode function will raise a binascii.Error if the input is
        # not valid Base64, checking for correct characters, padding, and length.
        # The 'validate=True' flag ensures strict adherence to the alphabet.
        base64.b64decode(text_as_bytes, validate=True)
        return True
    except (binascii.Error, UnicodeDecodeError):
        # A binascii.Error indicates invalid Base64 (e.g., bad padding).
        # A UnicodeDecodeError indicates the string wasn't pure ASCII.
        return False


def is_hex(text: str) -> bool:
    """
    Checks if a given string is a valid hexadecimal value.

    A string is considered hexadecimal if it optionally starts with '0x',
    has an even number of characters, and contains only valid hex digits
    (0-9 and A-F, case-insensitive).

    Args:
        text (str): The input string to check.

    Returns:
        bool: True if the string is a valid hex value, False otherwise.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    # Handle the optional '0x' prefix
    if text.lower().startswith("0x"):
        text = text[2:]

    # After stripping the prefix, the string can't be empty.
    if not text:
        return False

    # A hex string representing bytes must have an even number of digits.
    if len(text) % 2 != 0:
        return False

    # The most robust way to check for hex characters is to try conversion.
    try:
        # Convert the string to an integer from base 16.
        int(text, 16)
        return True
    except ValueError:
        # The conversion failed, so it's not a valid hex string.
        return False


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


def is_bash_code(text: str, threshold: int = 3) -> bool:
    """
    Analyzes a string to determine if it's likely bash code.

    This function uses a heuristic scoring model, checking for common bash
    commands, control structures, and syntax. It returns a boolean value.

    Args:
        text (str): The input string to check.
        threshold (int): The internal score needed to return True. A lower
                         value increases sensitivity. Defaults to 3.

    Returns:
        bool: True if the string is likely bash code, False otherwise.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    score = 0

    # Heuristic 1: Shebang (strong indicator)
    if re.search(r"^#!\s*/(usr/)?bin/(bash|sh|zsh)", text):
        score += 10

    # Heuristic 2: Common commands and control structures
    # Extended list of common bash/shell commands
    keywords = [
        "ls",
        "cd",
        "echo",
        "rm",
        "grep",
        "awk",
        "sed",
        "cat",
        "curl",
        "wget",
        "sudo",
        "chmod",
        "chown",
        "mkdir",
        "touch",
        "cp",
        "mv",
        "find",
        "xargs",
        "tar",
        "gzip",
        "gunzip",
        "zip",
        "unzip",
        "ps",
        "kill",
        "pkill",
        "top",
        "df",
        "du",
        "mount",
        "umount",
        "export",
        "source",
        "alias",
        "unset",
        "set",
        "eval",
        "exec",
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "while",
        "do",
        "done",
        "case",
        "esac",
        "function",
        "return",
        "break",
        "continue",
        "true",
        "false",
        "test",
        "exit",
        "trap",
        "wait",
        "sleep",
        "head",
        "tail",
        "sort",
        "uniq",
        "cut",
        "paste",
        "join",
        "comm",
        "diff",
        "patch",
        "tee",
        "nc",
        "ssh",
        "scp",
        "rsync",
        "git",
        "docker",
        "kubectl",
        "npm",
        "pip",
        "apt",
        "yum",
        "brew",
        "systemctl",
        "service",
        "journalctl",
        "cron",
        "at",
    ]

    # Count how many bash keywords appear
    keyword_count = 0
    for keyword in keywords:
        if re.search(r"\b" + re.escape(keyword) + r"\b", text.lower()):
            keyword_count += 1

    # Award points based on keyword density
    if keyword_count >= 3:
        score += 4
    elif keyword_count >= 2:
        score += 3
    elif keyword_count >= 1:
        score += 2

    # Heuristic 3: Shell-specific syntax and operators
    if re.search(r"\$[a-zA-Z_]|\$\{[^}]+\}", text):  # Variable expansion: $VAR, ${VAR}
        score += 2
    if re.search(r"\$\([^)]+\)|`[^`]+`", text):  # Command substitution: $(...), `...`
        score += 3
    if re.search(r"\||>>?|<|&&|\|\||;", text):  # Piping, redirection, logical operators
        score += 1
    if re.search(
        r"(^|\s)-[a-zA-Z]|\s--[a-zA-Z][a-zA-Z0-9-]*", text
    ):  # Command line options
        score += 1

    # Heuristic 4: Common bash patterns
    if re.search(r"\[\s+.*\s+\]", text):  # Test brackets: [ condition ]
        score += 2
    if re.search(r"\$\?", text):  # Exit status variable
        score += 1
    if re.search(r"^\s*#(?!#)", text, re.MULTILINE):  # Shell comments (not shebang)
        score += 1
    if re.search(r"2>&1|1>&2|&>|2>", text):  # File descriptor redirection
        score += 2
    if re.search(r"[^\\][\*\?]", text):  # Wildcards (not escaped)
        score += 1
    if re.search(r"~\/|\/home\/|\/usr\/|\/etc\/|\/var\/|\/tmp\/", text):  # Common paths
        score += 1

    return score >= threshold


def is_code(text: str, threshold: float = 0.25) -> bool:
    """
    Analyzes a string to determine if it likely contains code.

    This function uses a heuristic model based on several indicators:
    1.  **Symbol Density**: The ratio of non-alphanumeric characters.
    2.  **Keyword Presence**: Common programming keywords.
    3.  **Structural Patterns**: Looks for function definitions, tags, etc.
    4.  **Indentation**: Checks for lines starting with significant whitespace.

    Args:
        text (str): The input string to check.
        threshold (float): A value between 0 and 1.0. A higher value requires
                         more evidence before classifying text as code.
                         Defaults to 0.25.

    Returns:
        bool: True if the string is likely code, False otherwise.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    score = 0.0

    # 1. --- Symbol Density Analysis ---
    # Code tends to have a higher ratio of symbols to letters.
    text_length = len(text)
    non_alnum_count = len(re.findall(r"[^a-zA-Z0-9\s]", text))
    symbol_density = non_alnum_count / text_length if text_length > 0 else 0

    # Only award symbol density points if it's a reasonable code-like density
    # Allow higher density for JSON/data structures
    if 0.12 < symbol_density <= 0.6:  # Sweet spot for code and data structures
        score += 0.4
    elif 0.05 < symbol_density <= 0.12:  # Partial credit for moderate symbol density
        score += 0.2

    # 2. --- Keyword Presence ---
    # Look for keywords common across many languages.
    keywords = {
        "if",
        "else",
        "elif",
        "for",
        "while",
        "do",
        "return",
        "yield",
        "function",
        "def",
        "class",
        "struct",
        "interface",
        "enum",
        "import",
        "from",
        "include",
        "require",
        "using",
        "namespace",
        "const",
        "let",
        "var",
        "auto",
        "int",
        "float",
        "string",
        "bool",
        "public",
        "private",
        "protected",
        "static",
        "final",
        "abstract",
        "true",
        "false",
        "null",
        "None",
        "nil",
        "undefined",
        "switch",
        "case",
        "default",
        "break",
        "continue",
        "try",
        "catch",
        "finally",
        "except",
        "throw",
        "raise",
        "new",
        "delete",
        "malloc",
        "free",
        "this",
        "self",
        "super",
        "lambda",
        "async",
        "await",
        "typeof",
        "instanceof",
        "extends",
        "implements",
        "inherits",
        "override",
    }

    # Using a set for efficient lookup
    found_keywords = {
        word for word in re.findall(r"\b\w+\b", text.lower()) if word in keywords
    }

    # Award points based on keyword count
    if len(found_keywords) >= 3:
        score += 0.6
    elif len(found_keywords) >= 2:
        score += 0.5
    elif len(found_keywords) >= 1:
        score += 0.3

    # 3. --- Structural Patterns (Regex) ---
    patterns = [
        r"<\s*/?\s*\w+.*?>",  # HTML/XML tags: <html>, </div>
        r"==|!=|<=|>=|\+=|=>|->",  # Common operators: ==, !=, +=, =>
        r"//|#|/\*|\*/",  # Comments: //, #, /*, */
        r"\b(def|function)\s+\w+\s*\(",  # Function definition
        r"[\[\]\{\}]",  # Brackets and braces
    ]
    for pattern in patterns:
        if re.search(pattern, text):
            score += 0.2  # Add a smaller score for each pattern found

    # 4. --- Indentation ---
    # Check if any line (after the first) starts with multiple spaces or a tab.
    lines = text.splitlines()
    if len(lines) > 1:
        for line in lines[1:]:
            if re.match(r"^\s{2,}|^\t", line):
                score += 0.3
                break  # Only need to find one instance

    # Normalize the score to be roughly between 0 and 1+
    # This is a simple normalization; a more complex one could be used.
    final_score = min(score, 1.0)

    return final_score >= threshold


def is_sql(text: str) -> bool:
    """
    Detects if a given string contains a SQL statement.

    This function uses a set of regular expressions to find common SQL
    keywords and query structures. It's case-insensitive.

    Args:
        text (str): The input string to check.

    Returns:
        bool: True if the string is likely a SQL statement, False otherwise.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    # 1. High-confidence patterns for core SQL commands
    # These patterns look for the basic structure of the most common queries.
    sql_patterns = [
        # More specific patterns to avoid false positives
        r"\bselect\s+[\w\*,\s\.]+\s+from\s+[\w\.]+(\s+where|\s+group|\s+order|\s+limit|;|\s*--|\s*$)",  # SELECT ... FROM table with SQL context
        r"\binsert\s+into\s+\w+\s*\([^)]*\)\s*values\s*\(",  # INSERT INTO table (...) VALUES (
        r"\bupdate\s+\w+\s+set\s+\w+\s*=",  # UPDATE table SET column =
        r"\bdelete\s+from\s+\w+",  # DELETE FROM table
        r"\b(create|alter|drop)\s+(table|database|view|index|procedure|function)\s+\w+",  # DDL
        r"\b(grant|revoke)\s+\w+\s+on\s+\w+",  # Permissions
        r"\btruncate\s+table\s+\w+",  # TRUNCATE TABLE
    ]

    # Check for the primary, high-confidence patterns first
    for pattern in sql_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    # 2. Fallback check for a combination of other common SQL keywords
    # This can catch partial queries or less common statements.
    secondary_keywords = [
        r"\bwhere\s+\w+\s*[=<>!]",  # WHERE with condition
        r"\bgroup\s+by\s+\w+",  # GROUP BY
        r"\border\s+by\s+\w+",  # ORDER BY
        r"\b(left|right|inner|outer|full)\s+join\s+\w+",  # JOINs
        r"\bon\s+\w+\.\w+\s*=\s*\w+\.\w+",  # ON join condition
        r"\bhaving\s+\w+\s*[=<>!]",  # HAVING with condition
        r"\bunion\s+(all\s+)?select",  # UNION
        r"\blike\s+['\"][^'\"]*['\"]",  # LIKE with pattern
        r"\bin\s*\([^)]*\)",  # IN clause
        r"\bexists\s*\(",  # EXISTS
        r"\bcount\s*\(",  # COUNT function
        r"\bmax\s*\(",  # MAX function
        r"\bmin\s*\(",  # MIN function
        r"\bavg\s*\(",  # AVG function
        r"\bsum\s*\(",  # SUM function
    ]

    found_keywords = 0
    for keyword_pattern in secondary_keywords:
        if re.search(keyword_pattern, text, re.IGNORECASE):
            found_keywords += 1

    # If we find at least two of these secondary keywords, it's a strong sign.
    if found_keywords >= 2:
        return True

    return False
