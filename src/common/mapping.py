import re
from functools import lru_cache

import socket
import urllib
import codecs
import pathlib
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
    STRING_BASH = "STRING_BASH"
    STRING_SQL = "STRING_SQL"
    STRING_CODE = "STRING_CODE"
    STRING = "STRING"
    MALFORMED_FILE = "MALFORMED_FILE"
    MALFORMED_SYNTAX = "MALFORMED_SYNTAX"
    TARGETED_FILE = "TARGETED_FILE"
    BOOLEAN = "BOOLEAN"
    INTEGER = "INTEGER"
    FLOAT = "FLOAT"
    OBJECT = "OBJECT"


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

# Pre-compiled regex patterns for performance optimization
# Bash detection patterns
_BASH_SHEBANG = re.compile(r"^#!\s*/(usr/)?bin/(bash|sh|zsh)")
_BASH_KEYWORDS = re.compile(
    r"\b(ls|cd|echo|rm|grep|awk|sed|cat|curl|wget|sudo|chmod|chown|mkdir|touch|cp|mv|find|xargs|tar|gzip|gunzip|zip|unzip|ps|kill|pkill|top|df|du|mount|umount|export|source|alias|unset|set|eval|exec|if|then|else|elif|fi|for|while|do|done|case|esac|function|return|break|continue|true|false|test|exit|trap|wait|sleep|head|tail|sort|uniq|cut|paste|join|comm|diff|patch|tee|nc|ssh|scp|rsync|git|docker|kubectl|npm|pip|apt|yum|brew|systemctl|service|journalctl|cron|at)\b",
    re.IGNORECASE,
)
_BASH_VARS = re.compile(r"\$[a-zA-Z_]|\$\{[^}]+\}")
_BASH_COMMAND_SUB = re.compile(r"\$\([^)]+\)|`[^`]+`")
_BASH_OPERATORS = re.compile(r"\||>>?|<|&&|\|\||;")
_BASH_OPTIONS = re.compile(r"(^|\s)-[a-zA-Z]|\s--[a-zA-Z][a-zA-Z0-9-]*")
_BASH_TEST_BRACKETS = re.compile(r"\[\s+.*\s+\]")
_BASH_EXIT_STATUS = re.compile(r"\$\?")
_BASH_COMMENTS = re.compile(r"^\s*#(?!#)", re.MULTILINE)
_BASH_REDIRECTION = re.compile(r"2>&1|1>&2|&>|2>")
_BASH_WILDCARDS = re.compile(r"[^\\][\*\?]")
_BASH_PATHS = re.compile(r"~\/|\/home\/|\/usr\/|\/etc\/|\/var\/|\/tmp\/")

# Code detection patterns
_CODE_STRONG_PATTERNS = re.compile(
    r"\b(def|function|class|struct|interface)\s+\w+\s*[\(\{]|\blambda\s+\w*\s*:|\b(if|while|for)\s*[\(\s].*[\)\s]*[\{\:]|[a-zA-Z_]\w*\s*[\[\(]\s*[^)]*\s*[\]\)]\s*[\{\=\;]|[a-zA-Z_]\w*\.\w+\s*\(|=>\s*[\{\w]|function\s*\(|</?[a-zA-Z][^>]*>|[\[\{]\s*[\"']?\w+[\"']?\s*:\s*[\"']?[^,}\]]+[\"']?|\b(import|from)\s+[\w\.]+(\s+import\s+|\s+as\s+)|[.#][\w-]+\s*\{[^}]*\}|[\w-]+\s*:\s*[^;]+;|^\s*\[[^\]]+\]\s*$|^\s*[\w-]+\s*=\s*[^=]+$|^\s*#(?!#)|^\s*//|/\*.*?\*/|\bprint\s*\(",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
_CODE_KEYWORDS = re.compile(
    r"\b(def|function|class|struct|interface|enum|if|else|elif|for|while|do|switch|case|return|yield|break|continue|try|catch|finally|throw|raise|import|from|include|require|const|let|var|public|private|protected|static|lambda|async|await|typeof|instanceof|extends|new|delete|this|self|super)\b",
    re.IGNORECASE,
)
_CODE_SYNTAX = re.compile(
    r"==|!=|<=|>=|\+=|-=|\*=|/=|&&|\|\||::|;[\s]*$|;[\s]*\n", re.MULTILINE
)
_CODE_NEGATIVE = re.compile(
    r"\b(PASSED|FAILED|Starting|Finished|Test|Case|COMPLETED)\b|^[\-\=\*]{3,}.*[\-\=\*]{3,}$|^\d+\.\d+\.",
    re.IGNORECASE | re.MULTILINE,
)
_CODE_NATURAL = re.compile(
    r"\b(the|and|or|but|with|that|this|have|will|would|should|could|are|is|was|were)\b",
    re.IGNORECASE,
)

# SQL detection patterns
_SQL_MAIN_PATTERNS = re.compile(
    r"\bselect\s+[\w\*,\s\.]+\s+from\s+[\w\.]+(\s+where|\s+group|\s+order|\s+limit|;|\s*--|\s*$)|\binsert\s+into\s+\w+\s*\([^)]*\)\s*values\s*\(|\bupdate\s+\w+\s+set\s+\w+\s*=|\bdelete\s+from\s+\w+|\b(create|alter|drop)\s+(table|database|view|index|procedure|function)\s+\w+|\b(grant|revoke)\s+\w+\s+on\s+\w+|\btruncate\s+table\s+\w+",
    re.IGNORECASE,
)
_SQL_SECONDARY = re.compile(
    r"\bwhere\s+\w+\s*[=<>!]|\bgroup\s+by\s+\w+|\border\s+by\s+\w+|\b(left|right|inner|outer|full)\s+join\s+\w+|\bon\s+\w+\.\w+\s*=\s*\w+\.\w+|\bhaving\s+\w+\s*[=<>!]|\bunion\s+(all\s+)?select|\blike\s+['\"][^'\"]*['\"]|\bin\s*\([^)]*\)|\bexists\s*\(|\b(count|max|min|avg|sum)\s*\(",
    re.IGNORECASE,
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


@lru_cache(maxsize=8192)
def _is_bash_code_cached(text: str, threshold: int = 3) -> bool:
    """
    Internal cached function for bash code detection.
    """
    if not text or len(text) < 2:
        return False

    score = 0

    # Quick shebang check (strong indicator)
    if _BASH_SHEBANG.search(text):
        return True  # Early exit for obvious bash

    # Count bash keywords efficiently
    keyword_matches = len(_BASH_KEYWORDS.findall(text.lower()))
    if keyword_matches >= 3:
        score += 4
    elif keyword_matches >= 2:
        score += 3
    elif keyword_matches >= 1:
        score += 2

    # Early exit if we already have enough score
    if score >= threshold:
        return True

    # Check bash-specific patterns
    if _BASH_VARS.search(text):
        score += 2
    if _BASH_COMMAND_SUB.search(text):
        score += 3
    if _BASH_OPERATORS.search(text):
        score += 1
    if _BASH_OPTIONS.search(text):
        score += 1
    if _BASH_TEST_BRACKETS.search(text):
        score += 2
    if _BASH_EXIT_STATUS.search(text):
        score += 1
    if _BASH_COMMENTS.search(text):
        score += 1
    if _BASH_REDIRECTION.search(text):
        score += 2
    if _BASH_WILDCARDS.search(text):
        score += 1
    if _BASH_PATHS.search(text):
        score += 1

    return score >= threshold


def is_bash_code(text: str, threshold: int = 3) -> bool:
    """
    Optimized function to determine if text is likely bash code.
    Uses pre-compiled regexes and caching for maximum performance.
    """
    if not isinstance(text, str):
        return False
    return _is_bash_code_cached(text, threshold)


@lru_cache(maxsize=8192)
def _is_code_cached(text: str, threshold: float = 0.3) -> bool:
    """
    Internal cached function for code detection.
    """
    if not text or len(text) < 3:
        return False

    # For very short strings, we need different scoring
    if len(text) < 20:
        score = 0.0
        if _CODE_STRONG_PATTERNS.search(text):
            score += 0.4
        if _CODE_SYNTAX.search(text):
            score += 0.3
        # Check for keywords even in short strings
        if _CODE_KEYWORDS.search(text):
            score += 0.2
        return score >= threshold

    score = 0.0

    # 1. Strong code patterns check (combined regex)
    if _CODE_STRONG_PATTERNS.search(text):
        score += 0.4

    # Early exit if we already have strong evidence
    if score >= threshold:
        return True

    # 2. Count programming keywords efficiently
    keyword_matches = len(_CODE_KEYWORDS.findall(text))
    if keyword_matches >= 3:
        score += 0.3
    elif keyword_matches >= 2:
        score += 0.25
    elif keyword_matches >= 1:
        score += 0.15

    # Early exit check
    if score >= threshold:
        return True

    # 3. Code syntax patterns
    if _CODE_SYNTAX.search(text):
        score += 0.2

    # 4. Indented multi-line code (quick check)
    if "\n" in text and ("\n    " in text or "\n\t" in text):
        score += 0.15

    # 5. Negative patterns (only if score is borderline)
    if score < 0.4:
        if _CODE_NEGATIVE.search(text):
            score -= 0.2

        # Natural language penalty
        natural_matches = len(_CODE_NATURAL.findall(text))
        if natural_matches >= 3 and keyword_matches <= 1:
            score -= 0.3

    return score >= threshold


def is_code(text: str, threshold: float = 0.3) -> bool:
    """
    Optimized function to determine if text likely contains code.
    Uses pre-compiled regexes and caching for maximum performance.
    """
    if not isinstance(text, str):
        return False
    return _is_code_cached(text, threshold)


@lru_cache(maxsize=8192)
def _is_sql_cached(text: str) -> bool:
    """
    Internal cached function for SQL detection.
    """
    if not text.strip():
        return False

    # Quick early exit for very short strings
    if len(text) < 6:  # Minimum SQL would be "SELECT"
        return False

    # 1. Check high-confidence SQL patterns first (early exit)
    if _SQL_MAIN_PATTERNS.search(text):
        return True

    # 2. Check secondary patterns for partial/complex queries
    secondary_matches = len(_SQL_SECONDARY.findall(text))

    # If we find at least two secondary patterns, likely SQL
    return secondary_matches >= 2


def is_sql(text: str) -> bool:
    """
    Optimized function to determine if text contains SQL statements.
    Uses pre-compiled regexes and caching for maximum performance.
    """
    if not isinstance(text, str):
        return False
    return _is_sql_cached(text)
