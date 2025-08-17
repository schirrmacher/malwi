import re

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


def is_code(text: str, threshold: float = 0.3) -> bool:
    """
    Analyzes a string to determine if it likely contains code.

    This function uses a heuristic model to detect actual programming code,
    while avoiding false positives on natural language text with punctuation.

    Args:
        text (str): The input string to check.
        threshold (float): A value between 0 and 1.0. A higher value requires
                         more evidence before classifying text as code.
                         Defaults to 0.3 (balanced).

    Returns:
        bool: True if the string is likely code, False otherwise.
    """
    if not isinstance(text, str) or not text.strip():
        return False

    # Must have meaningful length for code detection
    if len(text.strip()) < 3:
        return False

    score = 0.0

    # 1. --- Strong Code Indicators (High Weight) ---
    # These are patterns that strongly suggest actual code
    strong_patterns = [
        r"\b(def|function|class|struct|interface)\s+\w+\s*[\(\{]",  # Function/class definitions
        r"\blambda\s+\w*\s*:",  # Lambda functions
        r"\b(if|while|for)\s*[\(\s].*[\)\s]*[\{\:]",  # Control structures with proper syntax
        r"[a-zA-Z_]\w*\s*[\[\(]\s*[^)]*\s*[\]\)]\s*[\{\=\;]",  # Function calls/array access with syntax
        r"[a-zA-Z_]\w*\.\w+\s*\(",  # Method calls like obj.method()
        r"=>\s*[\{\w]|function\s*\(",  # Arrow functions or function expressions
        r"</?[a-zA-Z][^>]*>",  # HTML/XML tags
        r"[\[\{]\s*[\"']?\w+[\"']?\s*:\s*[\"']?[^,}\]]+[\"']?",  # JSON/object syntax
        r"^\s*[a-zA-Z_]\w*\s*[=\+\-\*\/]\s*[^;]+;?\s*$",  # Assignment statements
        r"\b(import|from)\s+[\w\.]+(\s+import\s+|\s+as\s+)",  # Import statements
        r"[.#][\w-]+\s*\{[^}]*\}",  # CSS selectors with properties
        r"[\w-]+\s*:\s*[^;]+;",  # CSS property declarations
        r"^\s*\[[^\]]+\]\s*$",  # Configuration file sections like [section]
        r"^\s*[\w-]+\s*=\s*[^=]+$",  # Configuration assignments like key=value
        r"^\s*#(?!#)",  # Comments (including Python)
        r"^\s*//",  # JavaScript/C++ comments
        r"/\*.*?\*/",  # Multi-line comments
        r"\bprint\s*\(",  # Print statements
    ]

    for pattern in strong_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
            score += 0.35  # High weight for strong indicators

    # 2. --- Programming Keywords (Medium Weight) ---
    code_keywords = {
        "def",
        "function",
        "class",
        "struct",
        "interface",
        "enum",
        "if",
        "else",
        "elif",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "return",
        "yield",
        "break",
        "continue",
        "try",
        "catch",
        "finally",
        "throw",
        "raise",
        "import",
        "from",
        "include",
        "require",
        "const",
        "let",
        "var",
        "public",
        "private",
        "protected",
        "static",
        "lambda",
        "async",
        "await",
        "typeof",
        "instanceof",
        "extends",
        "new",
        "delete",
        "this",
        "self",
        "super",
    }

    found_keywords = {
        word for word in re.findall(r"\b\w+\b", text.lower()) if word in code_keywords
    }

    # Award keyword points - more generous for imports and basic constructs
    if len(found_keywords) >= 3:
        score += 0.3
    elif len(found_keywords) >= 2:
        score += 0.25
    elif len(found_keywords) >= 1:
        score += 0.15

    # 3. --- Code Syntax Patterns (Medium Weight) ---
    syntax_patterns = [
        r"==|!=|<=|>=|\+=|-=|\*=|/=|&&|\|\||::",  # Programming operators
        r"[a-zA-Z_]\w*\[[\w\s\+\-\*\/\%]+\]",  # Array/object access with expressions
        r"\{\s*[^}]+\s*\}",  # Code blocks or object literals
        r";[\s]*$|;[\s]*\n",  # Semicolon line endings
    ]

    syntax_count = sum(1 for pattern in syntax_patterns if re.search(pattern, text))
    if syntax_count >= 2:
        score += 0.25
    elif syntax_count >= 1:
        score += 0.1

    # 4. --- Indented Multi-line Code ---
    lines = text.splitlines()
    if len(lines) > 1:
        indented_lines = sum(1 for line in lines[1:] if re.match(r"^\s{2,}|^\t", line))
        if indented_lines >= 2:
            score += 0.2
        elif indented_lines >= 1:
            score += 0.1

    # 5. --- Negative Indicators (Reduce Score) ---
    # These patterns suggest natural language, not code
    # Only apply if we don't already have strong code indicators
    if (
        score < 0.3
    ):  # Only apply negative patterns if we don't have strong code evidence
        negative_patterns = [
            r"\b(PASSED|FAILED|Starting|Finished|Test|Case|COMPLETED)\b",  # Test output
            r"^[\-\=\*]{3,}.*[\-\=\*]{3,}$",  # Decorative lines
            r"^\d+\.\d+\.",  # Numbered sections
            r"^[A-Z][a-z]+.*[a-z]\s*$",  # Sentence-like capitalization
        ]

        for pattern in negative_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score -= 0.2
                break

    # Check for natural language patterns - but be more careful
    natural_language_words = [
        "the",
        "and",
        "or",
        "but",
        "with",
        "that",
        "this",
        "have",
        "will",
        "would",
        "should",
        "could",
        "are",
        "is",
        "was",
        "were",
    ]
    natural_word_count = sum(
        1
        for word in re.findall(r"\b\w+\b", text.lower())
        if word in natural_language_words
    )

    # Only penalize if we have many natural language words, few code keywords, AND no strong code patterns
    if natural_word_count >= 3 and len(found_keywords) <= 1 and score < 0.3:
        score -= 0.3

    return score >= threshold


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
