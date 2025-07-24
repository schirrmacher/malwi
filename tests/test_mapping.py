import dis
import pytest

from unittest.mock import MagicMock

from research.mapping import (
    SpecialCases,
    is_valid_ip,
    is_valid_url,
    is_escaped_hex,
    is_base64,
    is_file_path,
    is_localhost,
    contains_url,
    map_entropy_to_token,
    map_string_length_to_token,
    map_code_object_arg,
    map_frozenset_arg,
    calculate_shannon_entropy,
    map_load_const_number_arg,
    map_jump_instruction_arg,
    map_tuple_arg,
    map_string_arg,
)


def test_map_entropy_to_token():
    assert map_entropy_to_token(0.5) == "ENT_LOW"


def test_map_string_length_to_token():
    assert map_string_length_to_token(5) == "LEN_XS"


def test_calculate_shannon_entropy():
    assert calculate_shannon_entropy(b"aabb") == 1.0


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1")


def test_is_valid_url():
    assert is_valid_url("http://example.com")


def test_is_escaped_hex():
    assert is_escaped_hex(r"\x41\x42\x43")


def test_is_base64():
    assert is_base64("SGVsbG8gd29ybGQ=")
    assert not is_base64("SGVsbG8gd29ybGQ")


def test_is_file_path():
    assert is_file_path("/usr/bin/python")
    # Escaped hex strings should not be considered file paths
    assert not is_file_path(r"\x68\x65\x6c\x6c\x6f")
    # But actual file paths should be
    assert is_file_path("./config.json")
    assert is_file_path("C:\\Windows\\System32\\cmd.exe")
    assert is_file_path("script.py")


def test_is_localhost():
    # Test exact localhost patterns
    assert is_localhost("localhost")
    assert is_localhost("127.0.0.1")
    assert is_localhost("::1")
    assert is_localhost("0.0.0.0")
    assert is_localhost("local")
    assert is_localhost("loopback")

    # Test localhost with ports
    assert is_localhost("localhost:8080")
    assert is_localhost("127.0.0.1:3000")

    # Test localhost in URLs
    assert is_localhost("http://localhost/api")
    assert is_localhost("https://127.0.0.1:8080/test")

    # Test private network ranges (RFC 1918)
    assert is_localhost("192.168.1.1")
    assert is_localhost("10.0.0.1")
    assert is_localhost("172.16.0.1")
    assert is_localhost("172.31.255.255")

    # Test non-localhost addresses
    assert not is_localhost("google.com")
    assert not is_localhost("8.8.8.8")
    assert not is_localhost("172.32.0.1")  # Outside private range
    assert not is_localhost("192.169.1.1")  # Outside private range
    assert not is_localhost("")
    assert not is_localhost("just_text")


def test_contains_url():
    # Test strings that contain URLs
    assert contains_url("Check out https://example.com for more info")
    assert contains_url("Visit http://test.com or ftp://files.com")
    assert contains_url("JavaScript: javascript:alert('test')")
    assert contains_url("Data URI: data:text/plain;base64,SGVsbG8=")
    assert contains_url("SSH to ssh://user@server.com")
    assert contains_url("Use telnet://host:23 for connection")
    assert contains_url("File at file:///path/to/file")
    assert contains_url("Script with vbscript:msgbox('hello')")

    # Test strings that don't contain URLs
    assert not contains_url("This is just plain text")
    assert not contains_url("No protocols here")
    assert not contains_url("http")  # Too short
    assert not contains_url("://example")  # No protocol
    assert not contains_url("")
    assert not contains_url("short")  # Below minimum length


class TestArgumentMapping:
    @pytest.mark.parametrize(
        "argval, expected_output_pattern",
        [
            ("eval", "DYNAMIC_CODE_EXECUTION"),
            ("os", "SYSTEM_INTERACTION"),
            ("/etc/passwd", SpecialCases.STRING_SENSITIVE_FILE_PATH.value),
            ("8.8.8.8", SpecialCases.STRING_IP.value),  # Public IP
            ("localhost", SpecialCases.STRING_LOCALHOST.value),  # Localhost
            ("127.0.0.1", SpecialCases.STRING_LOCALHOST.value),  # Localhost IP
            ("192.168.1.1", SpecialCases.STRING_LOCALHOST.value),  # Private IP
            ("http://example.com", SpecialCases.STRING_URL.value),
            (
                "Check out https://example.com for more",
                SpecialCases.CONTAINS_URL.value,
            ),  # Contains URL
            (
                "surveymonkey.com",
                "STRING_LEN_S_ENT_HIGH",
            ),  # From MOCK_FUNCTION_MAPPING_DATA
            ("./path/to/file.txt", SpecialCases.STRING_FILE_PATH.value),
            ("short", "short"),  # len=5 <= STRING_MAX_LENGTH (15)
            # Escaped hex strings are now classified as STRING_ESCAPED_HEX
            (
                "\\x68\\x65\\x6c\\x6c\\x6f",
                f"{SpecialCases.STRING_ESCAPED_HEX.value}_LEN_S_ENT_MED",
            ),
            ("68656c6c6f", "68656c6c6f"),  # len=10 <= STRING_MAX_LENGTH (15)
            (
                "SGVsbG8gd29ybGQ=",
                f"{SpecialCases.STRING_BASE64.value}_LEN_S_ENT_HIGH",
            ),  # len=16
            ("a" * 50, f"{SpecialCases.STRING_HEX.value}_LEN_S_ENT_LOW"),  # len=50
            (
                "this_is_a_long_generic_string_greater_than_15_chars",
                "STRING_LEN_L_ENT_HIGH",
            ),  # len=55
        ],
    )
    def test_map_string_arg(self, argval, expected_output_pattern, monkeypatch):
        result = map_string_arg(argval, repr(argval))

        is_complex_token = (
            any(
                token_prefix in expected_output_pattern
                for token_prefix in [
                    SpecialCases.STRING_BASE64.value,
                    SpecialCases.STRING_HEX.value,
                    "STRING_",
                ]
            )
            and "_" in expected_output_pattern
        )

        if is_complex_token:
            parts = expected_output_pattern.split("_")
            expected_main_type_prefix = parts[0]
            # LEN_S, ENT_LOW etc. parts
            expected_suffix_parts = parts[1:]

            assert result.startswith(expected_main_type_prefix)
            for suffix_part_component in expected_suffix_parts:
                # Handle cases like "LEN_S" vs "S" or "ENT_LOW" vs "LOW"
                assert suffix_part_component in result
        else:  # For exact matches
            assert result == expected_output_pattern

    def test_map_code_object_arg(self):
        co = compile("x=1", "<string>", "exec")
        assert map_code_object_arg(co, repr(co)) == "OBJECT"

    @pytest.mark.parametrize(
        "argval, expected",
        [
            (("cmd", "/bin/sh", 123), "/bin/sh INTEGER cmd"),
            ((1.0, 2.0), SpecialCases.FLOAT.value),
            ((1.0, "text"), "FLOAT text"),
            ((), ""),
        ],
    )
    def test_map_tuple_arg(self, argval, expected):
        assert map_tuple_arg(argval, repr(argval)) == expected

    @pytest.mark.parametrize(
        "argval, expected",
        [(frozenset({"admin", "user", 404.0}), "FLOAT admin user"), (frozenset(), "")],
    )
    def test_map_frozenset_arg(self, argval, expected):
        assert map_frozenset_arg(argval, repr(argval)) == expected

    def test_map_jump_instruction_arg(self):
        mock_instr = MagicMock(spec=dis.Instruction)
        assert map_jump_instruction_arg(mock_instr) == "TO_NUMBER"

    @pytest.mark.parametrize(
        "argval_value, expected_map_val",
        [
            (100, SpecialCases.INTEGER.value),
            (3.14, SpecialCases.FLOAT.value),
            (compile("y=2", "<string>", "exec"), "OBJECT"),
            ("a_const_string", "a_const_string"),
        ],
    )
    def test_map_load_const_number_arg(self, argval_value, expected_map_val):
        mock_instr = MagicMock(spec=dis.Instruction)
        result = map_load_const_number_arg(mock_instr, argval_value, repr(argval_value))
        assert result == expected_map_val
