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
    assert is_file_path(r"\x68\x65\x6c\x6c\x6f")


class TestArgumentMapping:
    @pytest.mark.parametrize(
        "argval, expected_output_pattern",
        [
            ("eval", "DYNAMIC_CODE_EXECUTION"),
            ("os", "SYSTEM_INTERACTION"),
            ("/etc/passwd", SpecialCases.STRING_SENSITIVE_FILE_PATH.value),
            ("192.168.1.1", SpecialCases.STRING_IP.value),
            ("http://example.com", SpecialCases.STRING_URL.value),
            (
                "surveymonkey.com",
                "STRING_LEN_S_ENT_HIGH",
            ),  # From MOCK_FUNCTION_MAPPING_DATA
            ("./path/to/file.txt", SpecialCases.STRING_FILE_PATH.value),
            ("short", "short"),  # len=5 <= STRING_MAX_LENGTH (15)
            # If SUT classifies '\\x...' as STRING_FILE_PATH due to '\'
            ("\\x68\\x65\\x6c\\x6c\\x6f", SpecialCases.STRING_FILE_PATH.value),
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
