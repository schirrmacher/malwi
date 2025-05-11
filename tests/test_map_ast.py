import re
import pytest

from research.normalize_data import (
    is_hex,
    is_base64,
    is_valid_ip,
    is_valid_url,
    map_identifier,
    FUNCTION_MAPPING,
    create_malwi_nodes_from_bytes,
    parse_python_string_literal,
)


def test_python_string_literals():
    test_cases = [
        '"""hello"""',
        "'''hello'''",
        '"hello"',
        "'hello'",
        'r"hello"',
        "f'''hello'''",
        'b"""hello"""',
        "hello",
    ]
    for t in test_cases:
        assert "hello" == parse_python_string_literal(t)


def test_is_url():
    assert is_valid_url("https://example.com")
    assert is_valid_url("http://example.com/path")
    assert not is_valid_url("not a url")


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1")
    assert is_valid_ip("8.8.8.8")
    assert not is_valid_ip("999.999.999.999")
    assert is_valid_ip("2001:db8::1")
    assert not is_valid_ip("not.an.ip")


def test_is_hex():
    assert not is_hex("dGVzdA==")
    assert is_hex("48656c6c6f")


def test_is_base64():
    assert is_base64("dGVzdA==")
    assert not is_base64("####")


def test_map_identifier():
    assert "FILESYSTEM_ACCESS" == map_identifier(
        identifier="os.fdopen", language="python", mapping_table=FUNCTION_MAPPING
    )
    assert "FILESYSTEM_ACCESS" == map_identifier(
        identifier="xxx.os.fdopen", language="python", mapping_table=FUNCTION_MAPPING
    )
    assert None == map_identifier(
        identifier="os.fdopen.xxx", language="python", mapping_table=FUNCTION_MAPPING
    )


def test_empty_nodes():
    empty = bytes()
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=empty, file_path="test.py", language="python"
    )

    assert len(result) == 0


def test_function_name_too_long():
    code = b"""
def xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx():
    pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="lala.py", language="python"
    )
    assert result[0].to_string() == "F_DEF VERY_LONG_FUNCTION_NAME BLOCK PASS_STATEMENT"


def test_nested_functions():
    code = b"""
class OuterClass:
    def __init__(self, name: str):
        self.name = name

    def greet(self) -> None:
        print(f"Hello from OuterClass, {self.name}!")

    class InnerClass:
        def __init__(self, value: int):
            self.value = value

        def show_value(self) -> None:
            print(f"Value from InnerClass: {self.value}")

        class DeepInnerClass:
            def __init__(self, text: str):
                self.text = text

            def repeat_text(self, times: int) -> str:
                def build_repeated() -> str:
                    # Nested function inside the method
                    return (self.text + " ") * times

                return build_repeated().strip()
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="lala.py", language="python"
    )
    assert result[0].to_string() == "F_DEF init BLOCK EXP ASSIGNMENT MEMBER_ACCESS"
    assert (
        result[1].to_string()
        == "F_DEF greet BLOCK EXP F_CALL_USER_IO1 STRING_LEN_S_ENT_HIGH"
    )
    assert result[2].to_string() == "F_DEF init BLOCK EXP ASSIGNMENT MEMBER_ACCESS"
    assert (
        result[3].to_string()
        == "F_DEF show.value BLOCK EXP F_CALL_USER_IO1 STRING_LEN_S_ENT_HIGH"
    )
    assert result[4].to_string() == "F_DEF init BLOCK EXP ASSIGNMENT MEMBER_ACCESS"
    assert (
        result[5].to_string()
        == "F_DEF repeat.text BLOCK F_DEF build.repeated BLOCK RETURN_STATEMENT RETURN_STATEMENT RETURN_STATEMENT RETURN_STATEMENT F_CALL build.repeated.strip MEMBER_ACCESS F_CALL build.repeated"
    )
    assert (
        result[6].to_string()
        == "F_DEF build.repeated BLOCK RETURN_STATEMENT RETURN_STATEMENT"
    )


def test_sensitive_file_warning():
    code = b"""
def foo():
    pass

def foo():
    pass


class Bar:
    def method(self):
        pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="setup.py", language="python"
    )
    assert result[0].warnings == ["TARGET_FILE"]


def test_python_nodes():
    code = b"""
def foo():
    pass

class Bar:
    def method(self):
        pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="test.py", language="python"
    )

    assert result is not None
    assert len(result) == 2
    types = [node.node.type for node in result]
    assert "function_definition" in types


def test_critical_file():
    code = b"""
def foo():
    pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="setup.py", language="python"
    )
    assert result[0].to_string() == "TARGET_FILE F_DEF foo BLOCK PASS_STATEMENT"


@pytest.mark.skip(
    reason="Skipping this test temporarily because:  Incompatible Language version 15. Must be between 13 and 14"
)
def test_rust_nodes():
    code = b"""
fn foo() -> i32 {
    42
}

struct Bar {
    value: i32,
}
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="test.rs", language="rust"
    )

    assert result is not None
    assert len(result) == 2
    types = [node.node.type for node in result]
    assert "function_item" in types
    assert "struct_item" in types


def test_python_cases():
    code = [
        b"""
def obscure_eval_rename(new_name):
    os.fdopen("abc", eval("SGVsbG8gV29ybGQh"))
""",
        b"""
def open(new_name, other):
    x = self.abc()
""",
        b"""
from typing import List

class Book:

    CONST = "hello"

    def __init__(self, title: str, author: str, pages: int, tags: List[str]) -> None:
        self.title = title
        self.author = author
        self.pages = pages
        self.tags = tags

    def is_long(self) -> bool:
        return self.pages > 300

    def __str__(self) -> str:
        return f"'{self.title}' by {self.author}, {self.pages} pages"
""",
        b"""
def test():
    x = "www.evil.de"
    y = '192.168.1.10'
""",
    ]
    expected = [
        "F_DEF obscure.eval.rename BLOCK EXP F_CALL_FILESYSTEM_ACCESS2 STRING_HEX_LEN_XS_ENT_MED DYNAMIC_CODE_EXECUTION1 STRING_BASE64_LEN_S_ENT_HIGH MEMBER_ACCESS",
        "F_DEF_FILESYSTEM_ACCESS BLOCK EXP ASSIGNMENT F_CALL self.abc MEMBER_ACCESS",
        "F_DEF init BLOCK EXP ASSIGNMENT MEMBER_ACCESS EXP ASSIGNMENT MEMBER_ACCESS EXP ASSIGNMENT MEMBER_ACCESS EXP ASSIGNMENT MEMBER_ACCESSF_DEF is.long BLOCK RETURN_STATEMENT RETURN_STATEMENT BINARY_OPERATION MEMBER_ACCESS NUMERICF_DEF str BLOCK RETURN_STATEMENT RETURN_STATEMENT STRING_LEN_S_ENT_HIGH",
        "F_DEF test BLOCK EXP ASSIGNMENT STRING_STRING_URL EXP ASSIGNMENT STRING_STRING_IP",
    ]

    for i, c in enumerate(code):
        result = create_malwi_nodes_from_bytes(
            source_code_bytes=c, file_path="", language="python"
        )
        actual = ""
        for node in result:
            actual += node.to_string()

        assert re.sub(r"\s+", " ", actual).strip() == expected[i], (
            f"Expected at {i}: {expected[i]}"
        )


def test_node_hashing():
    code = b"""
def foo():
    pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="test.py", language="python"
    )

    assert result[0].to_string() == "F_DEF foo BLOCK PASS_STATEMENT"
    assert (
        result[0].to_string_hash()
        == "09ce504e602dfa4a8082d7e5d3cc7f8f14e4e6d318e453838b3c0711acff3601"
    )
