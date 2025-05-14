import re
import os
import json
import pytest

from typing import Dict

from research.normalize_data import (
    is_hex,
    is_base64,
    is_valid_ip,
    is_valid_url,
    map_identifier,
    FUNCTION_MAPPING,
    create_malwi_nodes_from_bytes,
    parse_python_string_literal,
    compress_tokens,
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


def test_compression():
    code = b"""
def some_func():
    a.b.c.d.e()
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="lala.py", language="python"
    )
    assert (
        result[0].to_string(one_line=True, compression=True)
        == "F_DEF some.func BLOCK EXP F_CALL a.b.c.d.e MEMBER_ACCESS_3 MEMBER_ACCESS"
    )


def test_to_json():
    code = b"""
def hello_world():
    pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="lala.py", language="python"
    )
    json_output = result[0].to_json()
    parsed_json = json.loads(json_output)
    code_content = parsed_json["malicious"][0]["contents"][0]["code"]
    assert code_content == "def hello_world():\n    pass"

    base64_encoded_content = parsed_json["malicious"][0]["contents"][0]["tokens"]
    assert (
        base64_encoded_content == "FILE_LEN_XS F_DEF hello.world BLOCK PASS_STATEMENT"
    )


def test_to_yaml_format():
    code = b"""
def hello_world():
    pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="lala.py", language="python"
    )
    yaml_output = result[0].to_yaml()

    # Define the expected YAML output as a string
    expected_yaml = """
format: 1
malicious:
- path: lala.py
  contents:
  - type: function
    name: hello_world
    score: null
    tokens: FILE_LEN_XS F_DEF hello.world BLOCK PASS_STATEMENT
    code: |-
      def hello_world():
          pass
    hash: d1804a98a2c26e3dc136cd9a3227510d3a7deaed095e8206eb2ec4f5f45266e4
    """

    # Compare the generated YAML output to the expected one
    assert yaml_output.strip() == expected_yaml.strip(), (
        f"YAML output does not match the expected format.\nGenerated: {yaml_output}\nExpected: {expected_yaml}"
    )


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
    assert (
        result[0].to_string()
        == "FILE_LEN_S F_DEF init BLOCK EXP ASSIGNMENT MEMBER_ACCESS"
    )
    assert (
        result[1].to_string()
        == "FILE_LEN_S F_DEF greet BLOCK EXP F_CALL_USER_IO1 STRING_LEN_S_ENT_HIGH"
    )
    assert (
        result[2].to_string()
        == "FILE_LEN_S F_DEF init BLOCK EXP ASSIGNMENT MEMBER_ACCESS"
    )
    assert (
        result[3].to_string()
        == "FILE_LEN_S F_DEF show.value BLOCK EXP F_CALL_USER_IO1 STRING_LEN_S_ENT_HIGH"
    )
    assert (
        result[4].to_string()
        == "FILE_LEN_S F_DEF init BLOCK EXP ASSIGNMENT MEMBER_ACCESS"
    )
    assert (
        result[5].to_string()
        == "FILE_LEN_S F_DEF repeat.text BLOCK F_DEF build.repeated BLOCK RETURN_STATEMENT RETURN_STATEMENT RETURN_STATEMENT RETURN_STATEMENT F_CALL build.repeated.strip MEMBER_ACCESS F_CALL build.repeated"
    )
    assert (
        result[6].to_string()
        == "FILE_LEN_S F_DEF build.repeated BLOCK RETURN_STATEMENT RETURN_STATEMENT"
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
    assert (
        result[0].to_string()
        == "FILE_LEN_XS TARGET_FILE F_DEF foo BLOCK PASS_STATEMENT"
    )


def test_function_name_disabling():
    code = b"""
def make_this_invisible():
    pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="setup.py", language="python"
    )
    assert (
        result[0].to_string(disable_function_names=True)
        == "FILE_LEN_XS TARGET_FILE F_DEF BLOCK PASS_STATEMENT"
    )


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
        "FILE_LEN_XS F_DEF obscure.eval.rename BLOCK EXP F_CALL_FILESYSTEM_ACCESS2 STRING_HEX_LEN_XS_ENT_MED DYNAMIC_CODE_EXECUTION1 STRING_BASE64_LEN_S_ENT_HIGH MEMBER_ACCESS",
        "FILE_LEN_XS F_DEF_FILESYSTEM_ACCESS BLOCK EXP ASSIGNMENT F_CALL self.abc MEMBER_ACCESS",
        "FILE_LEN_S TYPING List F_DEF init BLOCK EXP ASSIGNMENT MEMBER_ACCESS EXP ASSIGNMENT MEMBER_ACCESS EXP ASSIGNMENT MEMBER_ACCESS EXP ASSIGNMENT MEMBER_ACCESSFILE_LEN_S TYPING List F_DEF is.long BLOCK RETURN_STATEMENT RETURN_STATEMENT BINARY_OPERATION MEMBER_ACCESS NUMERICFILE_LEN_S TYPING List F_DEF str BLOCK RETURN_STATEMENT RETURN_STATEMENT STRING_LEN_S_ENT_HIGH",
        "FILE_LEN_XS F_DEF test BLOCK EXP ASSIGNMENT STRING_STRING_URL EXP ASSIGNMENT STRING_STRING_IP",
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

    assert result[0].to_string() == "FILE_LEN_XS F_DEF foo BLOCK PASS_STATEMENT"
    assert (
        result[0].to_string_hash()
        == "13628eb9102cb634225aed763f5dec879d51b980495e2eee4b826a41f8cb709e"
    )


def test_no_import_names():
    code = b"""
import unknown_lib_a
import unknown_lib_b
import unknown_lib_c
def foo():
    pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="test.py", language="python"
    )

    assert (
        result[0].to_string(disable_import_names=True)
        == "FILE_LEN_XS F_DEF foo BLOCK PASS_STATEMENT"
    )


def test_duplicate_import_names():
    code = b"""
import os
import os
def foo():
    pass
"""
    result = create_malwi_nodes_from_bytes(
        source_code_bytes=code, file_path="test.py", language="python"
    )

    assert (
        result[0].to_string(disable_import_names=True)
        == "FILE_LEN_XS SYSTEM_INTERACTION F_DEF foo BLOCK PASS_STATEMENT"
    )


def test_python_import_cases():
    import_statements = [
        b"import ccc\nimport aaa\nimport bbb\ndef dummy():\npass",
        b"import module as alias\ndef dummy():\npass",
        b"import package.module\ndef dummy():\npass",
        b"import package.module as alias\ndef dummy():\npass",
        b"from module import platform\ndef dummy():\npass",
        b"from module import name as alias\ndef dummy():\npass",
        b"from module import name1, name2\ndef dummy():\npass",
        b"from module import name1 as alias1, name2 as alias2\ndef dummy():\npass",
        b"from package.module import name\ndef dummy():\npass",
        b"from package.module import name as alias\ndef dummy():\npass",
        b"from package.module import name1, name2\ndef dummy():\npass",
        b"from package.module import name1 as alias1, name2 as alias2\ndef dummy():\npass",
        b"from module import *\ndef dummy():\npass",
        b"from package.module import *\ndef dummy():\npass",
        b"from . import name\ndef dummy():\npass",
        b"from .. import name\ndef dummy():\npass",
        b"from .module import name\ndef dummy():\npass",
        b"from ..module import name\ndef dummy():\npass",
        b"from ...module import name\ndef dummy():\npass",
        b"from .module import name as alias\ndef dummy():\npass",
        b"from ..module import name1, name2 as alias2\ndef dummy():\npass",
        b"import module1, os\ndef dummy():\npass",
        b"import module1 as m1, module2 as m2\ndef dummy():\npass",
        b"from module import (name1,\n name2)\ndef dummy():\npass",
        b"from module import xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\ndef dummy():\npass",
    ]
    expected = [
        "FILE_LEN_XS aaa bbb ccc F_DEF dummy BLOCK",
        "FILE_LEN_XS module F_DEF dummy BLOCK",
        "FILE_LEN_XS package.module F_DEF dummy BLOCK",
        "FILE_LEN_XS package.module F_DEF dummy BLOCK",
        "FILE_LEN_XS module SYSTEM_INTERACTION F_DEF dummy BLOCK",
        "FILE_LEN_XS module name F_DEF dummy BLOCK",
        "FILE_LEN_XS module name1 F_DEF dummy BLOCK",
        "FILE_LEN_XS module name1 F_DEF dummy BLOCK",
        "FILE_LEN_XS package.module name F_DEF dummy BLOCK",
        "FILE_LEN_XS package.module name F_DEF dummy BLOCK",
        "FILE_LEN_XS package.module name1 F_DEF dummy BLOCK",
        "FILE_LEN_XS package.module name1 F_DEF dummy BLOCK",
        "FILE_LEN_XS module F_DEF dummy BLOCK",
        "FILE_LEN_XS package.module F_DEF dummy BLOCK",
        "FILE_LEN_XS name F_DEF dummy BLOCK",
        "FILE_LEN_XS name F_DEF dummy BLOCK",
        "FILE_LEN_XS name F_DEF dummy BLOCK",
        "FILE_LEN_XS name F_DEF dummy BLOCK",
        "FILE_LEN_XS name F_DEF dummy BLOCK",
        "FILE_LEN_XS name F_DEF dummy BLOCK",
        "FILE_LEN_XS name1 F_DEF dummy BLOCK",
        "FILE_LEN_XS module1 SYSTEM_INTERACTION F_DEF dummy BLOCK",
        "FILE_LEN_XS module1 module2 F_DEF dummy BLOCK",
        "FILE_LEN_XS module name1 F_DEF dummy BLOCK",
        "FILE_LEN_XS module xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx F_DEF dummy BLOCK",
    ]

    for i, c in enumerate(import_statements):
        result = create_malwi_nodes_from_bytes(
            source_code_bytes=c, file_path="", language="python"
        )
        actual = ""
        for node in result:
            actual += node.to_string(disable_imports=False, disable_import_names=False)

        assert len(node.imports) > 0
        assert re.sub(r"\s+", " ", actual).strip() == expected[i], (
            f"Expected at {i}: {expected[i]}"
        )


RULES_FILE_PATH = "test_mapping_rules.json"


@pytest.fixture(scope="module")
def setup_rules_file():
    dummy_rules = {
        "python": {
            "EXP ASSIGNMENT": "EXP_ASSIGNMENT",
            "F_CALL EXP": "F_CALL_EXP",
            "BOOLEAN BOOLEAN": "BOOLEAN_2",
            "BOOLEAN BOOLEAN BOOLEAN": "BOOLEAN_3",
            "MEMBER_ACCESS MEMBER_ACCESS": "MEMBER_ACCESS_2",
            "MEMBER_ACCESS MEMBER_ACCESS MEMBER_ACCESS": "MEMBER_ACCESS_3",
            "NUMERIC NUMERIC": "NUMERIC_2",
            "NUMERIC NUMERIC NUMERIC": "NUMERIC_3",
            "EXP_ASSIGNMENT EXP_ASSIGNMENT": "EXP_ASSIGNMENT_2",
            "EXP_ASSIGNMENT EXP_ASSIGNMENT EXP_ASSIGNMENT": "EXP_ASSIGNMENT_3",
            "IF LPAREN BOOLEAN_3 RPAREN LBRACE": "IF_CONDITION_BLOCK_3",
            "IF LPAREN BOOLEAN_2 RPAREN LBRACE": "IF_CONDITION_BLOCK_2",
        }
    }
    with open(RULES_FILE_PATH, "w") as f:
        json.dump(dummy_rules, f, indent=4)

    yield RULES_FILE_PATH

    os.remove(RULES_FILE_PATH)


DUMMY_RULES_DATA: Dict[str, str] = {
    "EXP ASSIGNMENT": "EXP_ASSIGNMENT",
    "F_CALL EXP": "F_CALL_EXP",
    "BOOLEAN BOOLEAN": "BOOLEAN_2",
    "BOOLEAN BOOLEAN BOOLEAN": "BOOLEAN_3",
    "MEMBER_ACCESS MEMBER_ACCESS": "MEMBER_ACCESS_2",
    "MEMBER_ACCESS MEMBER_ACCESS MEMBER_ACCESS": "MEMBER_ACCESS_3",
    "NUMERIC NUMERIC": "NUMERIC_2",
    "NUMERIC NUMERIC NUMERIC": "NUMERIC_3",
    "EXP_ASSIGNMENT EXP_ASSIGNMENT": "EXP_ASSIGNMENT_2",
    "EXP_ASSIGNMENT EXP_ASSIGNMENT EXP_ASSIGNMENT": "EXP_ASSIGNMENT_3",
    "IF LPAREN BOOLEAN_3 RPAREN LBRACE": "IF_CONDITION_BLOCK_3",
    "IF LPAREN BOOLEAN_2 RPAREN LBRACE": "IF_CONDITION_BLOCK_2",
}


@pytest.fixture
def direct_rules_data() -> Dict[str, str]:
    # Return a copy to prevent modification across tests
    return DUMMY_RULES_DATA.copy()


# --- Test Functions ---


def test_simple_two_token_rule(direct_rules_data: Dict[str, str]):
    tokens = ["EXP", "ASSIGNMENT", "VALUE"]
    expected = ["EXP_ASSIGNMENT", "VALUE"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_three_token_rule_precedence(direct_rules_data: Dict[str, str]):
    tokens = ["BOOLEAN", "BOOLEAN", "BOOLEAN", "AND", "BOOLEAN"]
    expected = ["BOOLEAN_3", "AND", "BOOLEAN"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_no_applicable_rules(direct_rules_data: Dict[str, str]):
    tokens = ["UNKNOWN", "TOKEN", "SEQUENCE"]
    expected = ["UNKNOWN", "TOKEN", "SEQUENCE"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_multiple_rules_applied(direct_rules_data: Dict[str, str]):
    tokens = [
        "MEMBER_ACCESS",
        "MEMBER_ACCESS",
        "MEMBER_ACCESS",
        "DOT",
        "NUMERIC",
        "NUMERIC",
    ]
    expected = ["MEMBER_ACCESS_3", "DOT", "NUMERIC_2"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_overlapping_longer_preferred(direct_rules_data: Dict[str, str]):
    tokens = ["EXP_ASSIGNMENT", "EXP_ASSIGNMENT", "EXP_ASSIGNMENT"]
    expected = ["EXP_ASSIGNMENT_3"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_overlapping_shorter_at_end(direct_rules_data: Dict[str, str]):
    tokens = ["EXP_ASSIGNMENT", "EXP_ASSIGNMENT", "EXP_ASSIGNMENT", "EXP_ASSIGNMENT"]
    expected = ["EXP_ASSIGNMENT_3", "EXP_ASSIGNMENT"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_longer_composite_rule(direct_rules_data: Dict[str, str]):
    tokens = [
        "IF",
        "LPAREN",
        "BOOLEAN",
        "BOOLEAN",
        "BOOLEAN",
        "RPAREN",
        "LBRACE",
        "RETURN",
        "TRUE",
    ]
    expected = ["IF_CONDITION_BLOCK_3", "RETURN", "TRUE"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_shorter_composite_rule_when_longer_not_match(
    direct_rules_data: Dict[str, str],
):
    tokens = [
        "IF",
        "LPAREN",
        "BOOLEAN",
        "BOOLEAN",
        "RPAREN",
        "LBRACE",
        "RETURN",
        "FALSE",
    ]
    expected = ["IF_CONDITION_BLOCK_2", "RETURN", "FALSE"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_empty_token_list(direct_rules_data: Dict[str, str]):
    tokens: List[str] = []
    expected: List[str] = []
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_tokens_substring_of_rule_keys(direct_rules_data: Dict[str, str]):
    tokens = ["BOOLEAN", "BOOLEAN", "BOOLEANISH"]
    expected = ["BOOLEAN_2", "BOOLEANISH"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_sequential_application_three_become_one(direct_rules_data: Dict[str, str]):
    tokens = ["EXP", "ASSIGNMENT", "EXP", "ASSIGNMENT", "EXP", "ASSIGNMENT"]
    expected = ["EXP_ASSIGNMENT_3"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_sequential_application_two_pairs_become_one(direct_rules_data: Dict[str, str]):
    tokens = ["EXP", "ASSIGNMENT", "EXP", "ASSIGNMENT", "VALUE"]
    expected = ["EXP_ASSIGNMENT_2", "VALUE"]
    assert compress_tokens(tokens, direct_rules_data) == expected


def test_empty_rules_data_dict():
    tokens = ["SOME", "TOKENS"]
    expected_tokens = ["SOME", "TOKENS"]  # Expect original tokens back
    # The function now returns the original tokens if rules are empty, not an error.
    assert compress_tokens(tokens, {}) == expected_tokens


def test_empty_rules_and_empty_tokens():
    tokens: List[str] = []
    expected: List[str] = []
    assert compress_tokens(tokens, {}) == expected
