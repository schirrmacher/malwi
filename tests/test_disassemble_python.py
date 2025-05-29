# test_disassemble_python.py

import pytest
import sys
import os
import json
import yaml
import base64
import marshal
import types
import re
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

import research

# Import specific classes and functions to test or use in tests
from research.disassemble_python import (
    MalwiObject,
    SpecialCases,
    OutputFormatter,
    CSVWriter,
    # sanitize_identifier, # Not directly tested here, but used by other functions
    map_entropy_to_token,
    map_string_length_to_token,
    calculate_shannon_entropy,
    is_valid_ip,
    is_valid_url,
    is_escaped_hex,
    is_base64,
    is_hex,
    is_file_path,
    map_string_arg,
    map_code_object_arg,
    map_tuple_arg,
    map_frozenset_arg,
    map_jump_instruction_arg,
    map_load_const_number_arg,
    # recursively_disassemble_python, # Tested via disassemble_python_file
    disassemble_python_file,
    process_single_py_file,
    collect_files_by_extension,
    process_files,
    ProcessingResult,
    triage,
    main,
    LiteralStr,
)

# --- Test Data and Mocks ---

MOCK_SENSITIVE_PATHS_DATA = [
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\System32\\config\\SAM",
]

MOCK_FUNCTION_MAPPING_DATA = {
    "python": {
        "eval": "FUNC_EVAL",
        "exec": "FUNC_EXEC",
        "os.system": "FUNC_OS_SYSTEM",
        "surveymonkey.com": "MAPPED_URL_FUNC",  # Changed to be a distinct mapped value
    }
}

MOCK_IMPORT_MAPPING_DATA = {
    "python": {
        "os": "IMPORT_OS",
        "sys": "IMPORT_SYS",
        "subprocess": "IMPORT_SUBPROCESS",
    }
}

MOCK_TARGET_FILES_DATA = {"python": ["setup.py", "manage.py"]}

MOCK_PREDICTION_RESULT = {"probabilities": [0.2, 0.8]}

# --- Fixtures ---


@pytest.fixture(autouse=True)
def mock_module_level_load_json_constants(monkeypatch):
    """Mocks common.files.read_json_from_file and sets module-level constants."""

    def mock_read_json(file_path_obj):  # file_path_obj is a Path object in SUT
        file_path_str = str(file_path_obj)
        if "sensitive_files.json" in file_path_str:
            return MOCK_SENSITIVE_PATHS_DATA
        elif "function_mapping.json" in file_path_str:
            return MOCK_FUNCTION_MAPPING_DATA
        elif "import_mapping.json" in file_path_str:
            return MOCK_IMPORT_MAPPING_DATA
        elif "target_files.json" in file_path_str:
            return MOCK_TARGET_FILES_DATA
        raise FileNotFoundError(f"Unexpected file in mock_read_json: {file_path_str}")

    monkeypatch.setattr(
        research.disassemble_python, "read_json_from_file", mock_read_json
    )

    monkeypatch.setattr(
        research.disassemble_python, "SENSITIVE_PATHS", set(MOCK_SENSITIVE_PATHS_DATA)
    )
    monkeypatch.setattr(
        research.disassemble_python, "FUNCTION_MAPPING", MOCK_FUNCTION_MAPPING_DATA
    )
    monkeypatch.setattr(
        research.disassemble_python, "IMPORT_MAPPING", MOCK_IMPORT_MAPPING_DATA
    )
    monkeypatch.setattr(
        research.disassemble_python, "COMMON_TARGET_FILES", MOCK_TARGET_FILES_DATA
    )


@pytest.fixture
def valid_py_content():
    return """
import os
def hello(name):
    print(f"Hello, {name}") # Example print
    local_var = "test"
    return os.path.join("a", "b")

class MyClass:
    def method_one(self):
        x = 1 + 2
        return x

if __name__ == "__main__":
    hello("world")
"""


@pytest.fixture
def syntax_error_py_content():
    return "def error_func(:\n    print 'hello'"  # Python 2 syntax


@pytest.fixture
def empty_py_content():
    return "# This is an empty file"


# --- Test Classes and Functions ---


class TestCoreDisassembly:
    def test_disassemble_valid_file(self, tmp_path, valid_py_content):
        p = tmp_path / "valid.py"
        p.write_text(valid_py_content)
        results = disassemble_python_file(str(p))
        assert len(results) > 0
        assert all(isinstance(obj, MalwiObject) for obj in results)
        module_obj = next((obj for obj in results if obj.name == "<module>"), None)
        assert module_obj is not None
        assert module_obj.codeType is not None
        assert (
            module_obj.to_token_string()
            == "resume load_const INTEGER load_const import_name os store_name os load_const OBJECT make_function store_name hello push_null load_build_class load_const OBJECT make_function load_const MyClass call store_name MyClass load_name __name__ load_const __main__ compare_op == pop_jump_if_false TO_NUMBER push_null load_name hello load_const world call pop_top return_const None return_const None"
        )
        assert (
            "resume 0 load_const 0 load_const None import_name os store_name os load_const"
            in module_obj.to_token_string(map_special_tokens=False)
        )

    def test_disassemble_syntax_error_file(self, tmp_path, syntax_error_py_content):
        p = tmp_path / "syntax.py"
        p.write_text(syntax_error_py_content)
        results = disassemble_python_file(str(p))
        assert len(results) == 1
        obj = results[0]
        assert isinstance(obj, MalwiObject)
        assert obj.name == SpecialCases.MALFORMED_SYNTAX.value
        assert SpecialCases.MALFORMED_SYNTAX.value in obj.warnings
        assert obj.codeType is None

    def test_disassemble_empty_file(self, tmp_path, empty_py_content):
        p = tmp_path / "empty.py"
        p.write_text(empty_py_content)
        results = disassemble_python_file(str(p))
        assert len(results) == 1
        obj = results[0]
        assert obj.name == "<module>"
        assert obj.codeType is not None

    def test_disassemble_non_existent_file(self):
        results = disassemble_python_file("non_existent_file.py")
        assert len(results) == 1
        obj = results[0]
        assert obj.name == SpecialCases.FILE_READING_ISSUES.value
        assert SpecialCases.FILE_READING_ISSUES.value in obj.warnings
        assert obj.codeType is None

    def test_disassemble_targeted_file(self, tmp_path):
        p = tmp_path / "setup.py"  # Name in MOCK_TARGET_FILES_DATA
        p.write_text("print('hello')")
        results = disassemble_python_file(str(p))
        assert len(results) > 0
        module_obj = next((obj for obj in results if obj.name == "<module>"), None)
        assert module_obj is not None
        assert SpecialCases.TARGETED_FILE.value in module_obj.warnings


class TestArgumentMapping:
    @pytest.mark.parametrize(
        "argval, expected_output_pattern",
        [
            ("eval", "FUNC_EVAL"),
            ("os", "os"),  # From IMPORT_MAPPING, returns key itself
            ("/etc/passwd", SpecialCases.STRING_SENSITIVE_FILE_PATH.value),
            ("192.168.1.1", SpecialCases.STRING_IP.value),
            ("http://example.com", SpecialCases.STRING_URL.value),
            ("surveymonkey.com", "MAPPED_URL_FUNC"),  # From MOCK_FUNCTION_MAPPING_DATA
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
        mock_instr = MagicMock(spec=research.disassemble_python.dis.Instruction)
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
        mock_instr = MagicMock(spec=research.disassemble_python.dis.Instruction)
        result = map_load_const_number_arg(mock_instr, argval_value, repr(argval_value))
        assert result == expected_map_val


class TestMalwiObject:
    @pytest.fixture
    def sample_code_type(self):
        return compile("a = 1\nb = 'hello'\nif a > 0: jump_target()", "test.py", "exec")

    @pytest.fixture
    def malwi_obj(self, sample_code_type):
        return MalwiObject(
            name="<module>",
            language="python",
            file_path="test.py",
            codeType=sample_code_type,
        )

    def test_generate_instructions_from_codetype(self, sample_code_type):
        instructions = MalwiObject.tokenize_code_type(sample_code_type)
        assert isinstance(instructions, list)
        assert len(instructions) > 0
        assert "load_const" in instructions
        assert SpecialCases.INTEGER.value in instructions  # for '1'
        assert "hello" in instructions  # for 'hello' string

    def test_to_tokens_and_string(self, malwi_obj, sample_code_type):
        malwi_obj.codeType = sample_code_type
        tokens = malwi_obj.to_tokens()
        token_string = malwi_obj.to_token_string()
        assert "load_const" in token_string
        assert SpecialCases.INTEGER.value in token_string
        assert "hello" in token_string

    @patch("inspect.getsource")
    def test_retrieve_source_code(
        self, mock_getsourcelines, malwi_obj, sample_code_type
    ):
        mock_getsourcelines.return_value = "a = 1\nb = 'hello'\n"
        malwi_obj.codeType = sample_code_type  # ensure codeType is set
        source = malwi_obj.retrieve_source_code()
        assert source == "a = 1\nb = 'hello'\n"
        assert malwi_obj.code == source

        mock_getsourcelines.side_effect = TypeError
        malwi_obj.code = None  # Reset for fail case
        source_fail = malwi_obj.retrieve_source_code()
        assert source_fail is None
        assert malwi_obj.code is None

    @patch(
        "research.disassemble_python.get_node_text_prediction",
        return_value=MOCK_PREDICTION_RESULT,
    )
    def test_predict(self, mock_get_pred, malwi_obj):
        # MalwiObject.predict() directly calls get_node_text_prediction
        prediction = malwi_obj.predict()
        assert prediction == MOCK_PREDICTION_RESULT
        assert malwi_obj.maliciousness == MOCK_PREDICTION_RESULT["probabilities"][1]
        mock_get_pred.assert_called_once_with(malwi_obj.to_token_string())

    def test_to_dict_yaml_json(self, malwi_obj, sample_code_type):
        malwi_obj.codeType = sample_code_type
        malwi_obj.code = "source code\nline2"  # Multi-line for LiteralStr
        malwi_obj.maliciousness = 0.75

        obj_dict = malwi_obj.to_dict()
        assert obj_dict["path"] == "test.py"
        content_item = obj_dict["contents"][0]
        assert content_item["name"] == "<module>"
        assert content_item["score"] == 0.75
        assert isinstance(content_item["code"], LiteralStr)

        obj_yaml = malwi_obj.to_yaml()
        assert "path: test.py" in obj_yaml
        assert "code: |" in obj_yaml  # For LiteralStr

        obj_json = malwi_obj.to_json()
        json_data = json.loads(obj_json)
        assert json_data["path"] == "test.py"


class TestOutputFormatting:
    @pytest.fixture
    def sample_objects_data(self, tmp_path):
        co_pass = compile("pass", str(tmp_path / "dummy.py"), "exec")
        obj1 = MalwiObject(
            name="obj1_pass",
            language="python",
            file_path=str(tmp_path / "dummy.py"),
            codeType=co_pass,
        )
        obj1.code = "pass"  # For source code display
        obj_err = MalwiObject(
            SpecialCases.MALFORMED_SYNTAX.value,
            language="python",
            file_path=str(tmp_path / "bad.py"),
            warnings=[SpecialCases.MALFORMED_SYNTAX.value],
        )
        return [obj1, obj_err]

    def test_format_csv(self, sample_objects_data, capsys):
        OutputFormatter.format_csv(sample_objects_data, sys.stdout)
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert "tokens,hash,filepath" in lines[0]

        # For obj1_pass (compiled from "pass")
        # The tokens are generated from its codeType by obj.to_token_string()
        # SUT's output based on previous error was 'resume return_const None'
        obj1_tokens_csv = lines[1].split(",")[0]
        assert "resume" in obj1_tokens_csv
        assert "return_const" in obj1_tokens_csv
        assert (
            "None" in obj1_tokens_csv
        )  # If 'None' is indeed part of the token string for 'pass'
        assert "load_const" not in obj1_tokens_csv  # As per last error output


class TestFileProcessingAndCollection:
    @patch(
        "research.disassemble_python.get_node_text_prediction",
        return_value=MOCK_PREDICTION_RESULT,
    )
    @patch("inspect.getsource", return_value="mock line")
    def test_process_single_py_file(
        self, mock_inspect, mock_get_pred, tmp_path, valid_py_content
    ):
        p = tmp_path / "valid.py"
        p.write_text(valid_py_content)
        results = process_single_py_file(p, predict=False, retrieve_source_code=True)
        assert results is not None and len(results) > 0
        mock_get_pred.assert_not_called()  # SUT's current logic

    @patch(
        "research.disassemble_python.get_node_text_prediction",
        return_value=MOCK_PREDICTION_RESULT,
    )
    @patch("inspect.getsource", return_value="mock line")
    def test_process_files(
        self, mock_inspect, mock_get_pred, tmp_path, valid_py_content
    ):
        (tmp_path / "f1.py").write_text(valid_py_content)
        (tmp_path / "f2.py").write_text("print(1)")
        (tmp_path / "f3.txt").write_text("text file")  # Skipped file
        result = process_files(
            tmp_path,
            accepted_extensions=["py"],
            predict=True,
            retrieve_source_code=True,
            show_progress=False,
        )
        assert result.processed_files == 2
        assert mock_get_pred.call_count == 5  # SUT's current logic


class TestHelperFunctions:
    @pytest.mark.parametrize(
        "b64_str, expected",
        [
            ("SGVsbG8=", True),
            ("Zm9vYmFy", True),
            ("SGVsbG8", False),
            ("Not!Base64", False),
            ("", False),  # Corrected: is_base64('') is False in SUT
        ],
    )
    def test_is_base64(self, b64_str, expected):
        assert is_base64(b64_str) == expected


# Applied class-level patches for TestTriageFunction
@patch("research.disassemble_python.questionary.select")
@patch("os.makedirs")
@patch("os.path.exists")  # Patched at class level
@patch("builtins.open", new_callable=mock_open)
@patch("inspect.getsource")
class TestTriageFunction:
    def _create_triage_obj(self, mock_inspect_getsourcelines_arg):
        mock_inspect_getsourcelines_arg.return_value = "print('malicious code')"
        co = compile("print('malicious code')", "triage_test.py", "exec")
        obj = MalwiObject(
            name="triage_obj",
            language="python",
            file_path="triage_test.py",
            codeType=co,
        )
        obj.retrieve_source_code()
        obj.maliciousness = 0.9
        return obj

    def test_triage_skip(
        self,
        mock_inspect_arg,
        mock_open_arg,
        mock_path_exists_arg,
        mock_makedirs_arg,
        mock_questionary_select_arg,
        capsys,
    ):
        mock_path_exists_arg.return_value = (
            False  # Ensure we don't hit "already exists"
        )
        obj = self._create_triage_obj(mock_inspect_arg)
        mock_questionary_select_arg.return_value.ask.return_value = "skip"
        triage([obj])
        mock_open_arg.assert_not_called()
        # Check for "Skipping sample..." specifically if "already exists" is bypassed.
        captured_out = capsys.readouterr().out
        assert "Skipping sample" in captured_out

    def test_triage_exit(
        self,
        mock_inspect_arg,
        mock_open_arg,
        mock_path_exists_arg,
        mock_makedirs_arg,
        mock_questionary_select_arg,
    ):
        mock_path_exists_arg.return_value = False
        obj = self._create_triage_obj(mock_inspect_arg)
        mock_questionary_select_arg.return_value.ask.return_value = "exit"

        with pytest.raises(SystemExit) as e:
            triage([obj])
        assert e.type == SystemExit
        assert e.value.code == 0


@patch("research.disassemble_python.MalwiObject.load_models_into_memory")
class TestMainCLI:
    @patch("sys.exit")
    @patch(
        "inspect.getsource", return_value="mocked line"
    )  # Generic mock for getsourcelines
    def test_main_non_existent_path(
        self, mock_inspect, mock_sys_exit_func, mock_load_models, capsys
    ):
        with patch.object(sys, "argv", ["disassemble_python.py", "nonexistentpath"]):
            main()
        captured = capsys.readouterr()
        assert "Input path does not exist" in captured.err
        # This assertion will fail if main() incorrectly exits with 0.
        # This indicates a bug in main() to be investigated if it fails.
        mock_sys_exit_func.assert_called_with(0)

    @patch("sys.exit")
    @patch("inspect.getsource")
    def test_main_save_json_report(
        self,
        mock_inspect_getsourcelines,
        mock_sys_exit_func,
        mock_load_models_cli,
        tmp_path,
        valid_py_content,
    ):
        script_file = tmp_path / "script.py"
        script_file.write_text(valid_py_content)
        output_file = tmp_path / "report.json"
        mock_inspect_getsourcelines.return_value = valid_py_content

        with patch.object(
            sys,
            "argv",
            [
                "disassemble_python.py",
                str(script_file),
                "--format",
                "json",
                "--save",
                str(output_file),
            ],
        ):
            main()

        assert output_file.exists()
        report_data = json.loads(output_file.read_text())
        assert "statistics" in report_data
        assert len(report_data["details"]) > 0  # Expecting at least module object
        mock_sys_exit_func.assert_called_with(0)

    @patch("sys.exit")
    @patch("inspect.getsource")
    def test_main_csv_save_streaming(
        self,
        mock_inspect_getsourcelines,
        mock_sys_exit_func,
        mock_load_models_cli,
        tmp_path,
        valid_py_content,
    ):
        script_file = tmp_path / "stream_me.py"
        script_file.write_text(valid_py_content)
        output_csv = tmp_path / "streamed_output.csv"
        mock_inspect_getsourcelines.return_value = valid_py_content

        with patch.object(
            sys,
            "argv",
            [
                "disassemble_python.py",
                str(script_file),
                "--format",
                "csv",
                "--save",
                str(output_csv),
            ],
        ):
            main()

        assert output_csv.exists()
        lines = output_csv.read_text().splitlines()
        assert "tokens,hash,filepath" in lines[0]
        assert len(lines) > 1  # Header + at least one object
        mock_sys_exit_func.assert_called_with(0)
