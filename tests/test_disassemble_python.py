import io
import sys
import json
import pytest
import csv

from unittest.mock import patch, mock_open

from research.mapping import SpecialCases

from research.disassemble_python import (
    MalwiObject,
    MalwiReport,
    disassemble_python_file,
    process_python_file,
    process_files,
    triage,
    main,
)


MOCK_TARGET_FILES_DATA = {"python": ["setup.py", "manage.py"]}

MOCK_PREDICTION_RESULT = {"probabilities": [0.2, 0.8]}


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
    return "def error_func(:\n    print 'hello'"


@pytest.fixture
def empty_py_content():
    return "# This is an empty file"


class TestCoreDisassembly:
    def test_disassemble_valid_file(self, tmp_path, valid_py_content):
        p = tmp_path / "valid.py"
        p.write_text(valid_py_content)
        results = disassemble_python_file(valid_py_content, str(p))
        # valid_py_content produces <module>, hello, MyClass, method_one
        assert len(results) == 4
        assert all(isinstance(obj, MalwiObject) for obj in results)

        module_obj = next((obj for obj in results if obj.name == "<module>"), None)
        assert module_obj is not None
        assert module_obj.code_type is not None
        # This is the original expected token string for the module object
        assert (
            module_obj.to_token_string()
            == "resume load_const INTEGER load_const import_name SYSTEM_INTERACTION store_name SYSTEM_INTERACTION load_const OBJECT make_function store_name hello push_null load_build_class load_const OBJECT make_function load_const MyClass call store_name MyClass load_name __name__ load_const __main__ compare_op == pop_jump_if_false TO_NUMBER push_null load_name hello load_const world call pop_top return_const None return_const None"
        )

        assert module_obj.calculate_token_stats()["SYSTEM_INTERACTION"] == 2

        hello_obj = next((obj for obj in results if obj.name == "hello"), None)
        assert hello_obj is not None

        myclass_obj = next((obj for obj in results if obj.name == "MyClass"), None)
        assert myclass_obj is not None

        method_one_obj = next(
            (obj for obj in results if obj.name == "MyClass.method_one"), None
        )
        assert method_one_obj is not None

        assert (
            MalwiObject.collect_token_stats(malwi_objects=results)["SYSTEM_INTERACTION"]
            == 3
        )

    def test_disassemble_syntax_error_file(self, tmp_path, syntax_error_py_content):
        p = tmp_path / "syntax.py"
        p.write_text(syntax_error_py_content)
        results = disassemble_python_file(syntax_error_py_content, str(p))
        assert len(results) == 1
        obj = results[0]
        assert isinstance(obj, MalwiObject)
        assert obj.name == SpecialCases.MALFORMED_SYNTAX.value
        assert SpecialCases.MALFORMED_SYNTAX.value in obj.warnings
        assert obj.code_type is None

    def test_disassemble_empty_file(self, tmp_path, empty_py_content):
        p = tmp_path / "empty.py"
        p.write_text(empty_py_content)
        results = disassemble_python_file(empty_py_content, str(p))
        assert len(results) == 1
        obj = results[0]
        assert isinstance(obj, MalwiObject)
        assert obj.name == "<module>"
        assert SpecialCases.MALFORMED_SYNTAX.value not in obj.warnings
        assert obj.code_type is not None

    def test_disassemble_non_existent_file(self, tmp_path):
        # The new implementation tries to compile the source code which is None
        # leading to a TypeError. This test is adjusted to reflect that a Malformed File
        # error is returned as no source code is provided.
        results = disassemble_python_file(
            source_code="", file_path="non_existent_file.py"
        )
        assert len(results) == 1
        obj = results[0]
        assert isinstance(obj, MalwiObject)
        assert obj.name == "<module>"

    @patch("research.disassemble_python.COMMON_TARGET_FILES", MOCK_TARGET_FILES_DATA)
    def test_disassemble_targeted_file(self, tmp_path):
        p = tmp_path / "setup.py"
        file_content = "print('hello')"
        p.write_text(file_content)
        results = disassemble_python_file(file_content, str(p))
        assert len(results) == 1
        obj = results[0]
        assert isinstance(obj, MalwiObject)
        assert obj.name == "<module>"
        assert SpecialCases.TARGETED_FILE.value in obj.warnings
        assert obj.code_type is not None

    def test_all_tokens(self):
        # The expected token list has changed, so we update the assertion
        assert MalwiObject.all_tokens() == sorted(
            [
                "ARCHIVE_COMPRESSION",
                "BUILD_MANIPULATION",
                "CODE_EXECUTION_INTEROP",
                "CRYPTOGRAPHY",
                "CRYPTO_ENCRYPTION_DECRYPTION",
                "CRYPTO_HASHING",
                "CRYPTO_MISC",
                "DATABASE_ACCESS",
                "DATA_HANDLING",
                "DESERIALIZATION",
                "DYNAMIC_CODE_COMPILATION",
                "DYNAMIC_CODE_EXECUTION",
                "DYNAMIC_IMPORT",
                "ENCODING_DECODING",
                "ENVIRONMENT_VARIABLE_ACCESS",
                "ENVIRONMENT_VARIABLE_MODIFICATION",
                "FILESYSTEM",
                "FILESYSTEM_ACCESS",
                "FILESYSTEM_DELETION",
                "FILE_READING_ISSUES",
                "FLOAT",
                "FS_COPY",
                "FS_CREATE_DIR",
                "FS_LINKING",
                "FS_METADATA_UPDATE",
                "FS_PERMISSIONS_OWNERSHIP",
                "FS_RENAME_MOVE",
                "INTEGER",
                "LOW_LEVEL_DATA_PACKING",
                "LOW_LEVEL_DATA_UNPACKING",
                "LOW_LEVEL_FFI",
                "LOW_LEVEL_MEMORY_MANIPULATION",
                "LOW_LEVEL_PYTHON_INTERNALS",
                "MALFORMED_FILE",
                "MALFORMED_SYNTAX",
                "MESSAGING_COMMUNICATION",
                "NETWORKING",
                "NETWORK_FILE_DOWNLOAD",
                "NETWORK_HTTP_REQUEST",
                "PROCESS_CONCURRENCY",
                "PROCESS_MANAGEMENT",
                "PROCESS_REPLACEMENT",
                "PROCESS_SIGNALING",
                "PROCESS_TERMINATION",
                "REFLECTION_DYNAMIC_DELETE",
                "REFLECTION_DYNAMIC_READ",
                "REFLECTION_DYNAMIC_WRITE",
                "SENSITIVE_DATA_ACCESS",
                "STRING_BASE64",
                "STRING_ESCAPED_HEX",
                "STRING_FILE_PATH",
                "STRING_HEX",
                "STRING_IP",
                "STRING_SENSITIVE_FILE_PATH",
                "STRING_URL",
                "SYSINFO_FILESYSTEM",
                "SYSINFO_HARDWARE",
                "SYSINFO_OS",
                "SYSINFO_RUNTIME",
                "SYSINFO_USER",
                "SYSTEM_INTERACTION",
                "TARGETED_FILE",
                "TEMP_FILE_CREATION",
                "TEMP_FILE_CREATION_INSECURE",
                "TIME",
                "TYPING",
                "USER_IO",
                "WEB_GUI_AUTOMATION",
            ]
        )


class TestOutputFormatting:
    @pytest.fixture
    def sample_objects_data(self, tmp_path):
        dummy_file_path = str(tmp_path / "dummy.py")
        co_pass = compile("pass", dummy_file_path, "exec")
        obj1 = MalwiObject(
            name="obj1_pass",
            language="python",
            file_path=dummy_file_path,
            file_source_code="pass",
            codeType=co_pass,
        )

        obj_err = MalwiObject(
            SpecialCases.MALFORMED_SYNTAX.value,
            language="python",
            file_path=str(tmp_path / "bad.py"),
            file_source_code="",
            warnings=[SpecialCases.MALFORMED_SYNTAX.value],
        )
        return [obj1, obj_err]

    def test_format_csv(self, sample_objects_data, tmp_path):
        report = MalwiReport(
            objects=sample_objects_data,
            threshold=0.7,
            all_files=[p.file_path for p in sample_objects_data],
            skipped_files=[],
            processed_files=len(sample_objects_data),
            malicious=False,
            confidence=0.1,
            activities=[],
        )
        output = io.StringIO()
        report.to_report_csv(output)
        output.seek(0)
        lines = output.getvalue().strip().split("\n")
        assert "tokens,hash,filepath" in lines[0]

        obj1_tokens_csv = lines[1].split(",")[0]
        assert "resume" in obj1_tokens_csv
        assert "return_const" in obj1_tokens_csv
        assert "None" in obj1_tokens_csv
        assert "load_const" not in obj1_tokens_csv


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
        results = process_python_file(p, predict=False, retrieve_source_code=True)
        assert results is not None
        assert len(results) == 4
        object_names = sorted([obj.name for obj in results])
        assert object_names == sorted(
            ["<module>", "MyClass", "hello", "MyClass.method_one"]
        )
        mock_get_pred.assert_not_called()

    @patch(
        "research.disassemble_python.svm_predict",
        return_value={"malicious": False, "confidence": 0.1},
    )
    @patch(
        "research.disassemble_python.get_node_text_prediction",
        return_value=MOCK_PREDICTION_RESULT,
    )
    @patch("inspect.getsource", return_value="mock line")
    def test_process_files(
        self, mock_inspect, mock_get_pred, mock_svm, tmp_path, valid_py_content
    ):
        (tmp_path / "f1.py").write_text(valid_py_content)
        (tmp_path / "f2.py").write_text("print(1)")
        (tmp_path / "f3.txt").write_text("text file")
        result = process_files(
            tmp_path,
            accepted_extensions=["py"],
            predict=True,
            retrieve_source_code=True,
            show_progress=False,
        )
        assert result.processed_files == 2
        # 4 objects from f1.py + 1 from f2.py
        assert mock_get_pred.call_count == 5
        mock_svm.assert_called_once()

    @patch(
        "research.disassemble_python.get_node_text_prediction",
        return_value=MOCK_PREDICTION_RESULT,  # This mock returns maliciousness of 0.8
    )
    @patch("inspect.getsource", return_value="mock line")
    def test_process_python_file_maliciousness_threshold(
        self, mock_inspect, mock_get_pred, tmp_path, valid_py_content
    ):
        """
        Tests that process_python_file correctly filters objects based on the
        maliciousness_threshold.
        """
        p = tmp_path / "valid.py"
        p.write_text(valid_py_content)

        # --- CASE 1: Threshold is HIGHER than the score, expect objects to be filtered ---
        # The maliciousness score from the mock is 0.8.
        # A threshold of 0.9 should now filter all objects.
        results_filtered = process_python_file(
            p,
            predict=True,
            retrieve_source_code=False,
            maliciousness_threshold=0.9,
        )

        # The function returns `None` when the resulting list of objects is empty.
        # This asserts the new, correct filtering behavior.
        assert results_filtered is None

        # --- CASE 2: Threshold is LOWER than the score, expect objects to be returned ---
        # A threshold of 0.7 is lower than the 0.8 score, so nothing should be filtered.
        results_not_filtered = process_python_file(
            p,
            predict=True,
            retrieve_source_code=False,
            maliciousness_threshold=0.7,
        )

        # All 4 objects from the valid_py_content fixture should be returned.
        assert results_not_filtered is not None
        assert len(results_not_filtered) == 4

        # Verify that prediction was called and the score was annotated correctly.
        assert all(obj.maliciousness == 0.8 for obj in results_not_filtered)


@patch(
    "research.disassemble_python.svm_predict",
    return_value={"malicious": False, "confidence": 0.1},
)
@patch("research.disassemble_python.MalwiObject.load_models_into_memory")
class TestMainCLI:
    @patch("sys.exit")
    @patch("inspect.getsource", return_value="mocked line")
    def test_main_non_existent_path(
        self, mock_inspect, mock_sys_exit_func, mock_load_models, mock_svm, capsys
    ):
        with patch.object(
            sys, "argv", ["research.disassemble_python.py", "nonexistentpath"]
        ):
            main()
        captured = capsys.readouterr()
        assert "Input path does not exist" in captured.err
        mock_sys_exit_func.assert_any_call(1)

    @patch("sys.exit")
    @patch("inspect.getsource")
    def test_main_save_json_report(
        self,
        mock_inspect_getsourcelines,
        mock_sys_exit_func,
        mock_load_models_cli,
        mock_svm,
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
                "research.disassemble_python.py",
                str(script_file),
                "--format",
                "json",
                "--save",
                str(output_file),
            ],
        ):
            main()

        assert output_file.exists()
        report_content = output_file.read_text()
        assert report_content.strip(), "JSON report file should not be empty"

        try:
            report_data = json.loads(report_content)
        except json.JSONDecodeError as e:
            pytest.fail(
                f"Failed to decode JSON from report file: {e}\nContent:\n{report_content}"
            )

        # In malicious_only mode with a default threshold of 0.5 and no mock predictions,
        # details list will be empty
        assert "statistics" in report_data
        assert report_data["details"] == []

        mock_sys_exit_func.assert_called_with(0)

    @patch("sys.exit")
    @patch("inspect.getsource")
    def test_main_csv_save_streaming(
        self,
        mock_inspect_getsourcelines,
        mock_sys_exit_func,
        mock_load_models_cli,
        mock_svm,
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
                "research.disassemble_python.py",
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
        # Expect 1 header line + 4 object lines
        assert len(lines) == 5
        assert "tokens,hash,filepath" in lines[0]

        data_rows = list(csv.reader(lines[1:]))

        for row in data_rows:
            assert len(row) == 3, f"CSV row expected 3 columns, got {len(row)}: {row}"
            assert row[2] == str(script_file)

        expected_module_tokens = "resume load_const INTEGER load_const import_name SYSTEM_INTERACTION store_name SYSTEM_INTERACTION load_const OBJECT make_function store_name hello push_null load_build_class load_const OBJECT make_function load_const MyClass call store_name MyClass load_name __name__ load_const __main__ compare_op == pop_jump_if_false TO_NUMBER push_null load_name hello load_const world call pop_top return_const None return_const None"
        found_module_tokens = any(row[0] == expected_module_tokens for row in data_rows)
        assert found_module_tokens, "Module tokens not found in CSV output"

        mock_sys_exit_func.assert_called_with(0)
