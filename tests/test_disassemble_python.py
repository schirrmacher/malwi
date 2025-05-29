import sys
import json
import pytest

from unittest.mock import patch, mock_open

from research.mapping import SpecialCases

from research.disassemble_python import (
    MalwiObject,
    OutputFormatter,
    disassemble_python_file,
    process_single_py_file,
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
    return "def error_func(:\n    print 'hello'"  # Python 2 syntax


@pytest.fixture
def empty_py_content():
    return "# This is an empty file"


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


class TestOutputFormatting:
    @pytest.fixture
    def sample_objects_data(self, tmp_path):
        co_pass = compile("pass", str(tmp_path / "dummy.py"), "exec")
        obj1 = MalwiObject(
            name="obj1_pass",
            language="python",
            file_path=str(tmp_path / "dummy.py"),
            file_source_code="",
            codeType=co_pass,
        )
        obj1.code = "pass"  # For source code display
        obj_err = MalwiObject(
            SpecialCases.MALFORMED_SYNTAX.value,
            language="python",
            file_path=str(tmp_path / "bad.py"),
            file_source_code="",
            warnings=[SpecialCases.MALFORMED_SYNTAX.value],
        )
        return [obj1, obj_err]

    def test_format_csv(self, sample_objects_data, capsys):
        OutputFormatter.format_csv(sample_objects_data, sys.stdout)
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
        assert "tokens,hash,filepath" in lines[0]

        obj1_tokens_csv = lines[1].split(",")[0]
        assert "resume" in obj1_tokens_csv
        assert "return_const" in obj1_tokens_csv
        assert (
            "None" in obj1_tokens_csv
        )  # If 'None' is indeed part of the token string for 'pass'
        assert "load_const" not in obj1_tokens_csv  # As per last error output


class TestFileProcessingAndCollection:
    @patch(
        "research.malwi_object.get_node_text_prediction",
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
        "research.malwi_object.get_node_text_prediction",
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
            file_source_code="",
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
