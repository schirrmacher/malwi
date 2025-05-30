import sys
import json
import pytest
import csv  # Import csv module

from unittest.mock import patch, mock_open

from research.mapping import SpecialCases

from research.disassemble_python import (
    MalwiObject,
    OutputFormatter,
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
        assert module_obj.codeType is not None
        # This is the original expected token string for the module object
        assert (
            module_obj.to_token_string()
            == "resume load_const INTEGER load_const import_name os store_name os load_const OBJECT make_function store_name hello push_null load_build_class load_const OBJECT make_function load_const MyClass call store_name MyClass load_name __name__ load_const __main__ compare_op == pop_jump_if_false TO_NUMBER push_null load_name hello load_const world call pop_top return_const None return_const None"
        )

        hello_obj = next((obj for obj in results if obj.name == "hello"), None)
        assert hello_obj is not None

        myclass_obj = next((obj for obj in results if obj.name == "MyClass"), None)
        assert myclass_obj is not None

        method_one_obj = next(
            (obj for obj in results if obj.name == "MyClass.method_one"), None
        )
        assert method_one_obj is not None

    def test_disassemble_syntax_error_file(self, tmp_path, syntax_error_py_content):
        p = tmp_path / "syntax.py"
        p.write_text(syntax_error_py_content)
        results = disassemble_python_file(syntax_error_py_content, str(p))
        assert len(results) == 1
        obj = results[0]
        assert isinstance(obj, MalwiObject)
        assert obj.name == SpecialCases.MALFORMED_SYNTAX.value
        assert SpecialCases.MALFORMED_SYNTAX.value in obj.warnings
        assert obj.codeType is None

    def test_disassemble_empty_file(self, tmp_path, empty_py_content):
        p = tmp_path / "empty.py"
        p.write_text(empty_py_content)
        results = disassemble_python_file(empty_py_content, str(p))
        assert len(results) == 1
        obj = results[0]
        assert isinstance(obj, MalwiObject)
        assert obj.name == "<module>"
        assert SpecialCases.MALFORMED_SYNTAX.value not in obj.warnings
        assert obj.codeType is not None

    def test_disassemble_non_existent_file(self):
        results = disassemble_python_file(None, "non_existent_file.py")
        assert len(results) == 1
        obj = results[0]
        assert isinstance(obj, MalwiObject)
        assert obj.name == SpecialCases.MALFORMED_FILE.value
        assert SpecialCases.MALFORMED_FILE.value in obj.warnings
        assert obj.codeType is None

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
        assert obj.codeType is not None


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

    def test_format_csv(self, sample_objects_data, capsys):
        OutputFormatter.format_csv(sample_objects_data, sys.stdout)
        captured = capsys.readouterr()
        lines = captured.out.strip().split("\n")
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
        "research.disassemble_python.get_node_text_prediction",
        return_value=MOCK_PREDICTION_RESULT,
    )
    @patch("inspect.getsource", return_value="mock line")
    def test_process_files(
        self, mock_inspect, mock_get_pred, tmp_path, valid_py_content
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
        assert mock_get_pred.call_count == 5


@patch("research.disassemble_python.questionary.select")
@patch("os.makedirs")
@patch("os.path.exists")
@patch("builtins.open", new_callable=mock_open)
@patch("inspect.getsource")
class TestTriageFunction:
    def _create_triage_obj(self, mock_inspect_getsourcelines_arg):
        source_content = "print('malicious code')"
        mock_inspect_getsourcelines_arg.return_value = source_content

        co = compile(source_content, "triage_test.py", "exec")
        obj = MalwiObject(
            name="triage_obj",
            language="python",
            file_source_code=source_content,
            file_path="triage_test.py",
            codeType=co,
        )
        obj.retrieve_source_code()
        if not obj.code:
            obj.code = source_content

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
        mock_path_exists_arg.return_value = False
        obj = self._create_triage_obj(mock_inspect_arg)
        assert obj.code, "obj.code should be populated for triage test"
        mock_questionary_select_arg.return_value.ask.return_value = "skip"
        triage([obj])
        mock_open_arg.assert_not_called()
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
        assert obj.code, "obj.code should be populated for triage test"
        mock_questionary_select_arg.return_value.ask.return_value = "exit"

        with pytest.raises(SystemExit) as e:
            triage([obj])
        assert e.type == SystemExit
        assert e.value.code == 0


@patch("research.disassemble_python.MalwiObject.load_models_into_memory")
class TestMainCLI:
    @patch("sys.exit")
    @patch("inspect.getsource", return_value="mocked line")
    def test_main_non_existent_path(
        self, mock_inspect, mock_sys_exit_func, mock_load_models, capsys
    ):
        with patch.object(sys, "argv", ["disassemble_python.py", "nonexistentpath"]):
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
        report_content = output_file.read_text()
        assert report_content.strip(), "JSON report file should not be empty"

        try:
            report_data = json.loads(report_content)
        except json.JSONDecodeError as e:
            pytest.fail(
                f"Failed to decode JSON from report file: {e}\nContent:\n{report_content}"
            )

        assert "statistics" in report_data
        assert len(report_data["details"]) == 4

        # Check that each detail object has at least 'filepath' and 'name' (if 'name' is indeed expected)
        # The KeyError for 'name' suggests it might be missing from some detail objects.
        # For now, let's check 'filepath' and that 'contents' (which usually holds name) is present.
        expected_object_names = sorted(
            ["<module>", "hello", "MyClass", "MyClass.method_one"]
        )
        reported_object_info = []

        for detail in report_data["details"]:
            assert detail["path"] == str(script_file)
            # 'contents' is a list of dictionaries, each should have a 'name'
            assert (
                "contents" in detail
                and isinstance(detail["contents"], list)
                and len(detail["contents"]) > 0
            )
            # Assuming the structure where 'name' is inside the first item of 'contents'
            # This might need adjustment based on the actual JSON structure from MalwiObject.to_report_json
            if "name" in detail["contents"][0]:
                reported_object_info.append(detail["contents"][0]["name"])
            elif "name" in detail:  # Fallback if name is at the top level of detail
                reported_object_info.append(detail["name"])

        # If the names are directly in details (e.g. if details are flat list of objects)
        # reported_names = sorted([item.get("name") for item in report_data["details"] if item.get("name")])
        # If names are nested as assumed above:
        assert sorted(reported_object_info) == expected_object_names, (
            f"Reported object names {sorted(reported_object_info)} did not match expected {expected_object_names}"
        )

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
        assert len(lines) == 5
        assert "tokens,hash,filepath" in lines[0]

        # Use csv.reader for robust parsing of CSV lines
        data_rows = list(csv.reader(lines[1:]))  # Skip header

        # Check filepath for all data rows
        for row in data_rows:
            assert len(row) == 3, f"CSV row expected 3 columns, got {len(row)}: {row}"
            assert row[2] == str(script_file)  # Filepath is the 3rd column

        # Check if the expected module token string is present in one of the rows
        expected_module_tokens = "resume load_const INTEGER load_const import_name os store_name os load_const OBJECT make_function store_name hello push_null load_build_class load_const OBJECT make_function load_const MyClass call store_name MyClass load_name __name__ load_const __main__ compare_op == pop_jump_if_false TO_NUMBER push_null load_name hello load_const world call pop_top return_const None return_const None"
        found_module_tokens = False
        for row in data_rows:
            if row[0] == expected_module_tokens:
                found_module_tokens = True
                break
        assert found_module_tokens, "Module tokens not found in CSV output"

        mock_sys_exit_func.assert_called_with(0)
