import pytest
import pathlib
import types
import dis
import pytest
import json
import yaml
import io
import sys

from pathlib import Path
from unittest import mock

# Import necessary components from the script to be tested, using the new package path
from research.disassemble_python import (
    MalwiObject,
    SpecialCases,
    OutputFormatter,
    CSVWriter,
    ProcessingResult,
    sanitize_identifier,
    map_identifier,
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
    recursively_disassemble_python,
    disassemble_python_file,
    process_single_py_file,
    process_files,
    collect_files_by_extension,
    main as script_main,
)


# --- Tests for File Processing ---
@mock.patch("research.disassemble_python.disassemble_python_file")
def test_process_single_py_file(mock_disassemble, tmp_path):
    py_file = tmp_path / "sample.py"
    py_file.write_text("a = 1")
    mock_mf_instance = MalwiObject("name", "lang", "file", [])
    mock_disassemble.return_value = [mock_mf_instance]
    result = process_single_py_file(py_file)
    assert result == [mock_mf_instance]


@mock.patch(
    "research.disassemble_python.disassemble_python_file",
    side_effect=Exception("Test error"),
)
def test_process_single_py_file_exception(mock_disassemble_exc, tmp_path, capsys):
    py_file = tmp_path / "error_sample.py"
    py_file.write_text("a = 1")
    assert process_single_py_file(py_file) is None
    assert "An unexpected error occurred" in capsys.readouterr().err


@pytest.fixture(autouse=True)
def mock_global_constants(monkeypatch):
    monkeypatch.setattr("research.disassemble_python.SCRIPT_DIR", pathlib.Path("."))
    monkeypatch.setattr("research.disassemble_python.read_json_from_file", lambda x: {})
    monkeypatch.setattr("research.disassemble_python.SENSITIVE_PATHS", [])
    monkeypatch.setattr("research.disassemble_python.FUNCTION_MAPPING", {"python": {}})
    monkeypatch.setattr("research.disassemble_python.IMPORT_MAPPING", {"python": {}})


@pytest.fixture
def mock_model_predictions(monkeypatch):
    monkeypatch.setattr(
        "research.disassemble_python.initialize_models", mock.MagicMock()
    )
    monkeypatch.setattr(
        "research.disassemble_python.get_node_text_prediction",
        mock.MagicMock(return_value={"probabilities": [0.1, 0.9]}),
    )


@pytest.fixture
def sample_malwifile():
    return MalwiObject(
        name="<module>",
        language="python",
        file_path="test.py",
        instructions=[("LOAD_CONST", "1"), ("RETURN_VALUE", "")],
        codeType=None,
    )


@pytest.fixture
def sample_code_object():
    def _dummy_func():
        pass

    return _dummy_func.__code__


# --- Tests for MalwiFile Class ---
class TestMalwiFile:
    def test_malwifile_initialization(self):
        mf = MalwiObject(
            name="test_func",
            language="python",
            file_path="example.py",
            instructions=[("LOAD_NAME", "print")],
            codeType=None,
            warnings=["TEST_WARNING"],
        )
        assert mf.name == "test_func"

    def test_to_tokens(self, sample_malwifile):
        assert sample_malwifile.to_tokens() == [
            "LOAD_CONST",
            "1",
            "RETURN_VALUE",
        ]

    def test_to_token_string(self, sample_malwifile):
        assert sample_malwifile.to_token_string() == "LOAD_CONST 1 RETURN_VALUE"

    def test_to_string_hash(self, sample_malwifile):
        expected_hash = (
            "d31f3e92b68ef17e63ed31922f3bb7c733d7484fd97d845d034ad184903b3cad"
        )
        assert sample_malwifile.to_string_hash() == expected_hash

    def test_predict(self, sample_malwifile, monkeypatch):
        mock_prediction_func = mock.MagicMock(
            return_value={"probabilities": [0.2, 0.8]}
        )
        monkeypatch.setattr(
            "research.disassemble_python.get_node_text_prediction", mock_prediction_func
        )
        prediction_result = sample_malwifile.predict()
        assert sample_malwifile.maliciousness == 0.8

    def test_to_dict(self, sample_malwifile):
        sample_malwifile.maliciousness = 0.75
        current_hash = sample_malwifile.to_string_hash()
        expected_dict = {
            "path": "test.py",
            "contents": [
                {
                    "name": "<module>",
                    "score": 0.75,
                    "code": "<source not available>",
                    "tokens": "LOAD_CONST 1 RETURN_VALUE",
                    "hash": current_hash,
                }
            ],
        }
        assert sample_malwifile.to_dict() == expected_dict


# --- Tests for OutputFormatter Class ---
class TestOutputFormatter:
    def test_format_text(self, sample_malwifile):
        output_stream = io.StringIO()
        OutputFormatter.format_text([sample_malwifile], output_stream)
        output_content = output_stream.getvalue()
        assert "Disassembly of <code object <module>>:" in output_content
        assert '(file: "test.py")' in output_content

    def test_format_csv(self, sample_malwifile):
        output_stream = io.StringIO()
        OutputFormatter.format_csv([sample_malwifile], output_stream)
        lines = output_stream.getvalue().strip().split("\n")
        assert lines[0] == "tokens,hash,filepath\r"
        expected_data_row = "LOAD_CONST 1 RETURN_VALUE,d31f3e92b68ef17e63ed31922f3bb7c733d7484fd97d845d034ad184903b3cad,test.py"
        assert lines[1] == expected_data_row

    def test_format_json(self, sample_malwifile):
        output_stream = io.StringIO()
        OutputFormatter.format_json([sample_malwifile], output_stream)
        output_content = output_stream.getvalue()
        # Should be valid JSON
        json_data = json.loads(output_content)
        assert "statistics" in json_data
        assert "details" in json_data

    def test_format_yaml(self, sample_malwifile):
        output_stream = io.StringIO()
        OutputFormatter.format_yaml([sample_malwifile], output_stream)
        output_content = output_stream.getvalue()
        # Should be valid YAML
        yaml_data = yaml.safe_load(output_content)
        assert "statistics" in yaml_data
        assert "details" in yaml_data


# --- Tests for CSVWriter Class ---
class TestCSVWriter:
    def test_csv_writer_initialization(self, tmp_path):
        csv_file = tmp_path / "test.csv"
        writer = CSVWriter(csv_file)
        writer.close()

        # Check that headers were written
        content = csv_file.read_text()
        assert "tokens,hash,filepath" in content

    def test_csv_writer_write_objects(self, tmp_path, sample_malwifile):
        csv_file = tmp_path / "test.csv"
        writer = CSVWriter(csv_file)
        writer.write_objects([sample_malwifile])
        writer.close()

        content = csv_file.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 2  # Header + 1 data row
        assert "LOAD_CONST 1 RETURN_VALUE" in lines[1]


# --- Tests for Helper Functions ---
def test_sanitize_identifier():
    assert sanitize_identifier("my_func") == "my.func"
    assert sanitize_identifier(".my_func.") == "my.func"


def test_map_identifier(monkeypatch):
    mock_mapping_table = {
        "python": {
            "os.path.join": "MAPPED_JOIN",
            "requests.get": "MAPPED_GET",
            "get": "MAPPED_FALLBACK_GET",
        }
    }
    assert map_identifier("os.path.join", "python", mock_mapping_table) == "MAPPED_JOIN"


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


def test_is_hex():
    assert is_hex("0123456789abcdefABCDEF")


def test_is_file_path():
    assert is_file_path("/usr/bin/python")
    assert is_file_path(r"\x68\x65\x6c\x6c\x6f")  # Current script behavior


def test_map_string_arg(monkeypatch):
    mock_func_mapping = {"python": {"print": "MAPPED_PRINT_SPECIFIC"}}
    mock_import_mapping = {"python": {"os_module": "MAPPED_OS_SPECIFIC"}}
    mock_sensitive_paths = {"/etc/shadow_specific"}

    monkeypatch.setattr(
        "research.disassemble_python.FUNCTION_MAPPING", mock_func_mapping
    )
    monkeypatch.setattr(
        "research.disassemble_python.IMPORT_MAPPING", mock_import_mapping
    )
    monkeypatch.setattr(
        "research.disassemble_python.SENSITIVE_PATHS", mock_sensitive_paths
    )

    assert map_string_arg("print", "print") == "MAPPED_PRINT_SPECIFIC"
    assert map_string_arg("os_module", "os_module") == "os_module"
    assert (
        map_string_arg("/etc/shadow_specific", "/etc/shadow_specific")
        == SpecialCases.STRING_SENSITIVE_FILE_PATH.value
    )
    assert map_string_arg("10.0.0.1", "10.0.0.1") == SpecialCases.STRING_IP.value
    # This assertion reflects the SCRIPT's current behavior where is_file_path on r"\x..." is true and checked before is_escaped_hex.
    # To get STRING_ESCAPED_HEX..., the script's map_string_arg logic for order of checks would need to change.
    assert (
        map_string_arg(r"\x68\x65\x6c\x6c\x6f", r"\x68\x65\x6c\x6c\x6f")
        == SpecialCases.STRING_FILE_PATH.value
    )


def test_map_code_object_arg(sample_code_object):
    assert map_code_object_arg(sample_code_object, "<code object ...>") == "OBJECT"


def test_map_tuple_arg():
    assert map_tuple_arg((1, "abc", 2.5), "(1, 'abc', 2.5)") == "FLOAT INTEGER abc"


def test_map_frozenset_arg():
    assert (
        map_frozenset_arg(frozenset([1, "abc", 2.5]), "frozenset({1, 'abc', 2.5})")
        == "FLOAT INTEGER abc"
    )


def test_map_jump_instruction_arg():
    mock_instr_jump = mock.Mock(spec=dis.Instruction)
    mock_instr_jump.opcode = dis.opmap["JUMP_FORWARD"]
    assert map_jump_instruction_arg(mock_instr_jump) == "TO_NUMBER"


def test_map_load_const_number_arg(sample_code_object):
    mock_instr_load_const = mock.Mock(spec=dis.Instruction)
    mock_instr_load_const.opname = "LOAD_CONST"
    assert (
        map_load_const_number_arg(mock_instr_load_const, 123, "123")
        == SpecialCases.INTEGER.value
    )


def test_recursively_disassemble_python_simple():
    def simple_func():
        pass

    code_obj = simple_func.__code__

    mock_py_instructions = []
    if sys.version_info >= (3, 11):
        mock_py_instructions.append(
            mock.Mock(
                opname="resume",
                argval=0,
                argrepr="0",
                opcode=dis.opmap.get("RESUME", -1),
            )
        )
    mock_py_instructions.extend(
        [
            mock.Mock(
                opname="load_const",
                argval=None,
                argrepr="None",
                opcode=dis.opmap["LOAD_CONST"],
            ),
            mock.Mock(
                opname="return_value",
                argval=None,
                argrepr="",
                opcode=dis.opmap["RETURN_VALUE"],
            ),
        ]
    )

    with mock.patch("dis.get_instructions", return_value=mock_py_instructions):
        all_objects_data = []
        recursively_disassemble_python(
            file_path="test.py",
            language="python",
            code_obj=code_obj,
            all_objects_data=all_objects_data,
        )
        assert len(all_objects_data) == 1
        mf = all_objects_data[0]
        expected_instructions = []
        if sys.version_info >= (3, 11):
            expected_instructions.append(("resume", "0"))
        expected_instructions.extend([("load_const", "None"), ("return_value", "")])
        assert mf.instructions == expected_instructions


def test_recursively_disassemble_python_with_errors():
    all_objects_data = []
    errors = [SpecialCases.MALFORMED_FILE.value]
    recursively_disassemble_python(
        file_path="error.py",
        language="python",
        code_obj=None,
        all_objects_data=all_objects_data,
        errors=errors,
    )
    assert all_objects_data[0].name == SpecialCases.MALFORMED_FILE.value


@mock.patch("research.disassemble_python.recursively_disassemble_python")
def test_disassemble_python_file_success(mock_recursive_disassemble, tmp_path):
    py_file = tmp_path / "test_script.py"
    py_file.write_text("print('hello')")
    mock_code_obj = mock.MagicMock(spec=types.CodeType)
    with mock.patch("builtins.compile", return_value=mock_code_obj) as mock_compile:
        disassemble_python_file(str(py_file))
        mock_recursive_disassemble.assert_called_once()


@mock.patch("research.disassemble_python.recursively_disassemble_python")
def test_disassemble_python_file_syntax_error(mock_recursive_disassemble, tmp_path):
    py_file = tmp_path / "syntax_error.py"
    py_file.write_text("print 'hello'")
    with mock.patch("builtins.compile", side_effect=SyntaxError()):
        disassemble_python_file(str(py_file))
        assert (
            SpecialCases.MALFORMED_SYNTAX.value
            in mock_recursive_disassemble.call_args.kwargs["errors"]
        )


@mock.patch("research.disassemble_python.recursively_disassemble_python")
def test_disassemble_python_file_read_error(mock_recursive_disassemble):
    with mock.patch("builtins.open", side_effect=IOError()):
        disassemble_python_file("non_existent_file.py")
        assert (
            SpecialCases.FILE_READING_ISSUES.value
            in mock_recursive_disassemble.call_args.kwargs["errors"]
        )


# --- Tests for ProcessingResult ---
class TestProcessingResult:
    def test_processing_result_creation(self):
        malwi_objects = [MalwiObject("test", "python", "test.py", [])]
        all_files = [Path("test.py"), Path("other.txt")]
        skipped_files = [Path("other.txt")]
        processed_files = 1

        result = ProcessingResult(
            malwi_objects=malwi_objects,
            all_files=all_files,
            skipped_files=skipped_files,
            processed_files=processed_files,
        )

        assert len(result.malwi_objects) == 1
        assert len(result.all_files) == 2
        assert len(result.skipped_files) == 1
        assert result.processed_files == 1


# --- Tests for File Collection Functions ---
class TestFileCollection:
    def test_collect_files_by_extension_single_py_file(self, tmp_path):
        py_file = tmp_path / "test.py"
        py_file.write_text("print('hello')")

        accepted, skipped = collect_files_by_extension(py_file, ["py"], silent=True)

        assert len(accepted) == 1
        assert accepted[0] == py_file
        assert len(skipped) == 0

    def test_collect_files_by_extension_wrong_extension(self, tmp_path):
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("hello")

        accepted, skipped = collect_files_by_extension(txt_file, ["py"], silent=True)

        assert len(accepted) == 0
        assert len(skipped) == 1
        assert skipped[0] == txt_file

    def test_collect_files_by_extension_directory(self, tmp_path):
        py_file1 = tmp_path / "script1.py"
        py_file1.write_text("pass")
        py_file2 = tmp_path / "script2.py"
        py_file2.write_text("pass")
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("readme")

        accepted, skipped = collect_files_by_extension(tmp_path, ["py"], silent=True)

        assert len(accepted) == 2
        assert py_file1 in accepted
        assert py_file2 in accepted
        assert len(skipped) == 1
        assert txt_file in skipped

    def test_collect_files_by_extension_multiple_extensions(self, tmp_path):
        py_file = tmp_path / "script.py"
        py_file.write_text("pass")
        js_file = tmp_path / "script.js"
        js_file.write_text("console.log('hello');")
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("readme")

        accepted, skipped = collect_files_by_extension(
            tmp_path, ["py", "js"], silent=True
        )

        assert len(accepted) == 2
        assert py_file in accepted
        assert js_file in accepted
        assert len(skipped) == 1
        assert txt_file in skipped

    def test_collect_files_by_extension_nonexistent_path(self, tmp_path):
        nonexistent = tmp_path / "nonexistent.py"

        accepted, skipped = collect_files_by_extension(nonexistent, ["py"], silent=True)

        assert len(accepted) == 0
        assert len(skipped) == 0


class TestProcessFilesWithProgress:
    @mock.patch("research.disassemble_python.process_single_py_file")
    def test_process_files_with_progress_single_file(
        self, mock_process_single, tmp_path
    ):
        py_file = tmp_path / "test.py"
        py_file.write_text("print('hello')")

        mock_obj = MalwiObject(
            name="test",
            language="python",
            file_path=str(py_file),
            instructions=[],
            warnings=[],
        )
        mock_process_single.return_value = [mock_obj]

        result = process_files(
            py_file,
            accepted_extensions=["py"],
            predict=False,
            retrieve_source_code=False,
            silent=True,
            show_progress=False,
        )

        assert len(result.malwi_objects) == 1
        assert result.malwi_objects[0] == mock_obj
        assert len(result.all_files) == 1
        assert len(result.skipped_files) == 0
        assert result.processed_files == 1

    @mock.patch("research.disassemble_python.process_single_py_file")
    def test_process_files_with_progress_directory(self, mock_process_single, tmp_path):
        py_file1 = tmp_path / "script1.py"
        py_file1.write_text("pass")
        py_file2 = tmp_path / "script2.py"
        py_file2.write_text("pass")
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("readme")

        mock_obj1 = MalwiObject("script1", "python", str(py_file1), [])
        mock_obj2 = MalwiObject("script2", "python", str(py_file2), [])
        mock_process_single.side_effect = [[mock_obj1], [mock_obj2]]

        result = process_files(
            tmp_path,
            accepted_extensions=["py"],
            predict=False,
            retrieve_source_code=False,
            silent=True,
            show_progress=False,
        )

        assert len(result.malwi_objects) == 2
        assert len(result.all_files) == 3  # 2 py + 1 txt
        assert len(result.skipped_files) == 1  # txt file
        assert result.processed_files == 2

    @mock.patch("research.disassemble_python.process_single_py_file")
    def test_process_files_with_progress_no_files(self, mock_process_single, tmp_path):
        result = process_files(
            tmp_path,
            accepted_extensions=["py"],
            predict=False,
            retrieve_source_code=False,
            silent=True,
            show_progress=False,
        )

        assert len(result.malwi_objects) == 0
        assert len(result.all_files) == 0
        assert len(result.skipped_files) == 0
        assert result.processed_files == 0

    @mock.patch("research.disassemble_python.process_single_py_file")
    def test_process_files_with_progress_with_exceptions(
        self, mock_process_single, tmp_path, capsys
    ):
        py_file = tmp_path / "error.py"
        py_file.write_text("pass")

        mock_process_single.side_effect = Exception("Processing error")

        result = process_files(
            py_file,
            accepted_extensions=["py"],
            predict=False,
            retrieve_source_code=False,
            silent=False,  # Enable error output for testing
            show_progress=False,
        )

        assert len(result.malwi_objects) == 0
        assert result.processed_files == 0
        captured = capsys.readouterr()
        assert "Critical error processing file" in captured.err


@mock.patch("argparse.ArgumentParser.parse_args")
@mock.patch("research.disassemble_python.Path.exists", return_value=True)
@mock.patch("research.disassemble_python.process_files")
@mock.patch("research.disassemble_python.OutputFormatter.format_text")
@mock.patch("research.disassemble_python.MalwiObject.load_models_into_memory")
@mock.patch("sys.stdout", new_callable=io.StringIO)
def test_main_simple_run(
    mock_stdout,
    mock_load_models,
    mock_format_text,
    mock_process_files,
    mock_path_exists,
    mock_parse_args,
):
    mock_args = mock.Mock()
    mock_args.path = "dummy.py"
    mock_args.format = "txt"
    mock_args.save = None
    mock_args.malicious_threshold = 0.5
    mock_args.malicious_only = False
    mock_args.model_path = None
    mock_args.tokenizer_path = None
    mock_parse_args.return_value = mock_args

    mock_mf = mock.MagicMock(spec=MalwiObject)
    mock_result = ProcessingResult(
        malwi_objects=[mock_mf],
        all_files=[pathlib.Path("dummy.py")],
        skipped_files=[],
        processed_files=1,
    )
    mock_process_files.return_value = mock_result

    with pytest.raises(SystemExit) as e:
        script_main()
    assert e.value.code == 0
    mock_process_files.assert_called_once()
    mock_format_text.assert_called_once_with([mock_mf], mock_stdout)
    mock_load_models.assert_called_once_with(model_path=None, tokenizer_path=None)


@mock.patch("builtins.open")
def test_module_tokens_from_multiline_python_string(mock_open_builtin, monkeypatch):
    python_content = """
x = 1
y = "s"
z = None
"""
    dummy_filepath = "setup.py"

    mock_file_object = io.StringIO(python_content)
    mock_open_builtin.return_value.__enter__.return_value = mock_file_object

    malwifiles = disassemble_python_file(dummy_filepath)

    assert len(malwifiles) == 1
    module_mf = malwifiles[0]
    assert (
        module_mf.to_token_string()
        == "TARGETED_FILE resume load_const INTEGER store_name x load_const s store_name y load_const store_name z return_const None"
    )


def mock_initialize_models(model_path=None, tokenizer_path=None):
    # print("Test: Mock models initialized")
    pass


def mock_get_node_text_prediction(token_string: str):
    # Predefined responses for consistent testing
    if "evil_script_tokens" in token_string:  # Specific to file1
        return {"probabilities": [0.1, 0.9]}  # Malicious
    if "harmless_utility_tokens" in token_string:  # Specific to file2
        return {"probabilities": [0.95, 0.05]}  # Non-malicious
    if "moderate_risk_tokens" in token_string:  # Specific to file3
        return {"probabilities": [0.4, 0.6]}  # Malicious (if threshold <= 0.6)
    if "unknown_op_tokens" in token_string:  # Specific to file4
        return {"probabilities": [0.8, 0.2]}  # Non-malicious
    return {"probabilities": [0.7, 0.3]}  # Default


MalwiObject.load_models_into_memory = classmethod(mock_initialize_models)


@pytest.fixture(scope="module", autouse=True)
def setup_models():
    # Ensure models are "loaded" once for the test module
    MalwiObject.load_models_into_memory()


@pytest.fixture
def sample_malwi_files():
    file1 = MalwiObject(
        name="evil_script.py",
        language="python",
        file_path="/path/to/evil_script.py",
        instructions=[("LOAD_CONST", "evil_script_tokens")],
        codeType=None,
        warnings=["Suspicious"],
    )  # Expected score: 0.9

    file2 = MalwiObject(
        name="harmless_utility.py",
        language="python",
        file_path="/path/to/harmless_utility.py",
        instructions=[("LOAD_CONST", "harmless_utility_tokens")],
        codeType=None,
    )  # Expected score: 0.05

    file3 = MalwiObject(
        name="moderate_risk.js",
        language="javascript",
        file_path="/path/to/moderate_risk.js",
        instructions=[("CALL", "moderate_risk_tokens")],
        codeType=None,
    )  # Expected score: 0.6

    file4 = MalwiObject(
        name="unknown.txt",
        language="text",
        file_path="/path/to/unknown.txt",
        instructions=[("DATA", "unknown_op_tokens")],
        codeType=None,
    )  # Expected score: 0.2 (if it uses the mock directly)

    return [file1, file2, file3, file4]


@pytest.fixture
def sample_malwi_files_predictions_set():
    # Create files and explicitly call predict to make sure scores are set
    # before report generation, simulating a scenario where scores are pre-calculated.
    # This helps ensure predict() in report generation handles already-set scores correctly.
    files = [
        MalwiObject(
            name="f1.py",
            language="python",
            file_path="f1.py",
            instructions=[("L", "evil_script_tokens")],
            codeType=None,
        ),
        MalwiObject(
            name="f2.py",
            language="python",
            file_path="f2.py",
            instructions=[("L", "harmless_utility_tokens")],
            codeType=None,
        ),
    ]
    for f in files:
        # Use the mock directly for prediction for test consistency
        prediction_result = mock_get_node_text_prediction(f.to_token_string())
        if prediction_result and "probabilities" in prediction_result:
            f.maliciousness = prediction_result["probabilities"][1]
    return files


def test_generate_yaml_report_basic(sample_malwi_files):
    """Test basic YAML report generation and consistency with JSON."""
    malwi_files = sample_malwi_files
    threshold = 0.5
    skipped_general = 1

    # Manually run predict to set scores based on mock
    for mf in malwi_files:
        mf.predict()

    yaml_report_str = MalwiObject.to_report_yaml(
        malwi_files,
        all_files=[],
        malicious_threshold=threshold,
        number_of_skipped_files=skipped_general,
    )
    report_data_yaml = yaml.safe_load(yaml_report_str)

    json_report_str = MalwiObject.to_report_json(
        malwi_files,  # Use the same files (scores are already set)
        all_files=[],
        malicious_threshold=threshold,
        number_of_skipped_files=skipped_general,
    )
    report_data_json = json.loads(json_report_str)

    # The core data structure should be identical
    assert report_data_yaml == report_data_json


def test_report_empty_file_list():
    """Test report generation with an empty list of MalwiFiles."""
    skipped_general = 3

    json_report_str = MalwiObject.to_report_json(
        [],
        all_files=[],
        number_of_skipped_files=skipped_general,
    )
    report_data = json.loads(json_report_str)

    assert len(report_data["details"]) == 0

    yaml_report_str = MalwiObject.to_report_yaml(
        malwi_files=[],
        all_files=[],
        number_of_skipped_files=skipped_general,
    )
    report_data_yaml = yaml.safe_load(yaml_report_str)
    assert report_data_yaml == report_data  # Consistency


def test_report_calls_predict_if_needed(monkeypatch):
    """
    Test that _generate_report_data calls predict() on files if maliciousness is None.
    """
    # Mock predict method to check if it's called
    called_predict_for = []
    original_predict = MalwiObject.predict

    def mock_predict_spy(self_mf):
        called_predict_for.append(self_mf.name)
        # Call original predict to get a score, using the outer mock_get_node_text_prediction
        prediction_result = mock_get_node_text_prediction(self_mf.to_token_string())
        if prediction_result and "probabilities" in prediction_result:
            self_mf.maliciousness = prediction_result["probabilities"][1]
        return prediction_result

    monkeypatch.setattr(MalwiObject, "predict", mock_predict_spy)

    test_files = [
        MalwiObject(
            name="needs_predict1.py",
            language="python",
            file_path="np1.py",
            instructions=[("L", "evil_script_tokens")],
            codeType=None,
        ),
        MalwiObject(
            name="needs_predict2.py",
            language="python",
            file_path="np2.py",
            instructions=[("L", "harmless_utility_tokens")],
            codeType=None,
        ),
    ]
    # Ensure maliciousness is None
    assert test_files[0].maliciousness is None
    assert test_files[1].maliciousness is None

    MalwiObject.to_report_json(test_files, all_files=[])

    assert "needs_predict1.py" in called_predict_for
    assert "needs_predict2.py" in called_predict_for
    assert test_files[0].maliciousness is not None  # Should be set after predict call
    assert test_files[1].maliciousness is not None

    # Restore original predict if other tests need it unmocked, though pytest handles fixture/monkeypatch scope.
    monkeypatch.setattr(MalwiObject, "predict", original_predict)
