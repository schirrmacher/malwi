import pytest
import pathlib
import types
import dis
import pytest
import json
import yaml
import io
import sys

from unittest import mock

# Import necessary components from the script to be tested, using the new package path
from research.disassemble_python import (
    MalwiFile,
    SpecialCases,
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
    process_input_path,
    print_txt_output,
    print_csv_output_to_stdout,
    write_csv_rows_for_file_data,
    main as script_main,
)

# --- Fixtures ---


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
    return MalwiFile(
        name="<module>",
        language="python",
        code="abc",
        id_hex="0x123",
        file_path="test.py",
        firstlineno=1,
        instructions=[("LOAD_CONST", "1"), ("RETURN_VALUE", "")],
    )


@pytest.fixture
def sample_code_object():
    def _dummy_func():
        pass

    return _dummy_func.__code__


# --- Tests for MalwiFile Class ---
class TestMalwiFile:
    def test_malwifile_initialization(self):
        mf = MalwiFile(
            name="test_func",
            language="python",
            id_hex="0xabc",
            file_path="example.py",
            firstlineno=10,
            instructions=[("LOAD_NAME", "print")],
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
                    "code": "abc",
                    "tokens": "LOAD_CONST 1 RETURN_VALUE",
                    "hash": current_hash,
                }
            ],
        }
        assert sample_malwifile.to_dict() == expected_dict


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


# --- Tests for File Processing and Output ---
@mock.patch("research.disassemble_python.disassemble_python_file")
def test_process_single_py_file(mock_disassemble, tmp_path):
    py_file = tmp_path / "sample.py"
    py_file.write_text("a = 1")
    mock_mf_instance = MalwiFile("name", "lang", "id", "file", 1, [])
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


@mock.patch("research.disassemble_python.process_single_py_file")
def test_process_input_path_single_file(mock_process_single, tmp_path):
    target_file = tmp_path / "myfile.py"
    target_file.write_text("pass")
    mock_mf_instance = MalwiFile("name", "lang", "id", "file", 1, [])
    mock_process_single.return_value = [mock_mf_instance]
    result = process_input_path(target_file, "txt", None)
    assert result == [mock_mf_instance]


@mock.patch("research.disassemble_python.process_single_py_file")
def test_process_input_path_directory(mock_process_single, tmp_path):
    py_file1 = tmp_path / "s1.py"
    py_file1.write_text("p1")
    (tmp_path / "sub").mkdir()
    py_file2 = tmp_path / "sub" / "s2.py"
    py_file2.write_text("p2")
    mf1 = MalwiFile("mf1", "py", "id1", str(py_file1), 1, [])
    mf2 = MalwiFile("mf2", "py", "id2", str(py_file2), 1, [])
    mock_process_single.side_effect = [[mf1], [mf2]]
    result = process_input_path(tmp_path, "txt", None)
    assert mf1 in result and mf2 in result


def test_print_txt_output(sample_malwifile):
    output_stream = io.StringIO()
    print_txt_output([sample_malwifile], output_stream)
    assert "Disassembly of <code object <module> at 0x123>:" in output_stream.getvalue()


def test_write_csv_rows_for_file_data(sample_malwifile):
    output_stream = io.StringIO()
    # Use standard csv from the 'csv' module directly, not an alias that might be patched
    csv_writer = sys.modules["csv"].writer(output_stream, lineterminator="\n")
    write_csv_rows_for_file_data([sample_malwifile], csv_writer)
    expected = "<module>,LOAD_CONST 1 RETURN_VALUE,d31f3e92b68ef17e63ed31922f3bb7c733d7484fd97d845d034ad184903b3cad,test.py"
    assert output_stream.getvalue().strip() == expected


def test_print_csv_output_to_stdout(sample_malwifile):
    original_stdlib_csv_writer = sys.modules["csv"].writer

    def custom_writer_factory(stream_from_sut, *args_from_sut, **kwargs_from_sut):
        return original_stdlib_csv_writer(
            stream_from_sut, *args_from_sut, **kwargs_from_sut, lineterminator="\n"
        )

    output_stream = io.StringIO()
    with mock.patch(
        "research.disassemble_python.csv.writer",
        side_effect=custom_writer_factory,
    ):
        print_csv_output_to_stdout([sample_malwifile], output_stream)

    lines = output_stream.getvalue().strip().split("\n")
    assert lines[0] == "name,tokens,hash,filepath"
    expected_data_row = "<module>,LOAD_CONST 1 RETURN_VALUE,d31f3e92b68ef17e63ed31922f3bb7c733d7484fd97d845d034ad184903b3cad,test.py"
    assert lines[1] == expected_data_row


# Test for main function
@mock.patch("argparse.ArgumentParser.parse_args")
@mock.patch("research.disassemble_python.Path.exists", return_value=True)
@mock.patch("research.disassemble_python.process_input_path")
@mock.patch("research.disassemble_python.print_txt_output")
@mock.patch("sys.stdout", new_callable=io.StringIO)
def test_main_simple_run(
    mock_stdout, mock_print_txt, mock_process_input, mock_path_exists, mock_parse_args
):
    mock_args = mock.Mock()
    mock_args.path = "dummy.py"
    mock_args.format = "txt"
    mock_args.save = None
    mock_parse_args.return_value = mock_args
    mock_mf = mock.MagicMock(spec=MalwiFile)
    mock_process_input.return_value = [mock_mf]

    with pytest.raises(SystemExit) as e:
        script_main()
    assert e.value.code == 0
    mock_process_input.assert_called_once_with(pathlib.Path("dummy.py"), "txt", None)
    mock_print_txt.assert_called_once_with([mock_mf], mock_stdout)


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


MalwiFile.load_models_into_memory = classmethod(mock_initialize_models)


@pytest.fixture(scope="module", autouse=True)
def setup_models():
    # Ensure models are "loaded" once for the test module
    MalwiFile.load_models_into_memory()


@pytest.fixture
def sample_malwi_files():
    file1 = MalwiFile(
        name="evil_script.py",
        language="python",
        id_hex="abc",
        file_path="/path/to/evil_script.py",
        firstlineno=1,
        instructions=[("LOAD_CONST", "evil_script_tokens")],
        warnings=["Suspicious"],
    )  # Expected score: 0.9

    file2 = MalwiFile(
        name="harmless_utility.py",
        language="python",
        id_hex="def",
        file_path="/path/to/harmless_utility.py",
        firstlineno=5,
        instructions=[("LOAD_CONST", "harmless_utility_tokens")],
    )  # Expected score: 0.05

    file3 = MalwiFile(
        name="moderate_risk.js",
        language="javascript",
        id_hex="ghi",
        file_path="/path/to/moderate_risk.js",
        firstlineno=10,
        instructions=[("CALL", "moderate_risk_tokens")],
    )  # Expected score: 0.6

    file4 = MalwiFile(
        name="unknown.txt",
        language="text",
        id_hex="jkl",
        file_path="/path/to/unknown.txt",
        firstlineno=1,
        instructions=[("DATA", "unknown_op_tokens")],
    )  # Expected score: 0.2 (if it uses the mock directly)

    return [file1, file2, file3, file4]


@pytest.fixture
def sample_malwi_files_predictions_set():
    # Create files and explicitly call predict to make sure scores are set
    # before report generation, simulating a scenario where scores are pre-calculated.
    # This helps ensure predict() in report generation handles already-set scores correctly.
    files = [
        MalwiFile(
            name="f1.py",
            language="python",
            id_hex="f1",
            file_path="f1.py",
            firstlineno=1,
            instructions=[("L", "evil_script_tokens")],
        ),
        MalwiFile(
            name="f2.py",
            language="python",
            id_hex="f2",
            file_path="f2.py",
            firstlineno=1,
            instructions=[("L", "harmless_utility_tokens")],
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

    yaml_report_str = MalwiFile.to_report_yaml(
        malwi_files,
        all_files=[],
        malicious_threshold=threshold,
        number_of_skipped_files=skipped_general,
    )
    report_data_yaml = yaml.safe_load(yaml_report_str)

    json_report_str = MalwiFile.to_report_json(
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

    json_report_str = MalwiFile.to_report_json(
        [],
        all_files=[],
        number_of_skipped_files=skipped_general,
    )
    report_data = json.loads(json_report_str)

    assert len(report_data["details"]) == 0

    yaml_report_str = MalwiFile.to_report_yaml(
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
    original_predict = MalwiFile.predict

    def mock_predict_spy(self_mf):
        called_predict_for.append(self_mf.name)
        # Call original predict to get a score, using the outer mock_get_node_text_prediction
        prediction_result = mock_get_node_text_prediction(self_mf.to_token_string())
        if prediction_result and "probabilities" in prediction_result:
            self_mf.maliciousness = prediction_result["probabilities"][1]
        return prediction_result

    monkeypatch.setattr(MalwiFile, "predict", mock_predict_spy)

    test_files = [
        MalwiFile(
            name="needs_predict1.py",
            language="python",
            id_hex="np1",
            file_path="np1.py",
            firstlineno=1,
            instructions=[("L", "evil_script_tokens")],
        ),
        MalwiFile(
            name="needs_predict2.py",
            language="python",
            id_hex="np2",
            file_path="np2.py",
            firstlineno=1,
            instructions=[("L", "harmless_utility_tokens")],
        ),
    ]
    # Ensure maliciousness is None
    assert test_files[0].maliciousness is None
    assert test_files[1].maliciousness is None

    MalwiFile.to_report_json(test_files, all_files=[])

    assert "needs_predict1.py" in called_predict_for
    assert "needs_predict2.py" in called_predict_for
    assert test_files[0].maliciousness is not None  # Should be set after predict call
    assert test_files[1].maliciousness is not None

    # Restore original predict if other tests need it unmocked, though pytest handles fixture/monkeypatch scope.
    monkeypatch.setattr(MalwiFile, "predict", original_predict)
