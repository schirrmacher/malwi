import pytest
import tempfile
import pathlib
import types
import dis
import csv  # Standard import
import io
import sys  # For sys.version_info and sys.modules

# import csv as original_csv_standard_module # This alias can be tricky with patching, so we'll use sys.modules['csv']
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
        id_hex="0x123",
        filename="test.py",
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
            filename="example.py",
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
                    "tokens": "LOAD_CONST 1 RETURN_VALUE",
                    "code": "<tbd>",
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
                opname="RESUME",
                argval=0,
                argrepr="0",
                opcode=dis.opmap.get("RESUME", -1),
            )
        )
    mock_py_instructions.extend(
        [
            mock.Mock(
                opname="LOAD_CONST",
                argval=None,
                argrepr="None",
                opcode=dis.opmap["LOAD_CONST"],
            ),
            mock.Mock(
                opname="RETURN_VALUE",
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
            expected_instructions.append(("RESUME", "0"))
        expected_instructions.extend([("LOAD_CONST", "None"), ("RETURN_VALUE", "")])
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
    expected = f"{sample_malwifile.to_token_string()},{sample_malwifile.to_string_hash()},{sample_malwifile.file_path}"
    assert output_stream.getvalue().strip() == expected


def test_print_csv_output_to_stdout(sample_malwifile):
    # Get a guaranteed original reference to the standard library's csv.writer
    original_stdlib_csv_writer = sys.modules["csv"].writer

    def custom_writer_factory(stream_from_sut, *args_from_sut, **kwargs_from_sut):
        # This function is called when 'research.disassemble_python.csv.writer' is invoked.
        return original_stdlib_csv_writer(
            stream_from_sut, *args_from_sut, **kwargs_from_sut, lineterminator="\n"
        )

    output_stream = io.StringIO()
    with mock.patch(
        "research.disassemble_python.csv.writer",  # Target the 'csv.writer' used by the SUT
        side_effect=custom_writer_factory,
    ):
        print_csv_output_to_stdout([sample_malwifile], output_stream)

    lines = output_stream.getvalue().strip().split("\n")
    assert lines[0] == "tokens,hash,filepath"
    expected_data_row = f"{sample_malwifile.to_token_string()},{sample_malwifile.to_string_hash()},{sample_malwifile.file_path}"
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
        == "TARGETED_FILE RESUME LOAD_CONST INTEGER STORE_NAME STRING_LEN_XS_ENT_LOW LOAD_CONST STRING_LEN_XS_ENT_LOW STORE_NAME STRING_LEN_XS_ENT_LOW LOAD_CONST None STORE_NAME STRING_LEN_XS_ENT_LOW RETURN_CONST None"
    )
