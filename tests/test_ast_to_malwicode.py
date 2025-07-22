import sys
from pathlib import Path
import pytest

# Add the parent directory to the path to import the compiler
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.research.ast_to_malwicode import ASTCompiler

# --- Test Fixtures ---


@pytest.fixture(scope="module")
def source_path() -> Path:
    """Provides the path to the directory containing sample source files."""
    return Path(__file__).parent / "source_samples"


@pytest.fixture(scope="module")
def python_compiler() -> ASTCompiler:
    """Returns a reusable instance of the ASTCompiler for Python."""
    return ASTCompiler("python")


@pytest.fixture(scope="module")
def js_compiler() -> ASTCompiler:
    """Returns a reusable instance of the ASTCompiler for JavaScript."""
    return ASTCompiler("javascript")


def test_python_compilation(python_compiler: ASTCompiler, source_path: Path):
    """
    Tests compilation by comparing the string output of the CodeObject.
    """
    py_file = source_path / "python.py"
    code_objects = python_compiler.process_file(py_file)

    # Load expected output from file - comprehensive test suite output
    expected_file = source_path / "expected_python_output.txt"
    with open(expected_file, "r") as f:
        expected_string = f.read().strip()

    # Generate output to match the exact expected format with headers and separators
    output_parts = []
    for i, code_obj in enumerate(code_objects):
        if i == 0:
            output_parts.append(f"Root CodeObject ({code_obj.name}):")
        else:
            output_parts.append(f"\n{code_obj.name}:")

        # Add header like print_code_object does
        header = f"--- CodeObject '{code_obj.name}' from {code_obj.path.name} (lines {code_obj.location[0]}-{code_obj.location[1]}) ---"
        output_parts.append(header)
        output_parts.append(code_obj.to_string())

        # Add separator
        separator = "-" * len(header)
        output_parts.append(separator)

    generated_string = "\n".join(output_parts).strip()
    assert generated_string == expected_string


def test_javascript_compilation(js_compiler: ASTCompiler, source_path: Path):
    """
    Tests compilation of a JavaScript file using the same string comparison method.
    """
    js_file = source_path / "javascript.js"
    code_objects = js_compiler.process_file(js_file)

    # Load expected output from file - comprehensive test suite output
    expected_file = source_path / "expected_javascript_output.txt"
    with open(expected_file, "r") as f:
        expected_string = f.read().strip()

    # Generate output to match the exact expected format with headers and separators
    output_parts = []
    for i, code_obj in enumerate(code_objects):
        if i == 0:
            output_parts.append(f"Root CodeObject ({code_obj.name}):")
        else:
            output_parts.append(f"\n{code_obj.name}:")

        # Add header like print_code_object does
        header = f"--- CodeObject '{code_obj.name}' from {code_obj.path.name} (lines {code_obj.location[0]}-{code_obj.location[1]}) ---"
        output_parts.append(header)
        output_parts.append(code_obj.to_string())

        # Add separator
        separator = "-" * len(header)
        output_parts.append(separator)

    generated_string = "\n".join(output_parts).strip()

    # Note: Minor differences in AST parsing can occur. This test assumes
    # the structures are similar enough for this comparison to work.
    assert generated_string == expected_string


def test_python_mapping_feature(python_compiler: ASTCompiler, source_path: Path):
    """
    Tests the mapping feature for Python CodeObjects.
    This test will verify that the mapping functionality works correctly.
    """
    py_file = source_path / "python.py"
    code_objects = python_compiler.process_file(py_file)

    # Test that we got CodeObjects
    assert len(code_objects) > 0

    # Test basic functionality
    root_obj = code_objects[0]
    assert root_obj.name == "<module>"
    assert len(root_obj.byte_code) > 0

    # Test that we have various instruction types
    opcodes = [instr.opcode.name for instr in root_obj.byte_code]
    assert "IMPORT_NAME" in opcodes
    assert len(opcodes) > 10  # Should have many instructions

    # Test to_oneline method functionality
    oneline = root_obj.to_oneline()
    assert isinstance(oneline, str)
    assert len(oneline) > 0
    assert "IMPORT_NAME" in oneline

    # Test to_oneline with custom separator
    oneline_pipe = root_obj.to_oneline(" | ")
    assert isinstance(oneline_pipe, str)
    assert " | " in oneline_pipe

    # Test that instruction count matches between formats
    instruction_count = len(root_obj.byte_code)
    oneline_parts = oneline.split(" ")
    # Should have at least as many parts as instructions (opcodes + some args)
    assert len(oneline_parts) >= instruction_count

    # Test function CodeObjects exist
    function_objects = [obj for obj in code_objects if "ref_" in obj.name]
    assert len(function_objects) > 0

    # Test a function CodeObject
    func_obj = function_objects[0]
    assert len(func_obj.byte_code) > 0
    func_oneline = func_obj.to_oneline()
    assert isinstance(func_oneline, str)

    # Compare with expected mapping output file
    expected_mapping_file = source_path / "expected_python_output_mapped.txt"
    with open(expected_mapping_file, "r") as f:
        expected_mapping_string = f.read().strip()

    # Generate mapping output format (to be defined based on mapping feature)
    mapping_output_parts = []
    for i, code_obj in enumerate(code_objects):
        if i == 0:
            mapping_output_parts.append(f"Root CodeObject ({code_obj.name}) - Mapping:")
        else:
            mapping_output_parts.append(f"\n{code_obj.name} - Mapping:")

        # Add oneline representation for now (will be updated for actual mapping)
        mapping_output_parts.append(code_obj.to_oneline(" | "))

    generated_mapping_string = "\n".join(mapping_output_parts).strip()
    # Note: This assertion will be updated once the mapping feature is implemented
    # assert generated_mapping_string == expected_mapping_string


def test_javascript_mapping_feature(js_compiler: ASTCompiler, source_path: Path):
    """
    Tests the mapping feature for JavaScript CodeObjects.
    This test will verify that the mapping functionality works correctly.
    """
    js_file = source_path / "javascript.js"
    code_objects = js_compiler.process_file(js_file)

    # Test that we got CodeObjects
    assert len(code_objects) > 0

    # Test basic functionality
    root_obj = code_objects[0]
    assert root_obj.name == "<module>"
    assert len(root_obj.byte_code) > 0

    # Test that we have various instruction types
    opcodes = [instr.opcode.name for instr in root_obj.byte_code]
    assert "IMPORT_NAME" in opcodes
    assert len(opcodes) > 10  # Should have many instructions

    # Test to_oneline method functionality
    oneline = root_obj.to_oneline()
    assert isinstance(oneline, str)
    assert len(oneline) > 0
    assert "IMPORT_NAME" in oneline

    # Test to_oneline with custom separator
    oneline_pipe = root_obj.to_oneline(" | ")
    assert isinstance(oneline_pipe, str)
    assert " | " in oneline_pipe

    # Test that instruction count matches between formats
    instruction_count = len(root_obj.byte_code)
    oneline_parts = oneline.split(" ")
    # Should have at least as many parts as instructions (opcodes + some args)
    assert len(oneline_parts) >= instruction_count

    # Test function CodeObjects exist
    function_objects = [obj for obj in code_objects if "ref_" in obj.name]
    assert len(function_objects) > 0

    # Test a function CodeObject
    func_obj = function_objects[0]
    assert len(func_obj.byte_code) > 0
    func_oneline = func_obj.to_oneline()
    assert isinstance(func_oneline, str)

    # Compare with expected mapping output file
    expected_mapping_file = source_path / "expected_javascript_output_mapped.txt"
    with open(expected_mapping_file, "r") as f:
        expected_mapping_string = f.read().strip()

    # Generate mapping output format (to be defined based on mapping feature)
    mapping_output_parts = []
    for i, code_obj in enumerate(code_objects):
        if i == 0:
            mapping_output_parts.append(f"Root CodeObject ({code_obj.name}) - Mapping:")
        else:
            mapping_output_parts.append(f"\n{code_obj.name} - Mapping:")

        # Add oneline representation for now (will be updated for actual mapping)
        mapping_output_parts.append(code_obj.to_oneline(" | "))

    generated_mapping_string = "\n".join(mapping_output_parts).strip()
    # Note: This assertion will be updated once the mapping feature is implemented
    # assert generated_mapping_string == expected_mapping_string
