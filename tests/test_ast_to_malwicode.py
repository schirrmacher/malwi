import sys
from pathlib import Path
import pytest

# Add the parent directory to the path to import the compiler
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.common.ast_to_malwicode import ASTCompiler

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


# --- Helper Functions ---


def _test_compilation(compiler: ASTCompiler, source_file: Path, expected_file: Path):
    """
    Common test logic for both Python and JavaScript compilation.
    Tests compilation by comparing mapped output with expected file.
    """
    code_objects = compiler.process_file(source_file)

    # Load expected output
    with open(expected_file, "r") as f:
        expected_string = f.read().strip()

    # Generate mapped output (same logic for both languages)
    generated_string = "\n".join(
        code_obj.to_string(one_line=False) for code_obj in code_objects
    ).strip()

    assert generated_string == expected_string


# --- Tests ---


def test_python_compilation(python_compiler: ASTCompiler, source_path: Path):
    """Tests Python compilation by comparing mapped output."""
    py_file = source_path / "python.py"
    expected_file = source_path / "expected_python_output_mapped.txt"
    _test_compilation(python_compiler, py_file, expected_file)


def test_javascript_compilation(js_compiler: ASTCompiler, source_path: Path):
    """Tests JavaScript compilation by comparing mapped output."""
    js_file = source_path / "javascript.js"
    expected_file = source_path / "expected_javascript_output_mapped.txt"
    _test_compilation(js_compiler, js_file, expected_file)


def test_python_basic_functionality(python_compiler: ASTCompiler, source_path: Path):
    """Tests basic functionality of Python compilation."""
    py_file = source_path / "python.py"
    code_objects = python_compiler.process_file(py_file)

    # Basic sanity checks
    assert len(code_objects) > 0
    assert code_objects[0].name == "<module>"
    assert len(code_objects[0].byte_code) > 0

    # Test string representations
    for code_obj in code_objects:
        assert isinstance(code_obj.to_string(), str)
        assert isinstance(code_obj.to_hash(), str)
        assert len(code_obj.to_hash()) == 64  # SHA256 hex string


def test_javascript_basic_functionality(js_compiler: ASTCompiler, source_path: Path):
    """Tests basic functionality of JavaScript compilation."""
    js_file = source_path / "javascript.js"
    code_objects = js_compiler.process_file(js_file)

    # Basic sanity checks
    assert len(code_objects) > 0
    assert code_objects[0].name == "<module>"
    assert len(code_objects[0].byte_code) > 0

    # Test string representations
    for code_obj in code_objects:
        assert isinstance(code_obj.to_string(), str)
        assert isinstance(code_obj.to_hash(), str)
        assert len(code_obj.to_hash()) == 64  # SHA256 hex string
