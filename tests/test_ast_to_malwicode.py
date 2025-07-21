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
    source_bytes = py_file.read_bytes()
    ast = python_compiler.bytes_to_treesitter_ast(source_bytes, str(py_file))
    code_obj = python_compiler.treesitter_ast_to_malwicode(ast, source_bytes, py_file)

    # Load expected output from file - comprehensive test suite output
    expected_file = source_path / "expected_python_output.txt"
    with open(expected_file, "r") as f:
        expected_string = f.read().strip()

    generated_string = code_obj.to_string().strip()
    assert generated_string == expected_string


def test_javascript_compilation(js_compiler: ASTCompiler, source_path: Path):
    """
    Tests compilation of a JavaScript file using the same string comparison method.
    """
    js_file = source_path / "javascript.js"
    source_bytes = js_file.read_bytes()
    ast = js_compiler.bytes_to_treesitter_ast(source_bytes, str(js_file))
    code_obj = js_compiler.treesitter_ast_to_malwicode(ast, source_bytes, js_file)

    # Load expected output from file - comprehensive test suite output
    expected_file = source_path / "expected_javascript_output.txt"
    with open(expected_file, "r") as f:
        expected_string = f.read().strip()

    generated_string = code_obj.to_string().strip()

    # Note: Minor differences in AST parsing can occur. This test assumes
    # the structures are similar enough for this comparison to work.
    assert generated_string == expected_string
