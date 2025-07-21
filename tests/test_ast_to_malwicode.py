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

    # The expected bytecode sequence, formatted as a string.
    # This is much easier to read and verify than the list of tuples.
    expected_string = """
LOAD_CONST           100.0
STORE_NAME           val
LOAD_NAME            val
LOAD_CONST           200.0
BINARY_ADD           
STORE_NAME           result
LOAD_CONST           1.0
LOAD_CONST           "two"
LOAD_NAME            val
BUILD_LIST           3
STORE_NAME           items
LOAD_CONST           1.0
BUILD_TUPLE          1
STORE_NAME           my_tuple
LOAD_CONST           1.0
LOAD_CONST           2.0
LOAD_CONST           3.0
BUILD_SET            3
STORE_NAME           my_set
LOAD_CONST           "key"
LOAD_CONST           "value"
BUILD_MAP            1
STORE_NAME           my_dict
MAKE_FUNCTION        <simple_func>
    LOAD_NAME            a
    LOAD_CONST           0.0
    POP_JUMP_IF_FALSE    <JUMP_TARGET>
    LOAD_NAME            a
    LOAD_CONST           2.0
    BINARY_MULTIPLY      
    RETURN_VALUE         
STORE_NAME           simple_func
LOAD_NAME            simple_func
LOAD_NAME            result
CALL_FUNCTION        1
MAKE_CLASS           <MyTestClass>
    LOAD_CONST           300.0
    STORE_NAME           y
STORE_NAME           MyTestClass
""".strip()

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

    expected_string = """
LOAD_CONST           100.0
STORE_NAME           val
LOAD_NAME            val
LOAD_CONST           200.0
BINARY_ADD           
STORE_NAME           result
LOAD_CONST           1.0
LOAD_CONST           "two"
LOAD_NAME            val
BUILD_LIST           3
STORE_NAME           items
LOAD_CONST           "key"
LOAD_CONST           "value"
BUILD_MAP            1
STORE_NAME           my_obj
MAKE_FUNCTION        <simple_func>
    LOAD_NAME            a
    LOAD_CONST           0.0
    BINARY_OPERATION     
    POP_JUMP_IF_FALSE    <JUMP_TARGET>
    LOAD_NAME            a
    LOAD_CONST           2.0
    BINARY_MULTIPLY      
    RETURN_VALUE         
STORE_NAME           simple_func
LOAD_NAME            simple_func
LOAD_NAME            result
CALL_FUNCTION        1
MAKE_CLASS           <MyTestClass>
    LOAD_CONST           300.0
    STORE_NAME           this.y
STORE_NAME           MyTestClass
""".strip()

    generated_string = code_obj.to_string().strip()

    # Note: Minor differences in AST parsing can occur. This test assumes
    # the structures are similar enough for this comparison to work.
    assert generated_string == expected_string
