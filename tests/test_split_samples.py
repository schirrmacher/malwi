"""
Test suite for split sample files organized by syntactic domains.
This allows easier review and debugging of specific language features.
"""

import pytest
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from research.ast_to_malwicode import ASTCompiler


class TestSplitSamples:
    """Test split sample files for both Python and JavaScript"""

    @pytest.fixture
    def python_compiler(self):
        return ASTCompiler("python")

    @pytest.fixture
    def js_compiler(self):
        return ASTCompiler("javascript")

    def get_domain_files(self, language: str) -> list[Path]:
        """Get all test files for a language organized by domain"""
        base_path = Path(__file__).parent / "source_samples" / language
        domains = [
            "imports",
            "basics",
            "data_types",
            "control_flow",
            "functions",
            "oop",
            "advanced",
            "stdlib" if language == "python" else "builtin",
            "dynamic",
            "operators",
        ]

        files = []
        for domain in domains:
            domain_path = base_path / domain
            if domain_path.exists():
                files.extend(
                    domain_path.glob("*.py" if language == "python" else "*.js")
                )

        return sorted(files)

    def test_python_domains_compile(self, python_compiler):
        """Test that all Python domain files compile successfully"""
        files = self.get_domain_files("python")
        assert len(files) > 0, "No Python test files found"

        for file_path in files:
            try:
                code_objects = python_compiler.process_file(file_path)
                assert len(code_objects) > 0, (
                    f"No code objects generated for {file_path}"
                )

                # Basic validation
                for code_obj in code_objects:
                    # Empty classes may have empty bytecode, which is fine
                    if (
                        "class" not in code_obj.name.lower()
                        and "ref" not in code_obj.name
                    ):
                        assert len(code_obj.byte_code) > 0, (
                            f"Empty bytecode for {file_path} in {code_obj.name}"
                        )
                    assert code_obj.name, f"No object name for {file_path}"

            except Exception as e:
                pytest.fail(f"Failed to compile {file_path}: {str(e)}")

    def test_javascript_domains_compile(self, js_compiler):
        """Test that all JavaScript domain files compile successfully"""
        files = self.get_domain_files("javascript")
        assert len(files) > 0, "No JavaScript test files found"

        for file_path in files:
            try:
                code_objects = js_compiler.process_file(file_path)
                assert len(code_objects) > 0, (
                    f"No code objects generated for {file_path}"
                )

                # Basic validation
                for code_obj in code_objects:
                    # Empty classes may have empty bytecode, which is fine
                    if (
                        "class" not in code_obj.name.lower()
                        and "ref" not in code_obj.name
                    ):
                        assert len(code_obj.byte_code) > 0, (
                            f"Empty bytecode for {file_path} in {code_obj.name}"
                        )
                    assert code_obj.name, f"No object name for {file_path}"

            except Exception as e:
                pytest.fail(f"Failed to compile {file_path}: {str(e)}")

    def test_python_imports_domain(self, python_compiler):
        """Test Python import patterns specifically"""
        file_path = (
            Path(__file__).parent / "source_samples/python/imports/test_imports.py"
        )
        code_objects = python_compiler.process_file(file_path)

        # Check for import-related opcodes
        bytecode_str = "\n".join(obj.to_string() for obj in code_objects)
        assert "IMPORT_NAME" in bytecode_str
        assert "IMPORT_FROM" in bytecode_str
        assert "STORE_NAME" in bytecode_str

    def test_python_control_flow_domain(self, python_compiler):
        """Test Python control flow specifically"""
        file_path = (
            Path(__file__).parent
            / "source_samples/python/control_flow/test_control_flow.py"
        )
        code_objects = python_compiler.process_file(file_path)

        # Check for control flow opcodes
        bytecode_str = "\n".join(obj.to_string() for obj in code_objects)
        assert "POP_JUMP_IF_FALSE" in bytecode_str
        assert "FOR_ITER" in bytecode_str
        assert "JUMP_BACKWARD" in bytecode_str  # From our while loop fix

    def test_python_functions_domain(self, python_compiler):
        """Test Python functions specifically"""
        file_path = (
            Path(__file__).parent / "source_samples/python/functions/test_functions.py"
        )
        code_objects = python_compiler.process_file(file_path)

        # Check for function-related opcodes
        bytecode_str = "\n".join(obj.to_string() for obj in code_objects)
        assert "MAKE_FUNCTION" in bytecode_str
        assert "CALL" in bytecode_str
        assert "RETURN_VALUE" in bytecode_str
        # Note: LOAD_FAST would appear in comprehensions, but this file doesn't have any

    def test_javascript_operators_domain(self, js_compiler):
        """Test JavaScript operators specifically"""
        file_path = (
            Path(__file__).parent
            / "source_samples/javascript/operators/test_operators.js"
        )
        code_objects = js_compiler.process_file(file_path)

        # Check for operator-related opcodes
        bytecode_str = "\n".join(obj.to_string() for obj in code_objects)
        assert "BINARY_OP" in bytecode_str
        assert "BINARY_SUBSCR" in bytecode_str
        assert "STORE_SUBSCR" in bytecode_str

    def test_domain_isolation(self, python_compiler, js_compiler):
        """Test that each domain file is self-contained and doesn't depend on others"""
        for lang, compiler in [
            ("python", python_compiler),
            ("javascript", js_compiler),
        ]:
            files = self.get_domain_files(lang)

            for file_path in files:
                # Each file should compile independently
                try:
                    code_objects = compiler.process_file(file_path)
                    assert len(code_objects) > 0
                except Exception as e:
                    pytest.fail(f"{file_path} is not self-contained: {str(e)}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
