"""Test recursion handling for complex mathematical files."""

import pytest
import sys
from pathlib import Path
from common.bytecode import ASTCompiler


class TestRecursionHandling:
    """Test suite for recursion handling in complex files."""

    def test_complex_mathematical_file_processing(self):
        """Test that complex mathematical files can be processed without recursion errors."""
        # Test the Galois polynomial resolvents file that was causing recursion issues
        test_file = Path("tests/source_samples/python/advanced/test_recursion.py")

        compiler = ASTCompiler("python")

        # This should not raise a RecursionError
        result = compiler.process_file(test_file)

        # Verify we got results
        assert isinstance(result, list)
        assert len(result) > 0, "Should have processed code objects from complex file"

        # Verify all objects are valid MalwiObjects
        for obj in result:
            assert hasattr(obj, "to_string")
            assert hasattr(obj, "to_hash")
            assert hasattr(obj, "language")
            assert hasattr(obj, "file_path")
            assert obj.language == "python"
            assert str(obj.file_path).endswith("test_recursion.py")

    def test_recursion_limit_restoration(self):
        """Test that recursion limit is properly restored after processing."""
        test_file = Path("tests/source_samples/python/advanced/test_recursion.py")

        # Store original limit
        original_limit = sys.getrecursionlimit()

        compiler = ASTCompiler("python")
        result = compiler.process_file(test_file)

        # Verify limit was restored
        current_limit = sys.getrecursionlimit()
        assert current_limit == original_limit, (
            f"Recursion limit not restored: {current_limit} != {original_limit}"
        )

        # Verify we still got results
        assert len(result) > 0

    def test_simple_file_still_works(self):
        """Test that simple files still work normally after recursion handling changes."""
        # Use one of the existing test files
        test_file = Path("tests/source_samples/python/basics/test_basics.py")

        compiler = ASTCompiler("python")
        result = compiler.process_file(test_file)

        assert len(result) > 0
        for obj in result:
            assert obj.language == "python"

    def test_expected_bytecode_output_consistency(self):
        """Test that the complex file produces consistent bytecode output."""
        test_file = Path("tests/source_samples/python/advanced/test_recursion.py")
        expected_output_file = Path(
            "tests/source_samples/python/advanced/test_recursion_bytecode.txt"
        )

        # Skip if expected output file doesn't exist
        if not expected_output_file.exists():
            pytest.skip("Expected output file not found")

        compiler = ASTCompiler("python")
        objects = compiler.process_file(test_file)

        # Generate current output in the same format as expected (with headers and multi-line)
        current_output = []
        for obj in objects:
            current_output.append(f"=== {obj.name} ===")
            current_output.append(obj.to_string(mapped=False, one_line=False))
            current_output.append("")
        current_output_text = "\n".join(current_output)

        # Read expected output
        expected_output_text = expected_output_file.read_text()

        # Compare
        assert current_output_text.strip() == expected_output_text.strip(), (
            f"Bytecode output mismatch for {test_file}"
        )

    def test_expected_mapped_output_consistency(self):
        """Test that the complex file produces consistent mapped bytecode output."""
        test_file = Path("tests/source_samples/python/advanced/test_recursion.py")
        expected_output_file = Path(
            "tests/source_samples/python/advanced/test_recursion_bytecode_mapped.txt"
        )

        # Skip if expected output file doesn't exist
        if not expected_output_file.exists():
            pytest.skip("Expected mapped output file not found")

        compiler = ASTCompiler("python")
        objects = compiler.process_file(test_file)

        # Generate current mapped output in the same format as expected (with headers and multi-line)
        current_output = []
        for obj in objects:
            current_output.append(f"=== {obj.name} ===")
            current_output.append(obj.to_string(mapped=True, one_line=False))
            current_output.append("")
        current_output_text = "\n".join(current_output)

        # Read expected output
        expected_output_text = expected_output_file.read_text()

        # Compare
        assert current_output_text.strip() == expected_output_text.strip(), (
            f"Mapped bytecode output mismatch for {test_file}"
        )
