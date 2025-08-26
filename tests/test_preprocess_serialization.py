"""Test preprocessing serialization functionality (regression test for 'path' attribute issue)."""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from research.preprocess import _process_single_file_with_compiler
from common.malwi_object import MalwiObject
from common.bytecode import ASTCompiler


class TestPreprocessSerialization:
    """Test suite for preprocessing serialization functionality."""

    def test_process_file_serialization_attributes(self):
        """Regression test: ensure process_file accesses file_path (not path) attribute."""
        # Create a test Python file
        test_code = """
def test_function():
    email = "user@example.com"
    url = "http://insecure.com"
    protocol = "Connect via ftp"
    return True
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            temp_file_path = f.name

        try:
            # Test the _process_single_file_with_compiler function that was failing with AttributeError
            compiler = ASTCompiler("python")
            result = _process_single_file_with_compiler(Path(temp_file_path), compiler)

            # Verify the result structure
            assert isinstance(result, dict)
            assert "success" in result
            assert result["success"] is True
            assert "code_objects" in result
            assert isinstance(result["code_objects"], list)
            assert len(result["code_objects"]) > 0

            # Check each serialized object
            for obj_data in result["code_objects"]:
                assert isinstance(obj_data, dict)
                assert "tokens" in obj_data
                assert "hash" in obj_data
                assert "language" in obj_data
                assert "filepath" in obj_data  # This was failing before fix

                # Verify the filepath is correct (was trying to access obj.path before)
                assert obj_data["filepath"] == temp_file_path
                assert obj_data["language"] == "python"
                assert isinstance(obj_data["tokens"], str)
                assert isinstance(obj_data["hash"], str)
                assert len(obj_data["hash"]) == 64  # SHA256 hash length

        except AttributeError as e:
            pytest.fail(
                f"process_file failed with AttributeError (likely obj.path access): {e}"
            )
        finally:
            Path(temp_file_path).unlink()

    def test_process_file_attribute_access_regression(self):
        """Regression test: ensure process_file accesses correct attributes after refactoring."""
        # Create simple test code - content doesn't matter, testing serialization
        test_code = """
def simple_function():
    x = 42
    return x
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(test_code)
            temp_file_path = f.name

        try:
            compiler = ASTCompiler("python")
            result = _process_single_file_with_compiler(Path(temp_file_path), compiler)

            assert result["success"] is True
            assert len(result["code_objects"]) > 0

            # The key test: verify all objects have correct filepath serialization
            for obj_data in result["code_objects"]:
                # This was the line that failed: "filepath": str(obj.path)
                # Should now work with: "filepath": str(obj.file_path)
                assert "filepath" in obj_data
                assert obj_data["filepath"] == temp_file_path
                assert obj_data["language"] == "python"

        finally:
            Path(temp_file_path).unlink()

    def test_process_file_malformed_code(self):
        """Test preprocessing with malformed code (should not crash on serialization)."""
        # Create a file with syntax errors
        malformed_code = """
def broken_function(
    # Missing closing parenthesis and other syntax errors
    if x ==
        print("This won't parse")
    return
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(malformed_code)
            temp_file_path = f.name

        try:
            compiler = ASTCompiler("python")
            result = _process_single_file_with_compiler(Path(temp_file_path), compiler)

            # Should still return a result structure, not crash
            assert isinstance(result, dict)
            assert "success" in result
            # May or may not succeed depending on error handling, but should not crash

            if result["success"]:
                # If it succeeded, verify serialization works
                assert "code_objects" in result
                for obj_data in result["code_objects"]:
                    assert "filepath" in obj_data  # Key test - no AttributeError
                    assert obj_data["filepath"] == temp_file_path

        except AttributeError as e:
            if "path" in str(e):
                pytest.fail(
                    f"process_file failed with path-related AttributeError: {e}"
                )
            # Other AttributeErrors might be expected with malformed code

        finally:
            Path(temp_file_path).unlink()

    def test_process_file_javascript(self):
        """Test preprocessing with JavaScript code for attribute access bug."""
        test_code = """
function simpleFunction() {
    const x = 42;
    return x;
}
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(test_code)
            temp_file_path = f.name

        try:
            compiler = ASTCompiler("javascript")
            result = _process_single_file_with_compiler(Path(temp_file_path), compiler)

            assert result["success"] is True
            assert len(result["code_objects"]) > 0

            # The main test: verify serialization works for JavaScript too
            for obj_data in result["code_objects"]:
                # This was failing with AttributeError: 'MalwiObject' object has no attribute 'path'
                assert "filepath" in obj_data
                assert obj_data["filepath"] == temp_file_path
                assert obj_data["language"] == "javascript"

        finally:
            Path(temp_file_path).unlink()

    def test_malwi_object_attribute_consistency(self):
        """Test that MalwiObject has consistent attributes for serialization."""
        # Create a real MalwiObject to test attributes
        obj = MalwiObject(
            name="test_obj",
            language="python",
            file_path="/test/example.py",
            file_source_code="print('test')",
        )

        # Test that the object has the expected attributes
        assert hasattr(obj, "file_path")
        assert not hasattr(obj, "path")  # Should not have old attribute

        # Test serialization that would have failed before the fix
        try:
            # This mimics the serialization in preprocess.py that was failing
            serialization_data = {
                "tokens": obj.to_string(one_line=True),
                "hash": obj.to_hash(),
                "language": obj.language,
                "filepath": str(
                    obj.file_path
                ),  # This line was causing AttributeError before
            }

            # Verify the serialization worked
            assert serialization_data["filepath"] == "/test/example.py"
            assert serialization_data["language"] == "python"
            assert isinstance(serialization_data["hash"], str)

        except AttributeError as e:
            if "path" in str(e):
                pytest.fail(
                    f"Serialization failed with path-related AttributeError: {e}"
                )
            raise  # Re-raise if it's a different AttributeError

    def test_process_file_empty_file(self):
        """Test preprocessing with empty file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("")  # Empty file
            temp_file_path = f.name

        try:
            compiler = ASTCompiler("python")
            result = _process_single_file_with_compiler(Path(temp_file_path), compiler)

            # Should handle empty files gracefully
            assert isinstance(result, dict)
            assert "success" in result

            if result["success"]:
                assert "code_objects" in result
                for obj_data in result["code_objects"]:
                    assert "filepath" in obj_data
                    assert obj_data["filepath"] == temp_file_path

        finally:
            Path(temp_file_path).unlink()
