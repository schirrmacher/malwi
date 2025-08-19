"""Test the MalwiObject class and its methods."""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from common.mapping import SpecialCases
from common.malwi_object import MalwiObject, LiteralStr
from common.bytecode import ASTCompiler


class TestMalwiObject:
    """Test suite for MalwiObject class."""

    @pytest.fixture
    def sample_bytecode(self):
        """Create sample bytecode for testing."""
        # Mock bytecode instructions for testing
        from unittest.mock import MagicMock

        mock_instruction = MagicMock()
        mock_instruction.to_string.return_value = "LOAD_CONST test"
        return [mock_instruction]

    @pytest.fixture
    def malwi_obj(self, sample_bytecode):
        """Create a MalwiObject instance for testing."""
        return MalwiObject(
            name="test_function",
            language="python",
            file_source_code="def test(): pass",
            file_path="test.py",
            byte_code=sample_bytecode,
            source_code="def test(): pass",
            location=(1, 1),
        )

    def test_to_tokens_and_string(self, malwi_obj):
        """Test token extraction and string conversion."""
        tokens = malwi_obj.to_tokens()
        assert isinstance(tokens, list)

        token_string = malwi_obj.to_token_string()
        assert isinstance(token_string, str)

    def test_source_code_population(self, malwi_obj):
        """Test source code population."""
        # Should have source code from merged properties
        assert malwi_obj.source_code is not None
        assert isinstance(malwi_obj.source_code, str)

    @patch("common.malwi_object.get_node_text_prediction")
    def test_predict(self, mock_predict, malwi_obj):
        """Test maliciousness prediction."""
        mock_predict.return_value = {"probabilities": [0.3, 0.7]}

        # Mock the to_tokens method to return special tokens so prediction is triggered
        with patch.object(
            malwi_obj,
            "to_token_string",
            return_value="DYNAMIC_CODE_EXECUTION test_function",
        ):
            result = malwi_obj.predict()

        # Should have set maliciousness score
        assert malwi_obj.maliciousness == 0.7
        assert result == {"probabilities": [0.3, 0.7]}

    def test_predict_no_special_tokens(self, malwi_obj):
        """Test prediction when no special tokens are present."""
        # Mock to_token_string to return tokens without special tokens
        with patch.object(
            malwi_obj,
            "to_token_string",
            return_value="normal_function call",
        ):
            result = malwi_obj.predict()

        # Should not set maliciousness and return None
        assert malwi_obj.maliciousness is None
        assert result is None

    def test_to_dict_yaml_json(self, malwi_obj):
        """Test conversion to dict, YAML, and JSON."""
        malwi_obj.maliciousness = 0.8
        # Code is now available via the property

        # Test to_dict
        data = malwi_obj.to_dict()
        assert isinstance(data, dict)
        assert "path" in data
        assert "contents" in data
        assert data["path"] == "test.py"
        assert len(data["contents"]) == 1

        # Test to_yaml
        yaml_str = malwi_obj.to_yaml()
        assert isinstance(yaml_str, str)
        assert "test_function" in yaml_str

        # Test to_json
        json_str = malwi_obj.to_json()
        assert isinstance(json_str, str)
        assert "test_function" in json_str

    def test_string_hash(self, malwi_obj):
        """Test string hash generation."""
        hash_val = malwi_obj.to_hash()
        assert isinstance(hash_val, str)
        assert len(hash_val) == 64  # SHA256 hex digest

    def test_all_tokens_class_method(self):
        """Test the all_tokens class method."""
        tokens = MalwiObject.all_tokens("python")
        assert isinstance(tokens, list)
        assert len(tokens) > 0
        assert all(isinstance(token, str) for token in tokens)

    def test_malwi_object_with_warnings(self):
        """Test MalwiObject creation with warnings."""
        obj = MalwiObject(
            name="error_object",
            language="python",
            file_path="error.py",
            file_source_code="invalid syntax",
            warnings=[SpecialCases.MALFORMED_SYNTAX.value],
        )

        # Test that warnings are handled in prediction
        # Since there's no bytecode, prediction should use warnings + MALFORMED_FILE
        result = obj.predict()
        # For objects without bytecode and with warnings, maliciousness should be None
        # unless special tokens are detected
        assert obj.maliciousness is None

    def test_malwi_object_javascript(self):
        """Test MalwiObject with JavaScript language."""
        obj = MalwiObject(
            name="test_function",
            language="javascript",
            file_path="test.js",
            file_source_code="function test() { return true; }",
        )

        assert obj.language == "javascript"
        # Test token extraction if bytecode is available
        if obj.byte_code:
            tokens = obj.to_tokens()
            assert isinstance(tokens, list)
        # For JavaScript objects created manually, bytecode may not be created
        # This is fine as the test is just checking the object creation

    def test_large_file_warning(self):
        """Test that LARGE_FILE warning is added for files >500KB."""
        # Create a large temporary file for testing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            # Write 600KB of content (bigger than 500KB threshold)
            large_content = 'x = "' + "A" * (600 * 1024) + '"'
            f.write(large_content)
            large_file_path = f.name

        try:
            # Create MalwiObject with the large file
            obj = MalwiObject(
                name="large_file_test",
                language="python",
                file_path=large_file_path,
                file_source_code=large_content,
            )

            # Get tokens and check for LARGE_FILE warning
            tokens = obj.to_tokens()
            assert SpecialCases.LARGE_FILE.value in tokens
            # LARGE_FILE should be one of the first tokens (warnings come first)
            assert tokens.index(SpecialCases.LARGE_FILE.value) < 5

        finally:
            # Clean up the temporary file
            Path(large_file_path).unlink()

    def test_small_file_no_warning(self):
        """Test that small files do not get LARGE_FILE warning."""
        # Create a small temporary file for testing
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            small_content = 'x = "small content"'
            f.write(small_content)
            small_file_path = f.name

        try:
            # Create MalwiObject with the small file
            obj = MalwiObject(
                name="small_file_test",
                language="python",
                file_path=small_file_path,
                file_source_code=small_content,
            )

            # Get tokens and check that LARGE_FILE warning is NOT present
            tokens = obj.to_tokens()
            assert SpecialCases.LARGE_FILE.value not in tokens

        finally:
            # Clean up the temporary file
            Path(small_file_path).unlink()

    def test_nonexistent_file_no_warning(self):
        """Test that nonexistent files don't cause errors and don't get LARGE_FILE warning."""
        obj = MalwiObject(
            name="nonexistent_file_test",
            language="python",
            file_path="/nonexistent/path/file.py",
            file_source_code="pass",
        )

        # Should not raise an error and should not have LARGE_FILE warning
        tokens = obj.to_tokens()
        assert SpecialCases.LARGE_FILE.value not in tokens


def test_literal_str():
    """Test LiteralStr class."""
    literal = LiteralStr("test\nmultiline\nstring")
    assert isinstance(literal, str)
    assert str(literal) == "test\nmultiline\nstring"


def test_malwi_object_creation_minimal():
    """Test minimal MalwiObject creation."""
    obj = MalwiObject(
        name="minimal",
        language="python",
        file_path="minimal.py",
        file_source_code="pass",
    )

    assert obj.name == "minimal"
    assert obj.language == "python"
    assert obj.file_path == "minimal.py"
    assert obj.maliciousness is None
    assert obj.byte_code is None
