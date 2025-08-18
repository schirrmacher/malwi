"""Test the MalwiObject class and its methods."""

import pytest
import tempfile
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from common.mapping import SpecialCases
from common.malwi_object import MalwiObject, LiteralStr
from common.bytecode import ASTCompiler, CodeObject


class TestMalwiObject:
    """Test suite for MalwiObject class."""

    @pytest.fixture
    def sample_ast_code_object(self):
        """Create a sample AST CodeObject for testing."""
        return CodeObject(
            name="test_function",
            byte_code=[],
            source_code="def test(): pass",
            path=Path("test.py"),
            location=(1, 1),
            language="python",
        )

    @pytest.fixture
    def malwi_obj(self, sample_ast_code_object):
        """Create a MalwiObject instance for testing."""
        return MalwiObject(
            name="test_function",
            language="python",
            file_source_code="def test(): pass",
            file_path="test.py",
            code_object=sample_ast_code_object,
        )

    def test_to_tokens_and_string(self, malwi_obj):
        """Test token extraction and string conversion."""
        tokens = malwi_obj.to_tokens()
        assert isinstance(tokens, list)

        token_string = malwi_obj.to_token_string()
        assert isinstance(token_string, str)
        assert token_string == " ".join(tokens)

    def test_source_code_population(self, malwi_obj):
        """Test source code population from AST CodeObject."""
        # Populate source code from AST CodeObject
        if malwi_obj.code_object and hasattr(malwi_obj.code_object, "source_code"):
            malwi_obj.code = malwi_obj.code_object.source_code

        # Should have populated from code_object
        assert malwi_obj.code is not None
        assert isinstance(malwi_obj.code, str)

    @patch("common.malwi_object.get_node_text_prediction")
    def test_predict(self, mock_predict, malwi_obj):
        """Test maliciousness prediction."""
        mock_predict.return_value = {"probabilities": [0.3, 0.7]}

        # Mock the token string to contain special tokens so prediction is triggered
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
        # Mock token string without special tokens
        with patch.object(
            malwi_obj, "to_token_string", return_value="normal_function call"
        ):
            result = malwi_obj.predict()

        # Should not set maliciousness and return None
        assert malwi_obj.maliciousness is None
        assert result is None

    def test_to_dict_yaml_json(self, malwi_obj):
        """Test conversion to dict, YAML, and JSON."""
        malwi_obj.maliciousness = 0.8
        # Populate source code from AST CodeObject
        if malwi_obj.code_object and hasattr(malwi_obj.code_object, "source_code"):
            malwi_obj.code = malwi_obj.code_object.source_code

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
        hash_val = malwi_obj.to_string_hash()
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

        tokens = obj.to_tokens()
        assert SpecialCases.MALFORMED_SYNTAX.value in tokens

    def test_malwi_object_javascript(self):
        """Test MalwiObject with JavaScript language."""
        obj = MalwiObject(
            name="test_function",
            language="javascript",
            file_path="test.js",
            file_source_code="function test() { return true; }",
        )

        assert obj.language == "javascript"
        tokens = obj.to_tokens()
        assert isinstance(tokens, list)


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
    assert obj.code is None
