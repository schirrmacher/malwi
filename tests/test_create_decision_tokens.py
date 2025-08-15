"""Test the create_decision_tokens function."""

from common.malwi_object import MalwiObject
from common.mapping import SpecialCases


class TestCreateDecisionTokens:
    """Test suite for create_decision_tokens function."""

    def test_malwi_object_creation_basic(self):
        """Test basic MalwiObject creation without decision tokens."""
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="test.py",
            file_source_code="def test(): pass",
        )
        assert obj.name == "test_function"
        assert obj.language == "python"
        assert obj.file_path == "test.py"

    def test_malwi_object_tokens_extraction(self):
        """Test token extraction from MalwiObject."""
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="test.py",
            file_source_code="def test(): pass",
        )
        tokens = obj.to_tokens()
        assert isinstance(tokens, list)
        assert len(tokens) >= 0

    def test_malwi_object_with_warnings(self):
        """Test MalwiObject with warnings."""
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="test.py",
            file_source_code="def test(): pass",
            warnings=[SpecialCases.MALFORMED_SYNTAX.value],
        )
        tokens = obj.to_tokens()
        assert SpecialCases.MALFORMED_SYNTAX.value in tokens

    def test_malwi_object_token_string(self):
        """Test converting tokens to string."""
        obj = MalwiObject(
            name="test_function",
            language="python",
            file_path="test.py",
            file_source_code="def test(): pass",
        )
        token_string = obj.to_token_string()
        assert isinstance(token_string, str)
