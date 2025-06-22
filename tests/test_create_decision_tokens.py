"""Test the create_decision_tokens function."""

import pytest
from research.disassemble_python import MalwiObject, SpecialCases
from research.mapping import FUNCTION_MAPPING


class TestCreateDecisionTokens:
    """Test suite for create_decision_tokens function."""
    
    def test_create_decision_tokens_empty(self):
        """Test with empty object list."""
        result = MalwiObject.create_decision_tokens([])
        assert result == ""
    
    def test_create_decision_tokens_with_objects(self):
        """Test with objects containing various tokens."""
        # Create mock objects with different token counts
        obj1 = MalwiObject(
            name="test1",
            language="python",
            file_path="test1.py",
            file_source_code="",
            warnings=[SpecialCases.TARGETED_FILE.value]
        )
        
        obj2 = MalwiObject(
            name="test2", 
            language="python",
            file_path="test2.py",
            file_source_code="",
            warnings=[SpecialCases.TARGETED_FILE.value, SpecialCases.MALFORMED_FILE.value]
        )
        
        # Get decision tokens
        result = MalwiObject.create_decision_tokens([obj1, obj2])
        
        # Should contain tokens ordered by count
        tokens = result.split()
        assert len(tokens) > 0
        assert SpecialCases.TARGETED_FILE.value in tokens
        assert SpecialCases.MALFORMED_FILE.value in tokens
        
        # TARGETED_FILE appears twice, MALFORMED_FILE once, so TARGETED_FILE should come first
        targeted_idx = tokens.index(SpecialCases.TARGETED_FILE.value)
        malformed_idx = tokens.index(SpecialCases.MALFORMED_FILE.value)
        assert targeted_idx < malformed_idx
    
    def test_create_decision_tokens_with_malicious_count(self):
        """Test that malicious count is included when non-zero."""
        obj = MalwiObject(
            name="test",
            language="python", 
            file_path="test.py",
            file_source_code="",
            warnings=[SpecialCases.TARGETED_FILE.value]
        )
        
        # With malicious_count > 0
        result = MalwiObject.create_decision_tokens([obj], malicious_count=5)
        tokens = result.split()
        
        # Should include MALICIOUS_COUNT token
        assert "MALICIOUS_COUNT" in tokens
        
        # MALICIOUS_COUNT has value 5, TARGETED_FILE has value 1
        # So MALICIOUS_COUNT should come first
        malicious_idx = tokens.index("MALICIOUS_COUNT")
        targeted_idx = tokens.index(SpecialCases.TARGETED_FILE.value)
        assert malicious_idx < targeted_idx
    
    def test_create_decision_tokens_ordering(self):
        """Test that tokens are properly ordered by count."""
        # Create objects with different warning frequencies
        objects = []
        
        # Add 3 objects with TARGETED_FILE
        for i in range(3):
            objects.append(MalwiObject(
                name=f"test{i}",
                language="python",
                file_path=f"test{i}.py", 
                file_source_code="",
                warnings=[SpecialCases.TARGETED_FILE.value]
            ))
        
        # Add 2 objects with MALFORMED_FILE
        for i in range(2):
            objects.append(MalwiObject(
                name=f"malformed{i}",
                language="python",
                file_path=f"malformed{i}.py",
                file_source_code="",
                warnings=[SpecialCases.MALFORMED_FILE.value]
            ))
        
        # Add 1 object with MALFORMED_SYNTAX
        objects.append(MalwiObject(
            name="syntax",
            language="python",
            file_path="syntax.py",
            file_source_code="",
            warnings=[SpecialCases.MALFORMED_SYNTAX.value]
        ))
        
        result = MalwiObject.create_decision_tokens(objects)
        tokens = result.split()
        
        # Find positions
        targeted_pos = tokens.index(SpecialCases.TARGETED_FILE.value)
        malformed_pos = tokens.index(SpecialCases.MALFORMED_FILE.value)
        syntax_pos = tokens.index(SpecialCases.MALFORMED_SYNTAX.value)
        
        # Should be ordered by count: TARGETED_FILE (3) > MALFORMED_FILE (2) > MALFORMED_SYNTAX (1)
        assert targeted_pos < malformed_pos
        assert malformed_pos < syntax_pos