import json
import yaml
import types
import pytest
import base64
import tempfile

from pathlib import Path
from unittest.mock import patch

from research.mapping import SpecialCases

from research.disassemble_python import (
    MalwiObject,
    LiteralStr,
)


MOCK_TARGET_FILES_DATA = {"python": ["setup.py", "manage.py"]}

MOCK_PREDICTION_RESULT = {"probabilities": [0.2, 0.8]}


class TestMalwiObject:
    @pytest.fixture
    def sample_code_type(self):
        return compile("a = 1\nb = 'hello'\nif a > 0: jump_target()", "test.py", "exec")

    @pytest.fixture
    def malwi_obj(self, sample_code_type):
        return MalwiObject(
            name="<module>",
            language="python",
            file_source_code="abcd",
            file_path="test.py",
            code_type=sample_code_type,
        )

    def test_to_tokens_and_string(self, malwi_obj, sample_code_type):
        malwi_obj.code_type = sample_code_type
        token_string = malwi_obj.to_token_string()
        assert "load_const" in token_string
        assert SpecialCases.INTEGER.value in token_string
        assert "hello" in token_string

    @patch("inspect.getsource")
    def test_retrieve_source_code(
        self, mock_getsourcelines, malwi_obj, sample_code_type
    ):
        mock_getsourcelines.return_value = "a = 1\nb = 'hello'\n"
        malwi_obj.code_type = sample_code_type  # ensure codeType is set
        source = malwi_obj.retrieve_source_code()
        assert source == "a = 1\nb = 'hello'\n"
        assert malwi_obj.code == source

        mock_getsourcelines.side_effect = TypeError
        malwi_obj.code = None  # Reset for fail case
        source_fail = malwi_obj.retrieve_source_code()
        assert source_fail is None
        assert malwi_obj.code is None

    @patch(
        "research.disassemble_python.get_node_text_prediction",
        return_value=MOCK_PREDICTION_RESULT,
    )
    def test_predict(self, mock_get_pred, malwi_obj):
        # MalwiObject.predict() only calls get_node_text_prediction if token string has special tokens
        # The default fixture doesn't have special tokens, so predict returns None
        prediction = malwi_obj.predict()
        assert prediction is None
        assert malwi_obj.maliciousness is None
        mock_get_pred.assert_not_called()
        
    @patch(
        "research.disassemble_python.get_node_text_prediction", 
        return_value=MOCK_PREDICTION_RESULT,
    )
    def test_predict_with_special_tokens(self, mock_get_pred):
        # Create an object with code that has special tokens (print = USER_IO)
        code_with_special = compile("print('hello')", "test.py", "exec")
        obj = MalwiObject(
            name="<module>",
            language="python", 
            file_source_code="print('hello')",
            file_path="test.py",
            code_type=code_with_special,
        )
        
        prediction = obj.predict()
        assert prediction == MOCK_PREDICTION_RESULT
        assert obj.maliciousness == MOCK_PREDICTION_RESULT["probabilities"][1]
        mock_get_pred.assert_called_once_with(obj.to_token_string())

    def test_to_dict_yaml_json(self, malwi_obj, sample_code_type):
        malwi_obj.code_type = sample_code_type
        malwi_obj.code = "source code\nline2"  # Multi-line for LiteralStr
        malwi_obj.maliciousness = 0.75

        obj_dict = malwi_obj.to_dict()
        assert obj_dict["path"] == "test.py"
        content_item = obj_dict["contents"][0]
        assert content_item["name"] == "<module>"
        assert content_item["score"] == 0.75
        assert isinstance(content_item["code"], LiteralStr)

        obj_yaml = malwi_obj.to_yaml()
        assert "path: test.py" in obj_yaml
        assert "source code\n    line2" in obj_yaml
        assert "code: |" in obj_yaml  # For LiteralStr

        obj_json = malwi_obj.to_json()
        json_data = json.loads(obj_json)
        assert json_data["path"] == "test.py"


def get_fake_code_object():
    def sample_function():
        return "malicious"

    return sample_function.__code__


def test_from_file_reads_yaml_correctly():
    fake_source = "print('hello world')"
    encoded_source = base64.b64encode(fake_source.encode("utf-8")).decode("utf-8")

    yaml_data = {
        "statistics": {
            "total_files": 1,
            "skipped_files": 0,
            "processed_objects": 1,
            "malicious_objects": 0,
        },
        "details": [
            {
                "path": "example.py",
                "contents": [
                    {
                        "name": "test_function",
                        "score": 0.3,
                        "tokens": "some tokenized form",
                        "hash": "fakehash",
                        "warnings": ["suspicious"],
                    }
                ],
            }
        ],
        "sources": {"example.py": encoded_source},
    }

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as tmp:
        yaml.dump(yaml_data, tmp, sort_keys=False)
        tmp_path = Path(tmp.name)

    malwi_objects = MalwiObject.from_file(tmp_path, language="python")

    assert len(malwi_objects) == 1
    obj = malwi_objects[0]

    assert obj.name == "test_function"
    assert obj.file_path == "example.py"
    assert obj.file_source_code == "print('hello world')"
    assert isinstance(obj.code_type, types.CodeType)
    assert (
        obj.to_token_string()
        == "suspicious resume push_null load_name USER_IO load_const hello world call pop_top return_const None"
    )
    assert obj.warnings == ["suspicious"]


def test_from_file_reads_object_correctly():
    fake_source = """
class Dog:
    def speak(self):
        return "Woof!"

class Cat:
    def speak(self):
        return "Meow!"
"""
    encoded_source = base64.b64encode(fake_source.encode("utf-8")).decode("utf-8")

    yaml_data = {
        "statistics": {
            "total_files": 1,
            "skipped_files": 0,
            "processed_objects": 1,
            "malicious_objects": 0,
        },
        "details": [
            {
                "path": "example.py",
                "contents": [
                    {
                        "name": "Cat.speak",
                        "score": 0.3,
                        "tokens": "some tokenized form",
                        "hash": "fakehash",
                        "warnings": ["suspicious"],
                    }
                ],
            }
        ],
        "sources": {"example.py": encoded_source},
    }

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yaml", delete=False) as tmp:
        yaml.dump(yaml_data, tmp, sort_keys=False)
        tmp_path = Path(tmp.name)

    malwi_objects = MalwiObject.from_file(tmp_path, language="python")

    assert len(malwi_objects) == 1
    obj = malwi_objects[0]

    assert obj.name == "Cat.speak"
    assert obj.file_path == "example.py"
    assert isinstance(obj.code_type, types.CodeType)
    assert obj.to_token_string() == "suspicious resume return_const Meow!"
    assert obj.warnings == ["suspicious"]
