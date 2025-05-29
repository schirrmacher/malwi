import json
import pytest

from unittest.mock import patch

from research.mapping import SpecialCases

from research.malwi_object import (
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
            codeType=sample_code_type,
        )

    def test_to_tokens_and_string(self, malwi_obj, sample_code_type):
        malwi_obj.codeType = sample_code_type
        token_string = malwi_obj.to_token_string()
        assert "load_const" in token_string
        assert SpecialCases.INTEGER.value in token_string
        assert "hello" in token_string

    @patch("inspect.getsource")
    def test_retrieve_source_code(
        self, mock_getsourcelines, malwi_obj, sample_code_type
    ):
        mock_getsourcelines.return_value = "a = 1\nb = 'hello'\n"
        malwi_obj.codeType = sample_code_type  # ensure codeType is set
        source = malwi_obj.retrieve_source_code()
        assert source == "a = 1\nb = 'hello'\n"
        assert malwi_obj.code == source

        mock_getsourcelines.side_effect = TypeError
        malwi_obj.code = None  # Reset for fail case
        source_fail = malwi_obj.retrieve_source_code()
        assert source_fail is None
        assert malwi_obj.code is None

    @patch(
        "research.malwi_object.get_node_text_prediction",
        return_value=MOCK_PREDICTION_RESULT,
    )
    def test_predict(self, mock_get_pred, malwi_obj):
        # MalwiObject.predict() directly calls get_node_text_prediction
        prediction = malwi_obj.predict()
        assert prediction == MOCK_PREDICTION_RESULT
        assert malwi_obj.maliciousness == MOCK_PREDICTION_RESULT["probabilities"][1]
        mock_get_pred.assert_called_once_with(malwi_obj.to_token_string())

    def test_to_dict_yaml_json(self, malwi_obj, sample_code_type):
        malwi_obj.codeType = sample_code_type
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
        assert "source: YWJjZA==" in obj_yaml
        assert "code: |" in obj_yaml  # For LiteralStr

        obj_json = malwi_obj.to_json()
        json_data = json.loads(obj_json)
        assert json_data["path"] == "test.py"
