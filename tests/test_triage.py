# research/test_triage.py

import unittest

from pathlib import Path
from unittest.mock import patch, MagicMock, call

import research.triage as triage_module


class TestProcessObjectFile(unittest.TestCase):
    @patch("research.triage.triage")
    @patch("research.triage.MalwiObject")
    def test_process_object_file_success(
        self, MockTriageModuleMalwiObject, mock_triage_module_triage_func
    ):
        # Setup
        mock_file_path = Path("dummy/test.yaml")
        mock_out_path = Path("output_dir")
        mock_grep_string = "exploit"
        mock_auto_triaging = "malicious"
        mock_max_tokens = 100
        mock_triaging_type = "auto"
        mock_llm_prompt = "Is this bad?"
        mock_llm_model = "test_model"

        mock_malwi_instance = MagicMock()
        MockTriageModuleMalwiObject.from_file.return_value = [mock_malwi_instance]

        triage_module.process_object_file(
            file_path=mock_file_path,
            out_path=mock_out_path,
            grep_string=mock_grep_string,
            auto_triaging=mock_auto_triaging,
            max_tokens=mock_max_tokens,
            triaging_type=mock_triaging_type,
            llm_prompt=mock_llm_prompt,
            llm_model=mock_llm_model,
        )

        MockTriageModuleMalwiObject.from_file.assert_called_once_with(mock_file_path)
        mock_triage_module_triage_func.assert_called_once_with(
            all_objects=[mock_malwi_instance],
            out_path=mock_out_path,
            grep_string=mock_grep_string,
            auto_triaging=mock_auto_triaging,
            max_tokens=mock_max_tokens,
            triaging_type=mock_triaging_type,
            llm_prompt=mock_llm_prompt,
            llm_model=mock_llm_model,
        )

    def test_process_object_file_exception_from_malwiobject(self):
        mock_file_path = Path("dummy/test.yaml")
        mock_out_path = Path("output_dir")
        
        with patch("research.triage.MalwiObject") as MockTriageModuleMalwiObject, \
             patch("research.triage.triage") as mock_triage_module_triage_func:
            
            MockTriageModuleMalwiObject.from_file.side_effect = Exception(
                "MalwiObject error"
            )

            # Should not raise exception, just log error
            triage_module.process_object_file(
                file_path=mock_file_path,
                out_path=mock_out_path,
                # llm_model defaults to "gemma3" in the function signature if not provided
            )

            MockTriageModuleMalwiObject.from_file.assert_called_once_with(mock_file_path)
            mock_triage_module_triage_func.assert_not_called()

    def test_process_object_file_exception_from_triage(self):
        mock_file_path = Path("dummy/test.yaml")
        mock_out_path = Path("output_dir")
        
        with patch("research.triage.MalwiObject") as MockTriageModuleMalwiObject, \
             patch("research.triage.triage") as mock_triage_module_triage_func:
            
            mock_malwi_instance = MagicMock()
            MockTriageModuleMalwiObject.from_file.return_value = [mock_malwi_instance]
            mock_triage_module_triage_func.side_effect = Exception("Triage error")

            # Should not raise exception, just log error
            triage_module.process_object_file(
                file_path=mock_file_path,
                out_path=mock_out_path,
                # llm_model defaults to "gemma3"
            )

            MockTriageModuleMalwiObject.from_file.assert_called_once_with(mock_file_path)
            mock_triage_module_triage_func.assert_called_once()

    @patch("research.triage.triage")
    @patch("research.triage.MalwiObject")
    def test_process_object_file_multiple_functions_one_file(
        self, MockTriageModuleMalwiObject, mock_triage_module_triage_func
    ):
        mock_file_path = Path("dummy/multi_func.yaml")
        mock_out_path = Path("output_dir_multi")

        mock_func1_obj = MagicMock(name="func1")
        mock_func2_obj = MagicMock(name="func2")
        mock_func3_obj = MagicMock(name="func3")
        all_mock_objects = [mock_func1_obj, mock_func2_obj, mock_func3_obj]
        MockTriageModuleMalwiObject.from_file.return_value = all_mock_objects

        test_grep_string = None
        test_auto_triaging = None
        test_max_tokens = 0
        test_triaging_type = "manual"
        test_llm_prompt = None
        # Using the default model name from the script's function signature for consistency
        test_llm_model = "gemma3"

        triage_module.process_object_file(
            file_path=mock_file_path,
            out_path=mock_out_path,
            grep_string=test_grep_string,
            auto_triaging=test_auto_triaging,
            max_tokens=test_max_tokens,
            triaging_type=test_triaging_type,
            llm_prompt=test_llm_prompt,
            llm_model=test_llm_model,
        )

        MockTriageModuleMalwiObject.from_file.assert_called_once_with(mock_file_path)
        mock_triage_module_triage_func.assert_called_once_with(
            all_objects=all_mock_objects,
            out_path=mock_out_path,
            grep_string=test_grep_string,
            auto_triaging=test_auto_triaging,
            max_tokens=test_max_tokens,
            triaging_type=test_triaging_type,
            llm_prompt=test_llm_prompt,
            llm_model=test_llm_model,
        )


class TestMainFunction(unittest.TestCase):
    @patch("research.triage.process_object_file")
    @patch("argparse.ArgumentParser")
    def test_main_single_file_processing(
        self, MockArgumentParser, mock_internal_process_object_file
    ):
        mock_args = MagicMock()
        mock_args.path = MagicMock(spec=Path)
        mock_args.path.is_file.return_value = True
        mock_args.path.is_dir.return_value = False
        mock_args.out = Path("triaging_output")
        mock_args.prompt = "test prompt"
        mock_args.model = "another_model"  # Testing a non-default model pass-through
        mock_args.grep = "findme"
        mock_args.max_tokens = 50
        mock_args.triage_ollama = False
        mock_args.auto = None

        MockArgumentParser.return_value.parse_args.return_value = mock_args

        triage_module.main()

        mock_args.path.is_file.assert_called_once()
        mock_internal_process_object_file.assert_called_once_with(
            file_path=mock_args.path,
            out_path=mock_args.out,
            grep_string=mock_args.grep,
            auto_triaging=None,
            max_tokens=mock_args.max_tokens,
            triaging_type="manual",
            llm_model=mock_args.model,  # Should be "another_model"
            llm_prompt=mock_args.prompt,
        )

    @patch("research.triage.process_object_file")
    @patch("argparse.ArgumentParser")
    @patch("research.triage.tqdm")
    def test_main_directory_processing(
        self,
        mock_tqdm_constructor,
        MockArgumentParser,
        mock_internal_process_object_file,
    ):
        mock_args = MagicMock()
        mock_args.path = MagicMock(spec=Path)
        mock_args.path.is_file.return_value = False
        mock_args.path.is_dir.return_value = True

        file1_yaml = MagicMock(spec=Path)
        file1_yaml.name = "file1.yaml"
        file1_yaml.is_file.return_value = True
        file1_yaml.suffix = ".yaml"
        file2_yml = MagicMock(spec=Path)
        file2_yml.name = "file2.yml"
        file2_yml.is_file.return_value = True
        file2_yml.suffix = ".yml"
        file3_txt = MagicMock(spec=Path)
        file3_txt.name = "file3.txt"
        file3_txt.is_file.return_value = True
        file3_txt.suffix = ".txt"

        mock_args.path.iterdir.return_value = [file1_yaml, file2_yml, file3_txt]
        mock_tqdm_constructor.side_effect = lambda iterable, **kwargs: iterable

        mock_args.out = Path("triaging_output_dir")
        mock_args.prompt = None
        mock_args.model = "gemma3"  # Script's default for --model
        mock_args.grep = None
        mock_args.max_tokens = 0
        mock_args.triage_ollama = True
        mock_args.auto = None

        MockArgumentParser.return_value.parse_args.return_value = mock_args

        triage_module.main()

        mock_args.path.is_file.assert_called_once()
        mock_args.path.is_dir.assert_called_once()
        mock_args.path.iterdir.assert_called_once()

        filtered_files_for_tqdm = [file1_yaml, file2_yml]
        mock_tqdm_constructor.assert_called_once_with(
            filtered_files_for_tqdm, desc="Processing files"
        )

        self.assertEqual(mock_internal_process_object_file.call_count, 2)
        expected_calls = [
            call(
                file_path=file1_yaml,
                out_path=mock_args.out,
                grep_string=None,
                auto_triaging=None,
                max_tokens=0,
                triaging_type="ollama",
                llm_model="gemma3",  # Script's default for --model
                llm_prompt=None,
            ),
            call(
                file_path=file2_yml,
                out_path=mock_args.out,
                grep_string=None,
                auto_triaging=None,
                max_tokens=0,
                triaging_type="ollama",
                llm_model="gemma3",  # Script's default for --model
                llm_prompt=None,
            ),
        ]
        mock_internal_process_object_file.assert_has_calls(
            expected_calls, any_order=True
        )

    @patch("research.triage.process_object_file")
    @patch("argparse.ArgumentParser")
    def test_main_auto_triaging_benign(
        self, MockArgumentParser, mock_internal_process_object_file
    ):
        mock_args = MagicMock()
        mock_args.path = MagicMock(spec=Path)
        mock_args.path.is_file.return_value = True
        mock_args.out = Path("out")
        mock_args.prompt = None
        mock_args.model = "gemma3"  # Script's default
        mock_args.grep = None
        mock_args.max_tokens = 0
        mock_args.triage_ollama = False
        mock_args.auto = "benign"
        MockArgumentParser.return_value.parse_args.return_value = mock_args

        triage_module.main()

        mock_internal_process_object_file.assert_called_once_with(
            file_path=mock_args.path,
            out_path=mock_args.out,
            grep_string=None,
            auto_triaging="benign",
            max_tokens=0,
            triaging_type="auto",
            llm_model="gemma3",  # Script's default
            llm_prompt=None,
        )

    @patch("research.triage.process_object_file")
    @patch("argparse.ArgumentParser")
    def test_main_auto_triaging_malicious(
        self, MockArgumentParser, mock_internal_process_object_file
    ):
        mock_args = MagicMock()
        mock_args.path = MagicMock(spec=Path)
        mock_args.path.is_file.return_value = True
        mock_args.out = Path("out")
        mock_args.prompt = None
        mock_args.model = "ollama_model_for_auto"  # Testing a specific model string
        mock_args.grep = None
        mock_args.max_tokens = 0
        mock_args.triage_ollama = False
        mock_args.auto = "malicious"
        MockArgumentParser.return_value.parse_args.return_value = mock_args

        triage_module.main()

        mock_internal_process_object_file.assert_called_once_with(
            file_path=mock_args.path,
            out_path=mock_args.out,
            grep_string=None,
            auto_triaging="malicious",
            max_tokens=0,
            triaging_type="auto",
            llm_model="ollama_model_for_auto",
            llm_prompt=None,
        )

    def test_main_invalid_path(self):
        with patch("argparse.ArgumentParser") as MockArgumentParser:
            mock_args = MagicMock()
            mock_args.path = MagicMock(spec=Path)
            mock_args.path.is_file.return_value = False
            mock_args.path.is_dir.return_value = False

            MockArgumentParser.return_value.parse_args.return_value = mock_args

            # Should not raise exception, just log error
            triage_module.main()

            mock_args.path.is_file.assert_called_once()
            mock_args.path.is_dir.assert_called_once()

    @patch("research.triage.process_object_file")
    @patch("argparse.ArgumentParser")
    def test_main_default_triaging_type_manual(
        self, MockArgumentParser, mock_internal_process_object_file
    ):
        mock_args = MagicMock()
        mock_args.path = MagicMock(spec=Path)
        mock_args.path.is_file.return_value = True
        mock_args.out = Path("out_dir")
        mock_args.prompt = "A specific prompt"
        mock_args.model = "gemma3"  # Testing with script's default model
        mock_args.grep = "pat"
        mock_args.max_tokens = 10
        mock_args.triage_ollama = False
        mock_args.auto = None
        MockArgumentParser.return_value.parse_args.return_value = mock_args

        triage_module.main()

        mock_internal_process_object_file.assert_called_once_with(
            file_path=mock_args.path,
            out_path=mock_args.out,
            grep_string="pat",
            auto_triaging=None,
            max_tokens=10,
            triaging_type="manual",
            llm_model="gemma3",  # Script's default model
            llm_prompt="A specific prompt",
        )


if __name__ == "__main__":
    unittest.main()
