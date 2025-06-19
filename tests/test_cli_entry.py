import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import os

# Add src to path to import from source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli.entry import main


class TestCLIEntry:
    """Minimal tests for CLI entry point"""

    def test_help_message(self, capsys):
        """Test that help message displays properly"""
        with patch.object(sys, "argv", ["malwi", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "malwi - AI Python Malware Scanner" in captured.out
        assert "PATH" in captured.out

    def test_no_arguments_shows_error(self, capsys):
        """Test that running without arguments shows error"""
        with patch.object(sys, "argv", ["malwi"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "the following arguments are required: PATH" in captured.err

    def test_invalid_path_logs_error(self):
        """Test that invalid path logs error and exits"""
        with patch.object(sys, "argv", ["malwi", "/non/existent/path"]):
            # The function logs error and returns without exception
            result = main()
            assert result is None

    @patch("cli.entry.Path")
    @patch("cli.entry.MalwiObject")
    @patch("cli.entry.process_files")
    def test_basic_cli_flow(
        self, mock_process_files, mock_malwi_object, mock_path, tmp_path
    ):
        """Test basic CLI flow with all necessary mocks"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Mock Path to return our test file
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Mock the report
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Demo output"
        mock_process_files.return_value = mock_report

        with patch.object(sys, "argv", ["malwi", str(test_file)]):
            with patch("cli.entry.result") as mock_result:
                main()
                mock_result.assert_called_with("Demo output", force=True)

    @patch("cli.entry.MalwiObject")
    @patch("cli.entry.process_files")
    def test_save_to_file(self, mock_process_files, mock_malwi_object, tmp_path):
        """Test saving output to file"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        output_file = tmp_path / "output.txt"

        # Mock report
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Saved content"
        mock_process_files.return_value = mock_report

        # Mock the path existence check for input file
        with patch("cli.entry.Path") as mock_path:

            def path_side_effect(path_str):
                if str(path_str) == str(test_file):
                    mock_input_path = MagicMock()
                    mock_input_path.exists.return_value = True
                    return mock_input_path
                else:
                    # For save path, return real Path so file actually gets created
                    return Path(path_str)

            mock_path.side_effect = path_side_effect

            with patch.object(
                sys,
                "argv",
                ["malwi", str(test_file), "--save", str(output_file), "--quiet"],
            ):
                main()

        assert output_file.exists()
        assert output_file.read_text() == "Saved content"

    @patch("cli.entry.Path")
    @patch("cli.entry.MalwiObject")
    @patch("cli.entry.process_files")
    def test_output_formats(
        self, mock_process_files, mock_malwi_object, mock_path, tmp_path
    ):
        """Test different output format options"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Mock Path
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Mock report with all format methods
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = "Demo"
        mock_report.to_report_markdown.return_value = "Markdown"
        mock_report.to_report_json.return_value = "JSON"
        mock_report.to_report_yaml.return_value = "YAML"
        mock_process_files.return_value = mock_report

        # Test each format
        for fmt, expected_output in [
            ("demo", "Demo"),
            ("markdown", "Markdown"),
            ("json", "JSON"),
            ("yaml", "YAML"),
        ]:
            with patch.object(
                sys, "argv", ["malwi", str(test_file), "--format", fmt, "--quiet"]
            ):
                with patch("cli.entry.result") as mock_result:
                    main()
                    mock_result.assert_called_with(expected_output, force=True)

    @patch("cli.entry.Path")
    @patch("cli.entry.MalwiObject")
    def test_model_loading_error_continues(
        self, mock_malwi_object, mock_path, tmp_path
    ):
        """Test that model loading errors are handled gracefully"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Mock Path
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        # Make model loading fail
        mock_malwi_object.load_models_into_memory.side_effect = Exception("Model error")

        with patch.object(sys, "argv", ["malwi", str(test_file)]):
            with patch("cli.entry.process_files") as mock_process:
                mock_report = MagicMock()
                mock_report.to_demo_text.return_value = "Output"
                mock_process.return_value = mock_report

                with patch("cli.entry.result"):
                    # Should not crash
                    main()

    @patch("cli.entry.Path")
    @patch("cli.entry.MalwiObject")
    @patch("cli.entry.process_files")
    def test_cli_parameters_passed_correctly(
        self, mock_process_files, mock_malwi_object, mock_path, tmp_path
    ):
        """Test that CLI parameters are passed correctly to process_files"""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")

        # Mock Path
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = test_file
        mock_path.side_effect = lambda x: (
            test_file if str(x) == str(test_file) else mock_path_instance
        )

        # Mock report
        mock_report = MagicMock()
        mock_report.to_demo_text.return_value = ""
        mock_process_files.return_value = mock_report

        # Test with various parameters
        with patch.object(
            sys,
            "argv",
            [
                "malwi",
                str(test_file),
                "--threshold",
                "0.9",
                "--extensions",
                "py",
                "pyw",
                "--quiet",
            ],
        ):
            with patch("cli.entry.result"):
                main()

        # Verify process_files was called with correct arguments
        mock_process_files.assert_called_once()
        call_args = mock_process_files.call_args[1]
        assert call_args["malicious_threshold"] == 0.9
        assert call_args["accepted_extensions"] == ["py", "pyw"]
        assert call_args["silent"]
