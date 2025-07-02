import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call
import os
import argparse

# Add src to path to import from source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cli.entry import main, process_batch_mode, run_batch_scan


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


class TestBatchMode:
    """Tests for batch processing functionality"""

    def test_batch_and_save_mutually_exclusive(self, capsys):
        """Test that --batch and --save flags are mutually exclusive"""
        with patch.object(sys, "argv", ["malwi", "/some/path", "--batch", "--save", "test.json"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2
        captured = capsys.readouterr()
        assert "not allowed with argument --batch" in captured.err

    def test_batch_mode_requires_directory(self, tmp_path):
        """Test that batch mode requires a directory path"""
        # Create a file instead of directory
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        
        # Create mock args
        args = MagicMock()
        args.format = "json"
        args.threshold = 0.7
        args.extensions = ["py"]
        args.quiet = True
        args.no_snippets = True
        args.no_sources = True
        args.model_path = None
        args.tokenizer_path = None
        args.svm_path = None
        args.triage = False
        args.triage_ollama = False
        
        with patch("cli.entry.path_error") as mock_path_error:
            process_batch_mode(test_file, args)
            mock_path_error.assert_called_once_with("Batch mode requires a directory path")

    def test_batch_mode_no_child_directories(self, tmp_path):
        """Test batch mode when no child directories exist"""
        # Create a directory with only files, no subdirectories
        (tmp_path / "file1.py").write_text("print('hello')")
        (tmp_path / "file2.py").write_text("print('world')")
        
        args = MagicMock()
        
        with patch("cli.entry.info") as mock_info:
            process_batch_mode(tmp_path, args)
            mock_info.assert_called_with("No child directories found for batch processing")

    @patch("cli.entry.MalwiObject")
    @patch("cli.entry.tqdm")
    @patch("cli.entry.ThreadPoolExecutor")
    @patch("cli.entry.run_batch_scan")
    def test_process_batch_mode_success(self, mock_run_batch_scan, mock_executor, mock_tqdm, mock_malwi_object, tmp_path):
        """Test successful batch processing"""
        # Create test directory structure
        (tmp_path / "folder1").mkdir()
        (tmp_path / "folder2").mkdir()
        (tmp_path / "folder3").mkdir()
        
        # Create args mock
        args = MagicMock()
        args.format = "json"
        args.quiet = False
        
        # Mock tqdm progress bar
        mock_pbar = MagicMock()
        mock_tqdm.return_value.__enter__.return_value = mock_pbar
        
        # Mock executor and futures
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance
        
        # Mock futures and results
        mock_future1 = MagicMock()
        mock_future2 = MagicMock()
        mock_future3 = MagicMock()
        
        mock_future1.result.return_value = {
            "folder": "folder1",
            "success": True,
            "skipped": False
        }
        mock_future2.result.return_value = {
            "folder": "folder2", 
            "success": True,
            "skipped": False
        }
        mock_future3.result.return_value = {
            "folder": "folder3",
            "success": False,
            "error": "error message",
            "skipped": False
        }
        
        # Map futures to folders
        future_to_folder = {
            mock_future1: tmp_path / "folder1",
            mock_future2: tmp_path / "folder2", 
            mock_future3: tmp_path / "folder3"
        }
        
        mock_executor_instance.submit.side_effect = [mock_future1, mock_future2, mock_future3]
        
        with patch("cli.entry.as_completed") as mock_as_completed:
            mock_as_completed.return_value = [mock_future1, mock_future2, mock_future3]
            
            with patch("cli.entry.info") as mock_info:
                
                process_batch_mode(tmp_path, args)
                
                # Verify model loading was called
                mock_malwi_object.load_models_into_memory.assert_called_once()
                
                # Verify info calls
                mock_info.assert_any_call("🚀 Starting batch scan of 3 folders")
                mock_info.assert_any_call("🎯 Batch scan complete: 2 successful, 1 failed, 0 skipped")
                
                # Verify tqdm progress bar was used (includes disable parameter)
                mock_tqdm.assert_called_once_with(total=3, desc="📈 Scanning folders", unit="folder", disable=False)
                
                # Verify progress bar updates
                assert mock_pbar.update.call_count == 3
                mock_pbar.set_postfix_str.assert_any_call("✅ folder1")
                mock_pbar.set_postfix_str.assert_any_call("✅ folder2")
                mock_pbar.set_postfix_str.assert_any_call("❌ folder3")

    def test_run_batch_scan_success(self, tmp_path):
        """Test successful single folder batch scan"""
        test_folder = tmp_path / "test_folder"
        test_folder.mkdir()
        
        # Create args mock
        args = MagicMock()
        args.format = "json"
        args.threshold = 0.7
        args.extensions = ["py"]
        args.quiet = True
        args.no_snippets = True
        args.no_sources = True
        args.model_path = None
        args.tokenizer_path = None
        args.svm_path = None
        args.triage = False
        args.triage_ollama = False
        
        # Mock the process_files function and report
        mock_report = MagicMock()
        mock_report.to_report_json.return_value = '{"test": "data"}'
        
        with patch("cli.entry.process_files", return_value=mock_report) as mock_process:
            with patch("cli.entry.Path.cwd", return_value=tmp_path):
                result = run_batch_scan(test_folder, args)
                
                # Verify process_files was called with correct arguments
                mock_process.assert_called_once_with(
                    input_path=test_folder,
                    accepted_extensions=["py"],
                    predict=True,
                    retrieve_source_code=True,
                    silent=True,
                    triaging_type=None,
                    malicious_threshold=0.7,
                )
                
                # Verify result
                assert result["folder"] == "test_folder"
                assert result["success"] is True
                assert result["skipped"] is False
                
                # Verify file was created
                output_file = tmp_path / "malwi_test_folder.json"
                assert output_file.exists()
                assert output_file.read_text() == '{"test": "data"}'

    def test_run_batch_scan_exception(self, tmp_path):
        """Test batch scan with general exception"""
        test_folder = tmp_path / "test_folder"
        test_folder.mkdir()
        
        args = MagicMock()
        args.format = "json"
        args.threshold = 0.7
        args.extensions = ["py"]
        args.quiet = True
        args.no_snippets = True
        args.no_sources = True
        args.model_path = None
        args.tokenizer_path = None
        args.svm_path = None
        args.triage = False
        args.triage_ollama = False
        
        # Mock process_files to raise exception
        with patch("cli.entry.process_files", side_effect=Exception("Test error")):
            with patch("cli.entry.Path.cwd", return_value=tmp_path):
                result = run_batch_scan(test_folder, args)
                
                assert result["folder"] == "test_folder"
                assert result["success"] is False
                assert result["error"] == "Test error"
                assert result["skipped"] is False

    def test_batch_file_extensions(self, tmp_path):
        """Test that batch mode creates files with correct extensions"""
        test_folder = tmp_path / "test_folder"
        test_folder.mkdir()
        
        format_extensions = [
            ("json", ".json", "to_report_json"),
            ("yaml", ".yaml", "to_report_yaml"),
            ("markdown", ".md", "to_report_markdown"),
            ("demo", ".txt", "to_demo_text")
        ]
        
        for fmt, expected_ext, method_name in format_extensions:
            args = MagicMock()
            args.format = fmt
            args.threshold = 0.7
            args.extensions = ["py"]
            args.quiet = True
            args.no_snippets = True
            args.no_sources = True
            args.model_path = None
            args.tokenizer_path = None
            args.svm_path = None
            args.triage = False
            args.triage_ollama = False
            
            # Mock report with the appropriate method
            mock_report = MagicMock()
            getattr(mock_report, method_name).return_value = "test output"
            
            with patch("cli.entry.process_files", return_value=mock_report):
                with patch("cli.entry.Path.cwd", return_value=tmp_path):
                    run_batch_scan(test_folder, args)
                    
                    # Check that the file was created with correct extension
                    expected_file = tmp_path / f"malwi_test_folder{expected_ext}"
                    assert expected_file.exists()
                    assert expected_file.read_text() == "test output"
                    
                    # Clean up for next iteration
                    expected_file.unlink()

    @patch("cli.entry.Path")
    def test_batch_mode_integration_with_main(self, mock_path, tmp_path):
        """Test batch mode integration with main function"""
        # Create test directory structure
        test_dir = tmp_path / "batch_test"
        test_dir.mkdir()
        (test_dir / "folder1").mkdir()
        (test_dir / "folder2").mkdir()
        
        # Mock Path to return our test directory
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = True
        mock_path_instance.is_dir.return_value = True
        mock_path_instance.iterdir.return_value = [test_dir / "folder1", test_dir / "folder2"]
        mock_path.return_value = mock_path_instance
        
        with patch.object(sys, "argv", ["malwi", str(test_dir), "--batch", "--quiet"]):
            with patch("cli.entry.process_batch_mode") as mock_batch_mode:
                main()
                mock_batch_mode.assert_called_once()
                
                # Verify that process_batch_mode was called with correct args
                call_args = mock_batch_mode.call_args
                assert call_args[0][0] == mock_path_instance  # input_path
                batch_args = call_args[0][1]  # args
                assert batch_args.batch is True
                assert batch_args.quiet is True

    def test_batch_mode_loads_models_in_batch_function(self, tmp_path):
        """Test that batch mode loads models within the batch processing function"""
        test_dir = tmp_path / "batch_test"
        test_dir.mkdir()
        
        with patch("cli.entry.Path") as mock_path:
            mock_path_instance = MagicMock()
            mock_path_instance.exists.return_value = True
            mock_path.return_value = mock_path_instance
            
            with patch.object(sys, "argv", ["malwi", str(test_dir), "--batch"]):
                with patch("cli.entry.MalwiObject") as mock_malwi_object:
                    with patch("cli.entry.process_batch_mode") as mock_batch_mode:
                        main()
                        
                        # Verify that model loading was NOT called in main (skipped for batch mode)
                        mock_malwi_object.load_models_into_memory.assert_not_called()
                        
                        # Verify that batch mode was called
                        mock_batch_mode.assert_called_once()

    def test_skip_existing_files(self, tmp_path):
        """Test that existing malwi files are skipped"""
        test_folder = tmp_path / "test_folder"
        test_folder.mkdir()
        
        # Create existing output file
        existing_file = tmp_path / "malwi_test_folder.json"
        existing_file.write_text('{"existing": "data"}')
        
        args = MagicMock()
        args.format = "json"
        args.threshold = 0.7
        args.extensions = ["py"]
        args.quiet = True
        args.no_snippets = True
        args.no_sources = True
        args.model_path = None
        args.tokenizer_path = None
        args.svm_path = None
        args.triage = False
        args.triage_ollama = False
        
        with patch("cli.entry.Path.cwd", return_value=tmp_path):
            result = run_batch_scan(test_folder, args)
            
            # Verify the folder was skipped
            assert result["folder"] == "test_folder"
            assert result["success"] is True
            assert result["skipped"] is True

    @patch("cli.entry.tqdm")
    @patch("cli.entry.ThreadPoolExecutor")
    def test_mixed_skip_and_process(self, mock_executor, mock_tqdm, tmp_path):
        """Test batch mode with mixed skipped and processed folders"""
        # Create test directory structure
        (tmp_path / "folder1").mkdir()  # Will be skipped
        (tmp_path / "folder2").mkdir()  # Will be processed
        
        # Create existing file for folder1
        (tmp_path / "malwi_folder1.json").write_text('{"existing": "data"}')
        
        args = MagicMock()
        args.format = "json"
        args.quiet = False
        
        # Mock tqdm progress bar
        mock_pbar = MagicMock()
        mock_tqdm.return_value.__enter__.return_value = mock_pbar
        
        # Mock executor
        mock_executor_instance = MagicMock()
        mock_executor.return_value.__enter__.return_value = mock_executor_instance
        
        # Mock futures and results
        mock_future1 = MagicMock()
        mock_future2 = MagicMock()
        
        mock_future1.result.return_value = {
            "folder": "folder1",
            "success": True,
            "skipped": True
        }
        mock_future2.result.return_value = {
            "folder": "folder2",
            "success": True,
            "skipped": False
        }
        
        mock_executor_instance.submit.side_effect = [mock_future1, mock_future2]
        
        with patch("cli.entry.as_completed") as mock_as_completed:
            mock_as_completed.return_value = [mock_future1, mock_future2]
            
            with patch("cli.entry.info") as mock_info:
                process_batch_mode(tmp_path, args)
                
                # Verify summary includes skip count
                mock_info.assert_any_call("🎯 Batch scan complete: 1 successful, 0 failed, 1 skipped")
                
                # Verify progress bar postfix shows skip and success
                mock_pbar.set_postfix_str.assert_any_call("⏭️ folder1")
                mock_pbar.set_postfix_str.assert_any_call("✅ folder2")
