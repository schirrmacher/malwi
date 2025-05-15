import pytest
from pathlib import Path
import subprocess
import json
import yaml
import logging  # Added for caplog.set_level
from unittest.mock import patch, MagicMock

# Adjust this import based on your project structure
# If entry.py is in src/cli/entry.py and src is in PYTHONPATH:
from cli.entry import file_to_nodes, file_or_dir_to_nodes, main, MalwiNode

# If entry.py is at the root, it would be:
# from entry import file_to_nodes, file_or_dir_to_nodes, main, MalwiNode


@pytest.fixture
def mock_malwi_node_class():
    class MockMalwiNode:
        def __init__(
            self,
            file_path,
            name,
            maliciousness,
            node_type="function",
            tokens="MOCK_TOKENS",
            code="mock code",
            line_number=1,
            node_hash="mockhash",
        ):
            self.file_path = str(file_path)
            self.name = name
            self.maliciousness = maliciousness
            self.node_type = node_type
            self.tokens = tokens
            self.code = code
            self.line_number = line_number
            self.hash = node_hash

        def to_string(self):
            return f"AST_NODE:{self.name}"

        @staticmethod
        def _format_node_content(node):
            return {
                "type": node.node_type,
                "name": node.name,
                "score": float(node.maliciousness),
                "tokens": node.tokens,
                "code": node.code,
                "hash": node.hash,
            }

        @staticmethod
        def _get_counts_and_percentage(malicious_nodes, benign_nodes_for_count):
            all_nodes_for_count = malicious_nodes + benign_nodes_for_count
            files_count = len(set(n.file_path for n in all_nodes_for_count))
            entities_count = len(all_nodes_for_count)
            malicious_percentage = (
                (len(malicious_nodes) / entities_count) if entities_count > 0 else 0
            )
            return files_count, entities_count, malicious_percentage

        @staticmethod
        def nodes_to_json(malicious_nodes, benign_nodes):
            files_count, entities_count, malicious_percentage = (
                MockMalwiNode._get_counts_and_percentage(malicious_nodes, benign_nodes)
            )
            mal_content_by_file = {}
            for node in malicious_nodes:
                mal_content_by_file.setdefault(node.file_path, []).append(
                    MockMalwiNode._format_node_content(node)
                )
            ben_content_by_file = {}
            for node in benign_nodes:
                ben_content_by_file.setdefault(node.file_path, []).append(
                    MockMalwiNode._format_node_content(node)
                )
            output_dict = {
                "format": 1,
                "files_count": files_count,
                "entities_count": entities_count,
                "malicious_percentage": malicious_percentage,
                "malicious": [
                    {"path": fp, "contents": cont}
                    for fp, cont in mal_content_by_file.items()
                ],
                "benign": [
                    {"path": fp, "contents": cont}
                    for fp, cont in ben_content_by_file.items()
                ],
            }
            return json.dumps(output_dict, indent=4)

        @staticmethod
        def nodes_to_yaml(malicious_nodes, benign_nodes):
            files_count, entities_count, malicious_percentage = (
                MockMalwiNode._get_counts_and_percentage(malicious_nodes, benign_nodes)
            )
            mal_content_by_file = {}
            for node in malicious_nodes:
                mal_content_by_file.setdefault(node.file_path, []).append(
                    MockMalwiNode._format_node_content(node)
                )
            ben_content_by_file = {}
            for node in benign_nodes:
                ben_content_by_file.setdefault(node.file_path, []).append(
                    MockMalwiNode._format_node_content(node)
                )
            output_dict = {
                "format": 1,
                "files_count": files_count,
                "entities_count": entities_count,
                "malicious_percentage": malicious_percentage,
                "malicious": [
                    {"path": fp, "contents": cont}
                    for fp, cont in mal_content_by_file.items()
                ],
                "benign": [
                    {"path": fp, "contents": cont}
                    for fp, cont in ben_content_by_file.items()
                ],
            }
            return yaml.dump(output_dict, sort_keys=False, allow_unicode=True)

        @staticmethod
        def nodes_to_csv(malicious_nodes, benign_nodes):
            header = "file_path,node_type,name,score,tokens,code,hash,status\n"
            csv_string = header
            for node in malicious_nodes:
                csv_string += f'"{node.file_path}","{node.node_type}","{node.name}",{node.maliciousness:.6f},"{node.tokens}","{node.code.replace('"', '""').replace("\n", "\\n")}","{node.hash}",malicious\n'
            for node in benign_nodes:
                csv_string += f'"{node.file_path}","{node.node_type}","{node.name}",{node.maliciousness:.6f},"{node.tokens}","{node.code.replace('"', '""').replace("\n", "\\n")}","{node.hash}",benign\n'
            return csv_string

    return MockMalwiNode


@pytest.fixture
def temp_file(tmp_path):
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "hello.py"
    p.write_text(
        "print('hello world')\ndef secret_func():\n    import os\n    os.system('clear')"
    )
    return p


@pytest.fixture
def temp_dir(tmp_path):
    d = tmp_path / "test_dir"
    d.mkdir()
    f1 = d / "file1.py"
    f1.write_text("import os\nprint(os.name)")
    f2 = d / "file2.py"
    f2.write_text("def func():\n    pass\n# benign code")
    f3 = d / "notes.txt"
    f3.write_text("some notes")  # This file will also be processed by rglob("*")
    return d


PATCH_PREFIX = "cli.entry."


@patch(f"{PATCH_PREFIX}create_malwi_nodes_from_file")
@patch(f"{PATCH_PREFIX}get_node_text_prediction")
def test_file_to_nodes_malicious(
    mock_get_prediction, mock_create_nodes, mock_malwi_node_class, temp_file
):
    mock_node_instance = mock_malwi_node_class(
        temp_file, "secret_func", 0.0, code="import os; os.system('clear')"
    )
    mock_create_nodes.return_value = [mock_node_instance]
    mock_get_prediction.return_value = {
        "status": "success",
        "probabilities": [0.1, 0.9],
    }
    malicious_nodes, benign_nodes = file_to_nodes(temp_file, threshold=0.5)
    assert len(malicious_nodes) == 1
    assert len(benign_nodes) == 0


@patch(f"{PATCH_PREFIX}file_to_nodes")
def test_file_or_dir_to_nodes_with_file(
    mock_internal_file_to_nodes, temp_file, mock_malwi_node_class
):
    mock_mal_node = mock_malwi_node_class(str(temp_file), "mal_node", 0.8)
    mock_ben_node = mock_malwi_node_class(str(temp_file), "ben_node", 0.1)
    mock_internal_file_to_nodes.return_value = ([mock_mal_node], [mock_ben_node])
    malicious_nodes, benign_nodes = file_or_dir_to_nodes(temp_file, threshold=0.5)
    assert len(malicious_nodes) == 1, (
        "Malicious nodes list incorrect. Check entry.py fix for file_or_dir_to_nodes (extend)."
    )
    assert len(benign_nodes) == 1, (
        "Benign nodes list incorrect. Check entry.py fix for file_or_dir_to_nodes (extend)."
    )
    mock_internal_file_to_nodes.assert_called_once_with(path=temp_file, threshold=0.5)


@patch(f"{PATCH_PREFIX}file_to_nodes")
def test_file_or_dir_to_nodes_with_dir(
    mock_internal_file_to_nodes, temp_dir, mock_malwi_node_class
):
    file1_path = temp_dir / "file1.py"
    file2_path = temp_dir / "file2.py"
    notes_path = temp_dir / "notes.txt"  # This file will also be found by rglob("*")

    mock_mal_node1 = mock_malwi_node_class(file1_path, "mal_node1", 0.9)
    mock_ben_node1 = mock_malwi_node_class(file1_path, "ben_node1", 0.2)
    mock_mal_node2 = mock_malwi_node_class(file2_path, "mal_node2", 0.7)
    mock_ben_node2 = mock_malwi_node_class(file2_path, "ben_node2", 0.3)

    def side_effect_func(path, threshold):
        if path == file1_path:
            return ([mock_mal_node1], [mock_ben_node1])
        elif path == file2_path:
            return ([mock_mal_node2], [mock_ben_node2])
        elif path == notes_path:
            return ([], [])  # For notes.txt
        return ([], [])

    mock_internal_file_to_nodes.side_effect = side_effect_func

    malicious_nodes, benign_nodes = file_or_dir_to_nodes(temp_dir, threshold=0.5)
    assert len(malicious_nodes) == 2
    assert len(benign_nodes) == 2
    mock_internal_file_to_nodes.assert_any_call(path=file1_path, threshold=0.5)
    mock_internal_file_to_nodes.assert_any_call(path=file2_path, threshold=0.5)
    mock_internal_file_to_nodes.assert_any_call(
        path=notes_path, threshold=0.5
    )  # Called for notes.txt too
    # FIX: Reflect that entry.py's rglob("*") calls file_to_nodes for all files
    assert mock_internal_file_to_nodes.call_count == 3
    # For more robust code, entry.py's file_or_dir_to_nodes could filter for *.py files:
    # e.g., by using path.rglob("*.py") or checking file_path.suffix == ".py".
    # If entry.py is changed to filter, this test's call_count expectation should be 2.


@patch(f"{PATCH_PREFIX}argparse.ArgumentParser")
@patch(f"{PATCH_PREFIX}initialize_models")
@patch(f"{PATCH_PREFIX}file_or_dir_to_nodes")
@patch(f"{PATCH_PREFIX}MalwiNode")
@patch(f"{PATCH_PREFIX}tabulate")
@patch("builtins.print")
def test_main_table_output(
    mock_print,
    mock_tabulate,
    MockedMalwiNodeInEntry,
    mock_file_or_dir,
    mock_init_models,
    mock_argparse,
    temp_file,
    mock_malwi_node_class,
):
    mock_parser_instance = mock_argparse.return_value
    mock_args = MagicMock()
    mock_args.path = str(temp_file)
    mock_args.format = "table"
    mock_args.save = None
    mock_args.quiet = False
    mock_args.malicious_only = False
    mock_args.threshold = 0.6
    mock_args.tokenizer_path = None
    mock_args.model_path = None
    mock_parser_instance.parse_args.return_value = mock_args

    mal_node1 = mock_malwi_node_class(temp_file, "run", 1.0)
    mock_file_or_dir.return_value = ([mal_node1], [])
    mock_tabulate.return_value = "mocked table output"

    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 1
    expected_table_data = [{"File": str(temp_file), "Name": "run", "Malicious": "1.00"}]
    mock_tabulate.assert_called_once_with(
        expected_table_data, headers="keys", tablefmt="github"
    )


@patch(f"{PATCH_PREFIX}argparse.ArgumentParser")
@patch(f"{PATCH_PREFIX}initialize_models")
@patch(f"{PATCH_PREFIX}file_or_dir_to_nodes")
@patch(f"{PATCH_PREFIX}MalwiNode")
@patch("builtins.print")
def test_main_json_output(
    mock_print,
    MockedMalwiNodeInEntry,
    mock_file_or_dir,
    mock_init_models,
    mock_argparse,
    temp_file,
    mock_malwi_node_class,
):
    mock_parser_instance = mock_argparse.return_value
    mock_args = MagicMock()
    mock_args.path = str(temp_file)
    mock_args.format = "json"
    mock_args.save = None
    mock_args.quiet = True
    mock_args.malicious_only = False
    mock_args.threshold = 0.5
    mock_args.tokenizer_path = "tok_path"
    mock_args.model_path = "mod_path"
    mock_parser_instance.parse_args.return_value = mock_args

    mal_node = mock_malwi_node_class(temp_file, "run", 0.99)
    ben_node = mock_malwi_node_class(temp_file, "benign_func", 0.01)
    mock_file_or_dir.return_value = ([mal_node], [ben_node])

    expected_json_str = mock_malwi_node_class.nodes_to_json([mal_node], [ben_node])
    MockedMalwiNodeInEntry.nodes_to_json.return_value = expected_json_str

    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 1
    MockedMalwiNodeInEntry.nodes_to_json.assert_called_once_with(
        malicious_nodes=[mal_node], benign_nodes=[ben_node]
    )
    mock_print.assert_called_once_with(expected_json_str)


@patch(f"{PATCH_PREFIX}argparse.ArgumentParser")
@patch(f"{PATCH_PREFIX}initialize_models")
@patch(f"{PATCH_PREFIX}file_or_dir_to_nodes")
@patch(f"{PATCH_PREFIX}MalwiNode")
@patch("builtins.print")
def test_main_malicious_only_has_no_effect_on_json_call(
    mock_print,
    MockedMalwiNodeInEntry,
    mock_file_or_dir,
    mock_init_models,
    mock_argparse,
    temp_file,
    mock_malwi_node_class,
):
    mock_parser_instance = mock_argparse.return_value
    mock_args = MagicMock()
    mock_args.path = str(temp_file)
    mock_args.format = "json"
    mock_args.save = None
    mock_args.quiet = True
    mock_args.malicious_only = True
    mock_args.threshold = 0.5
    mock_parser_instance.parse_args.return_value = mock_args

    mal_node = mock_malwi_node_class(str(temp_file), "mal_func", 0.9)
    ben_node = mock_malwi_node_class(str(temp_file) + "_b", "ben_func", 0.1)
    mock_file_or_dir.return_value = ([mal_node], [ben_node])

    expected_json_output = mock_malwi_node_class.nodes_to_json([mal_node], [ben_node])
    MockedMalwiNodeInEntry.nodes_to_json.return_value = expected_json_output

    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 1
    MockedMalwiNodeInEntry.nodes_to_json.assert_called_once_with(
        malicious_nodes=[mal_node], benign_nodes=[ben_node]
    )
    printed_output_dict = json.loads(mock_print.call_args[0][0])
    assert "benign" in printed_output_dict and len(printed_output_dict["benign"]) > 0


@patch(f"{PATCH_PREFIX}argparse.ArgumentParser")
@patch(f"{PATCH_PREFIX}initialize_models")
@patch(f"{PATCH_PREFIX}file_or_dir_to_nodes")
@patch(f"{PATCH_PREFIX}MalwiNode")
@patch(f"{PATCH_PREFIX}Path")
def test_main_save_output(
    MockPathClassConstructor,
    MockedMalwiNodeInEntry,
    mock_file_or_dir,
    mock_init_models,
    mock_argparse,
    temp_file,
    mock_malwi_node_class,
    caplog,
):
    # FIX: Set caplog level
    caplog.set_level(logging.INFO)

    mock_parser_instance = mock_argparse.return_value
    save_path_str = "output.json"
    mock_args = MagicMock()
    mock_args.path = str(temp_file)
    mock_args.format = "json"
    mock_args.save = save_path_str
    mock_args.quiet = False
    mock_args.malicious_only = False
    mock_args.threshold = 0.5
    mock_parser_instance.parse_args.return_value = mock_args

    mal_node = mock_malwi_node_class(str(temp_file), "mal_func", 0.9)
    mock_file_or_dir.return_value = ([mal_node], [])
    expected_json_content = mock_malwi_node_class.nodes_to_json([mal_node], [])
    MockedMalwiNodeInEntry.nodes_to_json.return_value = expected_json_content
    mock_save_path_instance = MagicMock(spec=Path)

    def path_side_effect(p_arg):
        if p_arg == save_path_str:
            return mock_save_path_instance
        return MagicMock(spec=Path)

    MockPathClassConstructor.side_effect = path_side_effect

    with pytest.raises(SystemExit) as e:
        main()
    assert e.value.code == 1
    MockPathClassConstructor.assert_any_call(save_path_str)
    mock_save_path_instance.write_text.assert_called_once_with(expected_json_content)
    assert f"Output saved to {save_path_str}" in caplog.text, (
        "Log message for saving output not found."
    )


@patch(f"{PATCH_PREFIX}argparse.ArgumentParser")
def test_main_no_path(mock_argparse):
    mock_parser_instance = mock_argparse.return_value
    mock_args = MagicMock()
    mock_args.path = None
    mock_parser_instance.parse_args.return_value = mock_args
    mock_parser_instance.print_help = MagicMock()
    main()
    mock_parser_instance.print_help.assert_called_once()


def test_cli_invocation_help():  # Removed tmp_path as it's not used here
    project_root = Path(__file__).resolve().parent.parent
    script_path_options = [
        project_root / "src" / "cli" / "entry.py",
        project_root / "cli" / "entry.py",
        project_root / "entry.py",
    ]
    script_path = next((p for p in script_path_options if p.exists()), None)
    if not script_path:
        pytest.skip(
            "entry.py not found for CLI test. Adjust path in test_cli_invocation_help."
        )

    result = subprocess.run(
        ["python", str(script_path), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "malwi - AI Python Malware Scanner" in result.stdout
