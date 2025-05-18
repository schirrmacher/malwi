import logging
import argparse
from tqdm import tqdm
from pathlib import Path
from tabulate import tabulate
from typing import List, Tuple

from research.normalize_data import MalwiNode, create_malwi_nodes_from_file
from cli.predict import initialize_models, get_node_text_prediction

logging.basicConfig(format="%(message)s", level=logging.INFO)


def file_to_nodes(
    path: Path, threshold: float
) -> Tuple[List[MalwiNode], List[MalwiNode]]:
    path_obj = Path(path)

    malicious_nodes = []
    benign_nodes = []

    nodes = create_malwi_nodes_from_file(file_path=str(path_obj))

    for n in nodes:
        node_ast_one_line = n.to_string()
        prediction_data = get_node_text_prediction(node_ast_one_line)

        if prediction_data["status"] == "success":
            probabilities = prediction_data["probabilities"]
            maliciousness = probabilities[1]
            n.maliciousness = maliciousness
            if maliciousness > threshold:
                malicious_nodes.append(n)
            else:
                benign_nodes.append(n)
        else:
            logging.error(
                f"Prediction error for node in {n.file_path}: {prediction_data['message']}"
            )

    return malicious_nodes, benign_nodes


def file_or_dir_to_nodes(
    path: Path,
    threshold: float,
) -> Tuple[List[MalwiNode], List[MalwiNode]]:
    all_malicious_nodes = []
    all_benign_nodes = []

    if path.is_file():
        logging.info(f"Processing file: {path}")
        malicious_nodes, benign_nodes = file_to_nodes(path=path, threshold=threshold)
        all_malicious_nodes.extend(malicious_nodes)
        all_benign_nodes.extend(benign_nodes)
    elif path.is_dir():
        logging.info(f"Processing directory: {path}")
        processed_files_in_dir = False
        for file_path in path.rglob("*"):
            if file_path.is_file():
                processed_files_in_dir = True
                malicious_nodes, benign_nodes = file_to_nodes(
                    path=file_path, threshold=threshold
                )
                all_malicious_nodes.extend(malicious_nodes)
                all_benign_nodes.extend(benign_nodes)
        if not processed_files_in_dir:
            logging.info(f"No processable files found in directory '{path}'")
    else:
        logging.error(f"Path '{path}' is neither a file nor a directory")

    return all_malicious_nodes, all_benign_nodes


def main():
    parser = argparse.ArgumentParser(description="malwi - AI Python Malware Scanner")
    parser.add_argument(
        "path", metavar="PATH", help="Specify the package file or folder path."
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "yaml", "table", "csv", "tokens"],
        default="table",
        help="Specify the output format.",
    )
    parser.add_argument(
        "--save",
        "-s",
        metavar="FILE",
        help="Specify a file path to save the output.",
        default=None,
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress logging output and progress bar.",
    )
    parser.add_argument(
        "--malicious-only",
        "-mo",
        action="store_true",
        help="Only include malicious findings in the output.",
    )
    parser.add_argument(
        "--threshold",
        "-mt",
        metavar="FLOAT",
        type=float,
        default=0.5,
        help="Specify the threshold for classifying nodes as malicious (default: 0.5).",
    )

    developer_group = parser.add_argument_group("Developer Options")

    developer_group.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Print the model input before prediction.",
    )
    developer_group.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Specify the custom tokenizer directory.",
        default=None,
    )
    developer_group.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="Specify the custom model path directory.",
        default=None,
    )

    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.CRITICAL + 1)
    else:
        logging.info(
            """
                  __          __
  .--------.---.-|  .--.--.--|__|
  |        |  _  |  |  |  |  |  |
  |__|__|__|___._|__|________|__|
     AI Python Malware Scanner\n\n"""
        )

    if not args.path:
        parser.print_help()
        return

    initialize_models(model_path=args.model_path, tokenizer_path=args.tokenizer_path)

    malicious_nodes, benign_nodes = file_or_dir_to_nodes(
        Path(args.path), threshold=args.threshold
    )

    output = ""

    if args.format == "json":
        output = MalwiNode.nodes_to_json(
            malicious_nodes=malicious_nodes,
            benign_nodes=benign_nodes,
            malicious_only=args.malicious_only,
        )
    elif args.format == "yaml":
        output = MalwiNode.nodes_to_yaml(
            malicious_nodes=malicious_nodes,
            benign_nodes=benign_nodes,
            malicious_only=args.malicious_only,
        )
    elif args.format == "csv":
        output = MalwiNode.nodes_to_csv(
            malicious_nodes=malicious_nodes,
            benign_nodes=benign_nodes,
            malicious_only=args.malicious_only,
        )
    else:
        if len(malicious_nodes) == 0:
            output = "🟢 No malicious findings"
        else:
            table_data = [
                {
                    "File": m.file_path,
                    "Name": m.name,
                    "Malicious": f"{m.maliciousness:.2f}",
                }
                for m in malicious_nodes
            ]
            output = tabulate(table_data, headers="keys", tablefmt="github")

    if args.save:
        Path(args.save).write_text(output)
        if not args.quiet:
            logging.info(f"Output saved to {args.save}")
    else:
        print(output)

    exit(1 if malicious_nodes else 0)


if __name__ == "__main__":
    main()
