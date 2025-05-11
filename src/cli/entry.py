import logging
import argparse
from typing import List
from pathlib import Path

from research.normalize_data import MalwiNode, create_malwi_nodes_from_file
from cli.predict import initialize_hf_model_components, get_node_text_prediction

logging.basicConfig(format="%(message)s", level=logging.INFO)


def process_source_path(
    input_path: str,
) -> List[MalwiNode]:
    path_obj = Path(input_path)
    all_nodes: List[MalwiNode] = []

    if path_obj.is_file():
        nodes = create_malwi_nodes_from_file(file_path=str(path_obj))
        if nodes:
            all_nodes.extend(nodes)
        elif not any(
            Path(input_path).suffix.lstrip(".") in ext
            for ext in ["js", "ts", "rs", "py"]
        ):
            logging.info(f"File '{input_path}' is not a supported file type.")
        else:
            logging.info(
                f"No processable AST nodes found in '{input_path}' or relevant targets missing/empty in NODE_TARGETS for its language."
            )

    elif path_obj.is_dir():
        logging.info(f"Processing directory: {input_path}")
        processed_files_in_dir = False
        for file_path in path_obj.rglob("*"):
            if file_path.is_file():
                nodes = create_malwi_nodes_from_file(file_path=str(file_path))
                if nodes:
                    all_nodes.extend(nodes)
                    processed_files_in_dir = True
        if not processed_files_in_dir:
            logging.info(f"No processable files found in directory '{input_path}'.")
    else:
        logging.error(f"Path '{input_path}' is neither a file nor a directory.")
    return all_nodes


def main():
    parser = argparse.ArgumentParser(description="malwi - AI Python Malware Scanner")
    parser.add_argument(
        "path", metavar="PATH", help="Specify the package file or folder path."
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "table"],
        default="table",
        help="Specify the output format: 'json' or 'table'.",
    )
    parser.add_argument(
        "--save",
        "-s",
        metavar="FILE",
        help="Specify a file path to save the output.",
        default=None,
    )
    parser.add_argument(
        "--maliciousness_threshold",
        "-mt",
        metavar="FLOAT",
        type=float,
        default=0.5,
        help="Specify the threshold for classifying nodes as malicious (default: 0.5).",
    )
    parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        help="Print the model input before prediction.",
    )
    parser.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Specify the custom tokenizer path (directory or file).",
        default=None,
    )
    parser.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="Specify the custom model path (directory or file).",
        default=None,
    )

    args = parser.parse_args()

    if not logging.getLogger().hasHandlers():
        logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

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

    initialize_hf_model_components(
        model_path=args.model_path, tokenizer_path=args.tokenizer_path
    )

    all_collected_nodes = process_source_path(
        input_path=args.path,
    )

    if not all_collected_nodes:
        logging.info(
            f"No processable AST nodes found for the given path: '{args.path}'."
        )
        return

    malicious_nodes = []
    benign_nodes = []

    for n in all_collected_nodes:
        node_ast_one_line = n.to_string()

        if args.debug:
            print(f"\nInput:\n{n.file_path}\n\n{node_ast_one_line}\n\n")

        prediction_data = get_node_text_prediction(node_ast_one_line)

        if prediction_data["status"] == "success":
            probabilities = prediction_data["probabilities"]
            maliciousness = probabilities[1]
            n.maliciousness = maliciousness
            if maliciousness > args.maliciousness_threshold:
                malicious_nodes.append(n)
            else:
                benign_nodes.append(n)
        else:
            logging.error(
                f"Prediction error for node in {n.file_path}: {prediction_data['message']}"
            )

    output = ""
    if args.format == "json":
        output = MalwiNode.nodes_to_json(
            malicious_nodes=malicious_nodes, benign_nodes=benign_nodes
        )
    else:
        if len(malicious_nodes) == 0:
            output = "🟢 No malicious findings"
        else:
            output = "\n".join(
                f"{m.file_path}: 🛑 malicious {m.maliciousness:.2f}"
                for m in malicious_nodes
            )

    if args.save:
        Path(args.save).write_text(output)
        logging.info(f"Output saved to {args.save}")
    else:
        print(output)

    exit(1 if malicious_nodes else 0)


if __name__ == "__main__":
    main()
