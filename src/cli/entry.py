import logging
import argparse
from typing import List
from pathlib import Path

from research.disassemble_python import process_single_py_file, MalwiFile

logging.basicConfig(format="%(message)s", level=logging.INFO)


def process_source_path(
    input_path: str,
) -> List[MalwiFile]:
    path_obj = Path(input_path)
    all_files: List[MalwiFile] = []

    if path_obj.is_file():
        file = process_single_py_file(path_obj)
        if file:
            all_files.extend(file)
        elif not any(Path(input_path).suffix.lstrip(".") in ext for ext in ["py"]):
            logging.info(f"File '{input_path}' is not a supported file type.")
        else:
            logging.info(
                f"No processable AST nodes found in '{input_path}' or relevant targets missing/empty in NODE_TARGETS for its language."
            )

    elif path_obj.is_dir():
        logging.info(f"Processing directory: {input_path}")
        processed_files_in_dir = False
        for file_path in path_obj.rglob("*"):  # Using rglob for recursive traversal
            if file_path.is_file():
                file = process_single_py_file(Path(file_path))
                if file:
                    all_files.extend(file)
                    processed_files_in_dir = True
        if not processed_files_in_dir:
            logging.info(f"No processable files found in directory '{input_path}'.")
    else:
        logging.error(f"Path '{input_path}' is neither a file nor a directory.")
    return all_files


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

    MalwiFile.load_models_into_memory(
        model_path=args.model_path, tokenizer_path=args.tokenizer_path
    )

    objects = process_source_path(args.path)

    if objects:
        for o in objects:
            prediction = o.predict()
            print(o.to_yaml())

    output = ""

    if args.format == "json":
        pass
    elif args.format == "yaml":
        pass
    elif args.format == "csv":
        pass
    else:
        pass
    if args.save:
        Path(args.save).write_text(output)
        if not args.quiet:
            logging.info(f"Output saved to {args.save}")
    else:
        print(output)


if __name__ == "__main__":
    main()
