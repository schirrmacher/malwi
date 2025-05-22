import logging
import argparse
from tqdm import tqdm
from pathlib import Path
from typing import List, Tuple, Optional

from research.disassemble_python import process_single_py_file, MalwiFile

logging.basicConfig(format="%(message)s", level=logging.INFO)


def process_source_path(
    input_path: str,
    accepted_extensions: Optional[List[str]] = None,
) -> Tuple[List[MalwiFile], List[str]]:
    if accepted_extensions is None:
        accepted_extensions = ["py"]
    normalized_accepted_extensions = [ext.lower() for ext in accepted_extensions]

    path_obj = Path(input_path)
    all_files: List[str] = []
    all_malwi_files: List[MalwiFile] = []
    skipped_file_paths: List[str] = []

    if not path_obj.exists():
        logging.error(f"Path '{input_path}' does not exist. Skipping.")
        return all_malwi_files, skipped_file_paths

    if path_obj.is_file():
        all_files.append(path_obj)

        file_extension = path_obj.suffix.lstrip(".").lower()

        if file_extension in normalized_accepted_extensions:
            processed_objects = process_single_py_file(path_obj)
            if processed_objects:
                all_malwi_files.extend(processed_objects)
                logging.info(
                    f"Successfully processed and extracted data from file: {path_obj}"
                )
            else:
                logging.info(
                    f"File '{path_obj}' (type: .{file_extension}) was processed by the relevant handler "
                    f"but yielded no extractable data. This might be due to its content "
                    f"(e.g., no relevant AST nodes, specific targets missing, or empty file)."
                )
        else:
            logging.info(
                f"Skipping file '{path_obj}': Extension '.{file_extension}' "
                f"is not in the accepted list: {accepted_extensions}."
            )
            skipped_file_paths.append(str(path_obj))

    elif path_obj.is_dir():
        all_files = [f for f in path_obj.rglob("*") if f.is_file()]

        if not all_files:
            logging.info(f"No files found in directory '{input_path}'.")
            return all_malwi_files, skipped_file_paths

        files_processed_yielding_data = 0
        files_accepted_type_empty_yield = 0

        for file_path in tqdm(
            all_files,
            desc=f"Processing '{path_obj.name}'",
            unit="file",
            ncols=100,
            leave=False,
        ):
            file_extension = file_path.suffix.lstrip(".").lower()
            if file_extension in normalized_accepted_extensions:
                processed_objects = process_single_py_file(file_path)
                if processed_objects:
                    all_malwi_files.extend(processed_objects)
                    files_processed_yielding_data += 1
                else:
                    files_accepted_type_empty_yield += 1
                    logging.debug(
                        f"File '{file_path}' (type: .{file_extension}) processed but yielded no data."
                    )
            else:
                skipped_file_paths.append(str(file_path))

    else:
        logging.error(
            f"Path '{input_path}' exists but is neither a file nor a directory. Skipping."
        )
        skipped_file_paths.append(input_path)

    return all_malwi_files, skipped_file_paths, all_files


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

    objects, skipped, all_files = process_source_path(args.path)

    output = ""

    if args.format == "json":
        output = MalwiFile.to_report_json(
            objects,
            all_files=all_files,
            malicious_threshold=args.threshold,
            number_of_skipped_files=len(skipped),
            malicious_only=args.malicious_only,
        )
    elif args.format == "yaml":
        output = MalwiFile.to_report_yaml(
            objects,
            all_files=all_files,
            malicious_threshold=args.threshold,
            number_of_skipped_files=len(skipped),
            malicious_only=args.malicious_only,
        )
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
