import logging
import argparse
from typing import List
from pathlib import Path

from research.disassemble_python import (
    MalwiObject,
    process_files,
    ProcessingResult,
)

logging.basicConfig(format="%(message)s", level=logging.INFO)


def main():
    parser = argparse.ArgumentParser(description="malwi - AI Python Malware Scanner")
    parser.add_argument(
        "path", metavar="PATH", help="Specify the package file or folder path."
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["demo", "markdown", "json", "yaml"],
        default="demo",
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
        "--threshold",
        "-mt",
        metavar="FLOAT",
        type=float,
        default=0.7,
        help="Specify the threshold for classifying code objects as malicious (default: 0.7).",
    )
    parser.add_argument(
        "--extensions",
        "-e",
        nargs="+",
        default=["py"],
        help="Specify file extensions to process (default: py).",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress logging output and progress bar.",
    )

    speed_group = parser.add_argument_group("Efficiency")
    speed_group.add_argument(
        "--malicious-only",
        "-mo",
        action="store_true",
        help="Only include malicious findings in the output.",
    )
    speed_group.add_argument(
        "--no-snippets",
        action="store_false",
        help="Do not add code snippets of findings in the output to increase performance.",
        default=True,
    )
    speed_group.add_argument(
        "--no-sources",
        action="store_false",
        help="Avoid full source files being added to the output (required for loading objects from files, e.g. after triaging).",
        default=True,
    )

    developer_group = parser.add_argument_group("Developer Options")

    developer_group.add_argument(
        "--tokenizer-path",
        "-t",
        metavar="PATH",
        help="Specify the tokenizer path",
        default=None,
    )
    developer_group.add_argument(
        "--model-path",
        "-m",
        metavar="PATH",
        help="Specify the DistilBert model path",
        default=None,
    )
    developer_group.add_argument(
        "--svm-path",
        "-svm",
        metavar="PATH",
        help="Specify the SVM layer model path",
        default=None,
    )
    triage_group = developer_group.add_mutually_exclusive_group()

    triage_group.add_argument(
        "--triage",
        action="store_true",
        help="Enable manual triage mode.",
    )

    triage_group.add_argument(
        "--triage-ollama",
        action="store_true",
        help="Enable Ollama triage mode.",
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

    # Load ML models
    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=args.model_path,
            tokenizer_path=args.tokenizer_path,
            svm_layer_path=args.svm_path,
        )
    except Exception as e:
        if not args.quiet:
            logging.error(
                f"Warning: Could not initialize ML models: {e}. "
                "Maliciousness prediction will be disabled."
            )

    # Process files using the consolidated function
    input_path = Path(args.path)
    if not input_path.exists():
        logging.error(f"Error: Input path does not exist: {input_path}")
        return

    triaging_type = None
    if args.triage:
        triaging_type = "manual"
    elif args.triage_ollama:
        triaging_type = "ollama"

    result: ProcessingResult = process_files(
        input_path=input_path,
        accepted_extensions=args.extensions,
        predict=True,  # Enable prediction for malwi scanner
        retrieve_source_code=args.no_snippets,
        silent=args.quiet,
        show_progress=not args.quiet,
        triaging_type=triaging_type,
        malicious_threshold=args.threshold,
    )

    output = ""

    if args.format == "yaml":
        output = MalwiObject.to_report_yaml(
            result.objects,
            all_files=[str(f) for f in result.all_files],
            malicious_threshold=args.threshold,
            number_of_skipped_files=len(result.skipped_files),
            include_source_files=args.no_sources,
        )
    elif args.format == "json":
        output = MalwiObject.to_report_json(
            result.objects,
            all_files=[str(f) for f in result.all_files],
            malicious_threshold=args.threshold,
            number_of_skipped_files=len(result.skipped_files),
            include_source_files=args.no_sources,
        )
    elif args.format == "markdown":
        output = MalwiObject.to_report_markdown(
            result.objects,
            all_files=[str(f) for f in result.all_files],
            malicious_threshold=args.threshold,
            number_of_skipped_files=len(result.skipped_files),
            include_source_files=args.no_sources,
        )
    else:
        print(f"- {len(result.all_files)} files scanned")
        print(f"- {len(result.skipped_files)} files skipped")
        print(f"- {len(result.objects)} malicious objects")
        print("")
        if result.malicious:
            print(f"=> 👹 malicious {result.confidence}")
        else:
            print(f"=> 🟢 not malicious {result.confidence}")

    if args.save:
        save_path = Path(args.save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(output, encoding="utf-8")
        if not args.quiet:
            logging.info(f"Output saved to {args.save}")
    else:
        print(output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("👋")
