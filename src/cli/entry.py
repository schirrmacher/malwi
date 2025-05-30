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
        choices=["markdown", "json", "yaml", "tokens"],
        default="markdown",
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
    developer_group.add_argument(
        "--triage",
        action="store_true",
        default=False,
        help="Enable triage mode (default: False)",
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
            model_path=args.model_path, tokenizer_path=args.tokenizer_path
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

    result: ProcessingResult = process_files(
        input_path=input_path,
        accepted_extensions=args.extensions,
        predict=True,  # Enable prediction for malwi scanner
        retrieve_source_code=args.no_snippets,
        silent=args.quiet,
        show_progress=not args.quiet,
        interactive_triaging=args.triage,
    )

    output = ""

    if args.format == "yaml":
        output = MalwiObject.to_report_yaml(
            result.malwi_objects,
            all_files=[str(f) for f in result.all_files],
            malicious_threshold=args.threshold,
            number_of_skipped_files=len(result.skipped_files),
            malicious_only=args.malicious_only,
            include_source_files=args.no_sources,
        )
    elif args.format == "markdown":
        output = MalwiObject.to_report_markdown(
            result.malwi_objects,
            all_files=[str(f) for f in result.all_files],
            malicious_threshold=args.threshold,
            number_of_skipped_files=len(result.skipped_files),
            malicious_only=args.malicious_only,
            include_source_files=args.no_sources,
        )
    elif args.format == "tokens":
        output = generate_tokens_output(result.malwi_objects)
    else:
        output = MalwiObject.to_report_json(
            result.malwi_objects,
            all_files=[str(f) for f in result.all_files],
            malicious_threshold=args.threshold,
            number_of_skipped_files=len(result.skipped_files),
            malicious_only=args.malicious_only,
        )

    if args.save:
        save_path = Path(args.save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(output, encoding="utf-8")
        if not args.quiet:
            logging.info(f"Output saved to {args.save}")
    else:
        print(output)


def generate_tokens_output(malwi_objects: List[MalwiObject]) -> str:
    """Generate tokens-only output."""
    lines = []
    for obj in malwi_objects:
        lines.append(f"# {obj.file_path} - {obj.name}")
        lines.append(obj.to_token_string())
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
