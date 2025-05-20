import logging
import argparse
from pathlib import Path

from cli.predict import initialize_models
from research.disasemble_python import process_single_py_file

logging.basicConfig(format="%(message)s", level=logging.INFO)


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

    objects = process_single_py_file(Path(args.path))

    if objects:
        for o in objects:
            print(o.to_token_string())
            print()
            prediction = o.predict()
            print(
                f"benign: {prediction['probabilities'][0]}, malicious: {prediction['probabilities'][1]}"
            )

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
