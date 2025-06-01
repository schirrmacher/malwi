import argparse
from pathlib import Path

from typing import Optional

from research.disassemble_python import MalwiObject, triage


def process_object_file(
    file_path: Path,
    grep_string: str = None,
    auto_triaging: Optional[str] = None,
    max_tokens: int = 0,
    triaging_type: Optional[str] = None,
):
    try:
        objects = MalwiObject.from_file(file_path)
        triage(
            all_objects=objects,
            grep_string=grep_string,
            auto_triaging=auto_triaging,
            max_tokens=max_tokens,
            triaging_type=triaging_type,
        )
    except Exception as e:
        print(f"Failed to process {file_path}: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Process YAML files into MalwiObjects for triaging."
    )
    parser.add_argument(
        "--path",
        type=Path,
        required=True,
        help="Path to a YAML file or folder (non-recursive)",
    )
    parser.add_argument(
        "--grep",
        type=str,
        help="String to be contained in any MalwiObject attribute",
    )
    parser.add_argument(
        "--max-tokens",
        default=0,
        type=int,
        help="Maximum number of token words (separated by space)",
    )

    triage_group = parser.add_mutually_exclusive_group()
    triage_group.add_argument(
        "--triage-ollama",
        action="store_true",
        help="Enable Ollama triage mode.",
    )
    triage_group.add_argument(
        "--auto",
        type=str,
        default=None,
        choices=["malicious", "benign"],
        help="Automatically triage all findings as either 'malicious' or 'benign'.",
    )

    args = parser.parse_args()

    triaging_type = "manual"
    if args.triage_ollama:
        triaging_type = "ollama"
    elif args.auto:
        triaging_type = "auto"

    if args.path.is_file():
        process_object_file(
            file_path=args.path,
            grep_string=args.grep,
            auto_triaging=args.auto,
            max_tokens=args.max_tokens,
            triaging_type=triaging_type,
        )
    elif args.path.is_dir():
        for file in args.path.iterdir():
            if file.is_file() and file.suffix in {".yaml", ".yml"}:
                process_object_file(
                    file_path=file,
                    grep_string=args.grep,
                    auto_triaging=args.auto,
                    max_tokens=args.max_tokens,
                    triaging_type=triaging_type,
                )
    else:
        print(f"Invalid path: {args.path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("👋")
