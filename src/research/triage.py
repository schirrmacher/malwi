import argparse

from tqdm import tqdm
from pathlib import Path
from typing import Optional

from research.disassemble_python import MalwiObject, triage
from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    path_error,
)


def process_object_file(
    file_path: Path,
    out_path: Path,
    grep_string: str = None,
    auto_triaging: Optional[str] = None,
    max_tokens: int = 0,
    triaging_type: Optional[str] = None,
    llm_prompt: Optional[str] = None,
    llm_model: str = "gemma3",
):
    try:
        objects = MalwiObject.from_file(file_path)
        triage(
            all_objects=objects,
            out_path=out_path,
            grep_string=grep_string,
            auto_triaging=auto_triaging,
            max_tokens=max_tokens,
            triaging_type=triaging_type,
            llm_prompt=llm_prompt,
            llm_model=llm_model,
        )
        success(f"Triage completed for {file_path}")
    except Exception as e:
        error(f"Failed to process triage file {file_path}: {e}")


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
        "--out",
        type=Path,
        default="triaging",
        help="Output folder",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default=None,
        help="Prompt if LLM is applied",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="gemma3",
        help="LLM model to be used for triaging",
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

    # Configure messaging system
    configure_messaging(quiet=False)

    triaging_type = "manual"
    if args.triage_ollama:
        triaging_type = "ollama"
    elif args.auto:
        triaging_type = "auto"

    if args.path.is_file():
        process_object_file(
            file_path=args.path,
            out_path=args.out,
            grep_string=args.grep,
            auto_triaging=args.auto,
            max_tokens=args.max_tokens,
            triaging_type=triaging_type,
            llm_model=args.model,
            llm_prompt=args.prompt,
        )
    elif args.path.is_dir():
        files = [
            file
            for file in args.path.iterdir()
            if file.is_file() and file.suffix in {".yaml", ".yml"}
        ]
        info(f"Found {len(files)} YAML files to process")
        for file in tqdm(files, desc="Processing files"):
            process_object_file(
                file_path=file,
                out_path=args.out,
                grep_string=args.grep,
                auto_triaging=args.auto,
                max_tokens=args.max_tokens,
                triaging_type=triaging_type,
                llm_model=args.model,
                llm_prompt=args.prompt,
            )
    else:
        path_error(args.path, "is not a valid file or directory")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        warning("Operation interrupted by user")
