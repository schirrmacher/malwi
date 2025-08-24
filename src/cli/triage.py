"""
CLI subcommand for triaging files with LLM models.
"""

import os
import sys
from pathlib import Path

from common.messaging import configure_messaging, info, error
from common.triage import run_triage


def triage_command(args):
    """Execute the triage subcommand."""
    configure_messaging(quiet=args.quiet)

    # Validate input path
    input_path = Path(args.input)
    if not input_path.exists():
        error(f"Input path does not exist: {args.input}")
        sys.exit(1)

    # Get API key from args or environment variable
    api_key = args.llm_api_key or os.environ.get("LLM_API_KEY")

    if not api_key:
        error(
            "LLM API key is required. Use --llm-api-key or set LLM_API_KEY environment variable."
        )
        sys.exit(1)

    # Get base URL from args or environment variable
    base_url = getattr(args, "llm_base_url", None) or os.environ.get("LLM_BASE_URL")

    info(f"🔍 Triaging {args.input} with {args.llm}")

    try:
        # Run triage - will organize files into folders
        run_triage(
            input_path=args.input,
            llm_model=args.llm,
            api_key=api_key,
            base_url=base_url,
            output_dir=args.output,
            benign_folder=args.benign,
            suspicious_folder=args.suspicious,
            malicious_folder=args.malicious,
            strategy=args.strategy,
        )

    except Exception as e:
        error(f"Triage failed: {e}")
        sys.exit(1)


def setup_triage_parser(subparsers):
    """Set up the triage subcommand parser."""
    parser = subparsers.add_parser(
        "triage", help="Triage files into benign/suspicious/malicious folders using LLM"
    )

    # Required arguments
    parser.add_argument("input", help="Path to directory containing folders to triage")

    # LLM configuration
    parser.add_argument(
        "--llm",
        default="mistral-large-2411",
        help="LLM model to use for triage (default: mistral-large-2411)",
    )

    parser.add_argument(
        "--llm-base-url",
        help="Base URL for the LLM API (auto-derived from model if not specified, can also be set via LLM_BASE_URL env var)",
    )

    parser.add_argument(
        "--llm-api-key",
        help="API key for the LLM service (can also be set via LLM_API_KEY env var)",
        required=False,
    )

    parser.add_argument(
        "--benign",
        default="benign",
        help="Folder name for benign files (default: benign)",
    )

    parser.add_argument(
        "--suspicious",
        default="suspicious",
        help="Folder name for suspicious files (default: suspicious)",
    )

    parser.add_argument(
        "--malicious",
        default="malicious",
        help="Folder name for malicious files (default: malicious)",
    )

    parser.add_argument(
        "--output",
        default="triaged",
        help="Output directory path for triage results (default: triaged)",
    )

    parser.add_argument(
        "--strategy",
        choices=["concat", "single", "smart"],
        default="concat",
        help="Triage strategy: 'concat' sends all files in a folder together (default), 'single' analyzes each file individually, 'smart' extracts only malicious code parts into individual files for ML training",
    )

    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress informational messages"
    )

    parser.set_defaults(func=triage_command)
