import os
import argparse

from tqdm import tqdm
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


from research.malwi_object import (
    MalwiObject,
    process_files,
    MalwiReport,
)
from research.predict_distilbert import get_model_version_string
from common.messaging import (
    configure_messaging,
    banner,
    model_warning,
    path_error,
    info,
    result,
)
from malwi._version import __version__


def run_batch_scan(child_folder: Path, args) -> dict:
    """Run a single scan on a child folder and return results."""
    # Check if output file already exists
    format_ext = {"demo": ".txt", "markdown": ".md", "json": ".json", "yaml": ".yaml"}
    extension = format_ext.get(args.format, ".txt")
    output_file = Path.cwd() / f"malwi_{child_folder.name}{extension}"

    if output_file.exists():
        return {"folder": child_folder.name, "success": True, "skipped": True}

    try:
        report: MalwiReport = process_files(
            input_path=child_folder,
            accepted_extensions=args.extensions,
            predict=True,
            silent=True,  # Silent for individual folder processing in batch mode
            malicious_threshold=args.threshold,
        )

        # Generate output based on format
        if args.format == "yaml":
            output = report.to_report_yaml()
        elif args.format == "json":
            output = report.to_report_json()
        elif args.format == "markdown":
            output = report.to_report_markdown()
        else:
            output = report.to_demo_text()

        # Save the output
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(output, encoding="utf-8")

        return {"folder": child_folder.name, "success": True, "skipped": False}

    except Exception as e:
        return {
            "folder": child_folder.name,
            "success": False,
            "error": str(e),
            "skipped": False,
        }


def process_batch_mode(input_path: Path, args) -> None:
    """Process multiple child folders in batch mode."""
    if not input_path.is_dir():
        path_error("Batch mode requires a directory path")
        return

    # Get all child directories
    child_folders = [p for p in input_path.iterdir() if p.is_dir()]

    if not child_folders:
        info("No child directories found for batch processing")
        return

    # Load ML models once for batch processing
    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=args.model_path,
            tokenizer_path=args.tokenizer_path,
        )
    except Exception as e:
        model_warning("ML", e)

    info(f"🚀 Starting batch scan of {len(child_folders)} folders")

    # Use ThreadPoolExecutor for parallel processing (shares memory space for models)
    max_workers = min(4, len(child_folders))  # Restore parallel processing

    failed = 0
    skipped = 0
    failed_folders = []

    # Create progress bar (disable if quiet mode)
    with tqdm(
        total=len(child_folders),
        desc="📈 Scanning folders",
        unit="folder",
        disable=args.quiet,
    ) as pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            try:
                # Submit all jobs
                future_to_folder = {
                    executor.submit(run_batch_scan, folder, args): folder
                    for folder in child_folders
                }

                # Process completed jobs
                for future in as_completed(future_to_folder):
                    folder = future_to_folder[future]
                    try:
                        batch_result = future.result()

                        if batch_result.get("skipped", False):
                            skipped += 1
                            pbar.set_postfix_str(f"⏭️ {batch_result['folder']}")
                        elif batch_result["success"]:
                            pbar.set_postfix_str(f"✅ {batch_result['folder']}")
                        else:
                            failed += 1
                            error_msg = batch_result.get("error", "Unknown error")
                            failed_folders.append(
                                f"{batch_result['folder']}: {error_msg}"
                            )
                            pbar.set_postfix_str(f"❌ {batch_result['folder']}")

                    except Exception as e:
                        failed += 1
                        failed_folders.append(f"{folder.name}: {str(e)}")
                        pbar.set_postfix_str(f"❌ {folder.name}")

                    pbar.update(1)

            except KeyboardInterrupt:
                info("\n🛑 Interrupt received. Shutting down...")
                # Force immediate exit to avoid thread cleanup issues
                os._exit(130)

    # Summary
    processed = len(child_folders) - skipped
    success_count = processed - failed
    info(
        f"🎯 Batch scan complete: {success_count} successful, {failed} failed, {skipped} skipped"
    )

    # Show failed folders if any
    if failed_folders and not args.quiet:
        info("Failed folders:")
        for failure in failed_folders:
            info(f"  - {failure}")


def main():
    parser = argparse.ArgumentParser(description="malwi - AI Python Malware Scanner")
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=get_model_version_string(__version__),
    )
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
    # Create mutually exclusive group for batch and save modes
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--save",
        "-s",
        metavar="FILE",
        help="Specify a file path to save the output.",
        default=None,
    )
    output_group.add_argument(
        "--batch",
        action="store_true",
        help="Run independent scans on each child folder and save results to current directory as malwi_<foldername>.<format>.",
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
        default=["py", "js", "mjs", "cjs"],
        help="Specify file extensions to process (default: py, js, mjs, cjs).",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress logging output and progress bar.",
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

    args = parser.parse_args()

    # Configure unified messaging system
    configure_messaging(quiet=args.quiet)

    banner(
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

    # Process files using the consolidated function
    input_path = Path(args.path)
    if not input_path.exists():
        path_error(input_path)
        return

    # Handle batch mode - run independent scans on child folders
    if args.batch:
        process_batch_mode(input_path, args)
        return

    # Load ML models (only for non-batch mode)
    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=args.model_path,
            tokenizer_path=args.tokenizer_path,
        )
    except Exception as e:
        model_warning("ML", e)

    report: MalwiReport = process_files(
        input_path=input_path,
        accepted_extensions=args.extensions,
        predict=True,  # Enable prediction for malwi scanner
        silent=args.quiet,
        malicious_threshold=args.threshold,
    )

    output = ""

    if args.format == "yaml":
        output = report.to_report_yaml()
    elif args.format == "json":
        output = report.to_report_json()
    elif args.format == "markdown":
        output = report.to_report_markdown()
    else:
        output = report.to_demo_text()

    if args.save:
        save_path = Path(args.save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(output, encoding="utf-8")
        info(f"Output saved to {args.save}")
    else:
        # Ensure all streams are flushed before final output
        import sys

        sys.stdout.flush()
        sys.stderr.flush()

        # Use result() for consistent output handling
        result(output, force=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        result("👋", force=True)
        os._exit(130)
