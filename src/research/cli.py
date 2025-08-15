#!/usr/bin/env python3
"""
Ultimate Research CLI for malwi training pipeline.
Provides a unified interface for downloading data, preprocessing, and training models.
"""

import argparse
import sys
import subprocess
import os
from pathlib import Path
from typing import List, Optional
from enum import Enum

from common.messaging import (
    configure_messaging,
    info,
    success,
    warning,
    error,
    progress,
    banner,
)


class Step(Enum):
    """Available pipeline steps."""

    DOWNLOAD = "download"
    PREPROCESS = "preprocess"
    TRAIN = "train"


class Language(Enum):
    """Supported programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    BOTH = "both"


class ResearchCLI:
    """Main research CLI orchestrator."""

    def __init__(self):
        """Initialize the research CLI."""
        self.parser = self._setup_parser()

    def _setup_parser(self) -> argparse.ArgumentParser:
        """Set up the argument parser with all options."""
        parser = argparse.ArgumentParser(
            description="malwi Research CLI - Unified interface for training pipeline",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Run full pipeline for Python
  python -m research.cli --steps download preprocess train --language python
  
  # Preprocess and train JavaScript (default steps)
  python -m research.cli --language javascript
  
  # Download data only
  python -m research.cli --steps download
            """,
        )

        # Pipeline steps
        parser.add_argument(
            "--steps",
            nargs="+",
            choices=[step.value for step in Step],
            default=["preprocess", "train"],
            help="Pipeline steps to execute (default: preprocess train)",
        )

        # Language selection
        parser.add_argument(
            "--language",
            "-l",
            choices=[lang.value for lang in Language],
            default=Language.BOTH.value,
            help="Programming language(s) to process (default: both)",
        )

        return parser

    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Run the research CLI with the given arguments.

        Args:
            args: Command line arguments (if None, uses sys.argv)

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        parsed_args = self.parser.parse_args(args)

        # No validation needed for simplified CLI

        # Configure messaging
        configure_messaging(quiet=False)

        # Execute pipeline steps
        try:
            for step in parsed_args.steps:
                if not self._execute_step(step, parsed_args):
                    return 1
        except KeyboardInterrupt:
            warning("Pipeline interrupted by user")
            return 130
        except Exception as e:
            error(f"Pipeline failed: {e}")
            return 1

        success("Pipeline completed successfully!")
        return 0

    def _execute_step(self, step: str, args: argparse.Namespace) -> bool:
        """
        Execute a single pipeline step.

        Args:
            step: Step name to execute
            args: Parsed command line arguments

        Returns:
            True if step succeeded, False otherwise
        """
        banner(f"\n{'=' * 60}")
        banner(f"🚀 Executing step: {step.upper()}")
        banner(f"{'=' * 60}")

        if step == Step.DOWNLOAD.value:
            return self._download_data(args)
        elif step == Step.PREPROCESS.value:
            return self._preprocess_data(args)
        elif step == Step.TRAIN.value:
            return self._train_model(args)
        else:
            error(f"Unknown step: {step}")
            return False

    def _download_data(self, args: argparse.Namespace) -> bool:
        """
        Download malware samples and benign code.

        Args:
            args: Parsed command line arguments

        Returns:
            True if download succeeded, False otherwise
        """
        info("📥 Downloading data")
        info(f"   Language(s): {args.language}")

        try:
            # Step 1: Clone/update malwi-samples repository
            progress("Step 1: Downloading malwi-samples...")
            malwi_samples_path = Path("../malwi-samples")

            if not malwi_samples_path.exists():
                info("   • Cloning malwi-samples repository...")
                os.chdir("..")
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "https://github.com/schirrmacher/malwi-samples.git",
                    ],
                    check=True,
                )
                os.chdir("malwi")
                success("   malwi-samples cloned successfully")
            else:
                info("   • Updating existing malwi-samples repository...")
                original_dir = os.getcwd()
                os.chdir("../malwi-samples")
                subprocess.run(["git", "pull", "origin", "main"], check=True)
                os.chdir(original_dir)
                success("   malwi-samples updated successfully")

            # Step 2: Download training repositories (benign + malicious)
            progress("Step 2: Downloading training repositories...")
            info("   • Using pinned commits for reproducible training")
            info("   • This may take 10-30 minutes depending on network speed")

            # Import here to avoid circular dependencies
            from research.download_data import (
                process_benign_repositories,
                process_malicious_repositories,
                BENIGN_REPO_URLS,
                MALICIOUS_REPO_URLS,
            )

            # Process language-specific repositories
            if args.language in [Language.PYTHON.value, Language.BOTH.value]:
                info("   • Processing Python repositories...")
                process_benign_repositories(BENIGN_REPO_URLS)
                process_malicious_repositories(MALICIOUS_REPO_URLS)

            if args.language in [Language.JAVASCRIPT.value, Language.BOTH.value]:
                warning("JavaScript repository processing not yet implemented")

            success("   Repository download completed")

            # Step 3: Show summary
            success("Data download completed successfully!")
            info("📁 Downloaded data:")
            info("   • ../malwi-samples/ - Malware samples for training")
            info("   • .repo_cache/benign_repos/ - Benign Python repositories (pinned)")
            info(
                "   • .repo_cache/malicious_repos/ - Malicious package datasets (pinned)"
            )

            # Show disk usage summary
            info("💾 Disk usage summary:")
            if malwi_samples_path.exists():
                try:
                    result = subprocess.run(
                        ["du", "-sh", str(malwi_samples_path)],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    size = result.stdout.split()[0]
                    info(f"   • malwi-samples: {size}")
                except:
                    info("   • malwi-samples: unknown size")

            repo_cache_path = Path(".repo_cache")
            if repo_cache_path.exists():
                try:
                    result = subprocess.run(
                        ["du", "-sh", str(repo_cache_path)],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    size = result.stdout.split()[0]
                    info(f"   • Repository cache: {size}")
                except:
                    info("   • Repository cache: unknown size")

            return True

        except subprocess.CalledProcessError as e:
            error(f"Error during download: {e}")
            return False
        except Exception as e:
            error(f"Unexpected error during download: {e}")
            return False

    def _preprocess_data(self, args: argparse.Namespace) -> bool:
        """
        Preprocess code samples into training data.

        Args:
            args: Parsed command line arguments

        Returns:
            True if preprocessing succeeded, False otherwise
        """
        info("⚙️  Preprocessing data")
        info(f"   Language(s): {args.language}")

        try:
            # Step 1: Clean up previous outputs
            progress("Step 1: Cleanup")
            info("   • Removing previous output files...")
            for file in [
                "benign.csv",
                "malicious.csv",
                "malicious_processed.csv",
                "benign_processed.csv",
            ]:
                if Path(file).exists():
                    Path(file).unlink()
            success("   Cleanup completed")

            # Step 2: Generate AST data from source files
            progress("Step 2: Generate AST Data (Parallel Processing)")

            if args.language in [Language.PYTHON.value, Language.BOTH.value]:
                info("   • Generating benign Python AST data...")
                # Generate benign data from cached repos
                subprocess.run(
                    [
                        "uv",
                        "run",
                        "python",
                        "-m",
                        "src.research.preprocess",
                        ".repo_cache/benign_repos",
                        "benign.csv",
                        "--extensions",
                        ".py",
                    ],
                    check=True,
                )

                # Add false-positives from malwi-samples
                subprocess.run(
                    [
                        "uv",
                        "run",
                        "python",
                        "-m",
                        "src.research.preprocess",
                        "../malwi-samples/python/benign",
                        "benign.csv",
                        "--extensions",
                        ".py",
                    ],
                    check=True,
                )

                info("   • Generating malicious Python AST data...")
                # Generate malicious data
                subprocess.run(
                    [
                        "uv",
                        "run",
                        "python",
                        "-m",
                        "src.research.preprocess",
                        "../malwi-samples/python/malicious",
                        "malicious.csv",
                        "--extensions",
                        ".py",
                    ],
                    check=True,
                )

                # Add suspicious findings for future training categories
                subprocess.run(
                    [
                        "uv",
                        "run",
                        "python",
                        "-m",
                        "src.research.preprocess",
                        "../malwi-samples/python/suspicious",
                        "malicious.csv",
                        "--extensions",
                        ".py",
                    ],
                    check=True,
                )

            if args.language in [Language.JAVASCRIPT.value, Language.BOTH.value]:
                warning("JavaScript preprocessing not yet implemented")

            success("   AST data generation completed")

            # Step 3: Filter and process the data
            progress("Step 3: Data Processing")
            info("   • Filtering and processing data...")
            subprocess.run(
                [
                    "uv",
                    "run",
                    "python",
                    "-m",
                    "src.research.filter_data",
                    "-b",
                    "benign.csv",
                    "-m",
                    "malicious.csv",
                    "--triaging",
                    "triaging",
                ],
                check=True,
            )
            success("   Data processing completed")

            # Step 4: Summary
            success("Data preprocessing completed successfully!")
            info("📁 Generated files:")
            info("   • benign.csv (raw benign data)")
            info("   • malicious.csv (raw malicious data)")
            info("   • benign_processed.csv (processed benign data)")
            info("   • malicious_processed.csv (processed malicious data)")

            return True

        except subprocess.CalledProcessError as e:
            error(f"Error during preprocessing: {e}")
            return False
        except Exception as e:
            error(f"Unexpected error during preprocessing: {e}")
            return False

    def _train_model(self, args: argparse.Namespace) -> bool:
        """
        Train the DistilBERT model (includes tokenizer training).

        Args:
            args: Parsed command line arguments

        Returns:
            True if training succeeded, False otherwise
        """
        info("🧠 Training model")
        info(f"   Language(s): {args.language}")

        try:
            # Step 1: Check if processed data exists
            required_files = ["benign_processed.csv", "malicious_processed.csv"]
            for file in required_files:
                if not Path(file).exists():
                    error(f"Processed data file not found: {file}")
                    error(
                        "   Please run --steps preprocess first to generate processed data"
                    )
                    return False

            success("Processed data files found")

            # Step 2: Train tokenizer first
            progress("Step 1: Training custom tokenizer...")
            info("   • Training on: benign_processed.csv, malicious_processed.csv")
            info("   • Total tokens: 15000 (default)")
            info("   • Output directory: malwi_models/")

            subprocess.run(
                [
                    "uv",
                    "run",
                    "python",
                    "-m",
                    "src.research.train_tokenizer",
                    "-b",
                    "benign_processed.csv",
                    "-m",
                    "malicious_processed.csv",
                    "-o",
                    "malwi_models",
                    "--top-n-tokens",
                    "15000",
                    "--save-computed-tokens",
                    "--force-retrain",
                ],
                check=True,
            )

            success("Tokenizer training completed successfully!")
            info("📋 Generated tokenizer files in malwi_models/:")
            info("   • tokenizer.json - Main tokenizer configuration")
            info("   • tokenizer_config.json - Tokenizer metadata")
            info("   • vocab.json - Vocabulary mapping")
            info("   • merges.txt - BPE merge rules")
            info("   • computed_special_tokens.txt - All special tokens (base + data)")
            info("   • base_tokens_from_function_mapping.txt - Base tokens only")

            # Step 3: Check if tokenizer was created successfully
            if not Path("malwi_models/tokenizer.json").exists():
                error("Tokenizer training failed")
                return False

            success("Tokenizer found at malwi_models/")

            # Step 4: Train DistilBERT model
            progress("Step 2: Training DistilBERT model...")
            info("   • Loading pre-trained tokenizer from malwi_models/")
            info("   • Training data: benign_processed.csv, malicious_processed.csv")
            info("   • Model size: 256 hidden dimensions (smaller, faster model)")
            info("   • Epochs: 3")
            info("   • Using 1 processor for training")
            info("   Note: Set HIDDEN_SIZE=512 for larger model with better accuracy")

            # Get configurable parameters from environment or use defaults
            epochs = os.environ.get("EPOCHS", "3")
            hidden_size = os.environ.get("HIDDEN_SIZE", "256")
            num_proc = os.environ.get("NUM_PROC", "1")

            subprocess.run(
                [
                    "uv",
                    "run",
                    "python",
                    "-m",
                    "src.research.train_distilbert",
                    "-b",
                    "benign_processed.csv",
                    "-m",
                    "malicious_processed.csv",
                    "--epochs",
                    epochs,
                    "--hidden-size",
                    hidden_size,
                    "--num-proc",
                    num_proc,
                ],
                check=True,
            )

            success("DistilBERT model training completed!")
            info("📋 Model files saved to malwi_models/:")
            info("   • Trained DistilBERT model weights and config")
            info("   • Training metrics and logs")
            info("   • Pre-existing tokenizer (preserved)")

            # Final summary
            success("Complete model training pipeline finished successfully!")
            info("📁 All outputs are in malwi_models/:")
            info("   • Tokenizer (trained on your data's top 15000 tokens)")
            info(f"   • Trained DistilBERT model ({hidden_size} hidden dimensions)")
            info("   • Training metrics and logs")
            info("💡 Tip: For different configurations, set environment variables:")
            info(
                "   HIDDEN_SIZE=512 TOTAL_TOKENS=20000 python -m research.cli --steps train"
            )

            return True

        except subprocess.CalledProcessError as e:
            error(f"Error during training: {e}")
            return False
        except Exception as e:
            error(f"Unexpected error during training: {e}")
            return False


def main():
    """Main entry point for the research CLI."""
    cli = ResearchCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()
