"""
Triage functionality for malwi CLI with subcommands.
"""


def triage_scan_command(args):
    """Execute triage scan and move malicious files to suspicious folder."""
    from pathlib import Path
    from common.malwi_object import MalwiObject
    from common.malwi_report import MalwiReport
    from common.files import copy_file, concatenate_files
    from common.config import SUPPORTED_EXTENSIONS
    from common.messaging import (
        configure_messaging,
        banner,
        info,
        success,
        warning,
        result,
        model_warning,
        path_error,
        error,
    )
    import shutil

    configure_messaging(quiet=getattr(args, "quiet", False))
    banner()
    info("🔍 Triage Scan - Processing Results")

    # Create MalwiReport to get access to malicious files
    input_path = Path(args.path)
    if not input_path.exists():
        path_error(input_path)
        return

    # Load ML models
    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=getattr(args, "model_path", None),
            tokenizer_path=getattr(args, "tokenizer_path", None),
        )
    except Exception as e:
        model_warning("ML", e)

    # Create the report
    report: MalwiReport = MalwiReport.create(
        input_path=input_path,
        accepted_extensions=getattr(args, "extensions", SUPPORTED_EXTENSIONS),
        predict=True,
        silent=args.quiet,
        malicious_threshold=getattr(args, "threshold", 0.7),
    )

    # Generate and display output
    format_type = getattr(args, "format", "demo")
    if format_type == "yaml":
        output = report.to_report_yaml()
    elif format_type == "json":
        output = report.to_report_json()
    elif format_type == "markdown":
        output = report.to_report_markdown()
    elif format_type == "tokens":
        output = report.to_tokens_text()
    elif format_type == "code":
        output = report.to_code_text()
    else:
        output = report.to_demo_text()

    # Save or display output
    if getattr(args, "save", None):
        save_path = Path(args.save)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(output, encoding="utf-8")
        info(f"Output saved to {args.save}")
    else:
        result(output, force=True)

    # Triage: Process malicious files
    suspicious_folder = Path(getattr(args, "suspicious", "suspicious"))
    suspicious_folder.mkdir(parents=True, exist_ok=True)

    malicious_files = report.malicious_objects

    if malicious_files:
        # Get unique file paths
        unique_files = list(set(Path(obj.file_path) for obj in malicious_files))
        moved_count = 0

        # Move unique files to suspicious folder
        for source_file in unique_files:
            try:
                rel_path = source_file.relative_to(input_path)
                dest_file = suspicious_folder / rel_path
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_file, dest_file)
                moved_count += 1

            except Exception as e:
                warning(f"Failed to process {source_file}: {e}")

        # Generate concatenated content for LLM processing
        llm_content = concatenate_files(
            malicious_files, input_path, getattr(args, "threshold", 0.7)
        )
        llm_file = suspicious_folder / "malicious_content_for_llm.txt"
        try:
            llm_file.write_text(llm_content, encoding="utf-8")
        except Exception as e:
            warning(f"Failed to save LLM content: {e}")

        # Run First Responder analysis
        from cli.agents.first_responder import FirstResponder

        api_key = getattr(args, "api_key", "demo")
        model = getattr(args, "model", "mistral-medium-2508")

        first_responder = FirstResponder(api_key, model)
        decisions = first_responder.analyze_files(llm_content)

        # Process triage decisions - move files to appropriate folders
        benign_folder = Path(getattr(args, "benign", "benign"))
        malicious_folder = Path(getattr(args, "malicious", "malicious"))
        # Note: suspicious_folder already defined above

        # Get unique source file paths from malicious objects
        source_files = unique_files

        moved_files = first_responder.process_triage_decisions(
            decisions,
            source_files,
            benign_folder,
            suspicious_folder,
            malicious_folder,
            input_path,
        )

        # Report results with reasoning summaries
        success(
            f"Triage: {len(moved_files['benign'])} benign, {len(moved_files['suspicious'])} suspicious, {len(moved_files['malicious'])} malicious"
        )

        # Show unique decision reasoning (avoid duplicates for same file)
        seen_decisions = set()
        for decision in decisions:
            decision_key = (decision.decision, decision.reasoning)
            if decision_key not in seen_decisions:
                seen_decisions.add(decision_key)
                from pathlib import Path

                filename = Path(decision.file_path).name
                info(f"\n📄 File: {filename}")
                info(f"   Path: {decision.file_path}")
                info(f"   Analysis: {decision.reasoning}\n")
    else:
        info("No malicious files found - nothing to triage")


def triage_pypi_command(args):
    """Execute triage pypi scan and move malicious files to suspicious folder."""
    from pathlib import Path
    from common.malwi_object import MalwiObject
    from common.malwi_report import MalwiReport
    from common.messaging import (
        configure_messaging,
        banner,
        info,
        success,
        warning,
        result,
        model_warning,
        error,
    )
    from cli.pypi import PyPIScanner
    from common.files import concatenate_files
    import shutil

    configure_messaging(quiet=getattr(args, "quiet", False))
    banner()
    info("🔍 Triage PyPI - Processing Results")

    # Download and extract the package
    info("🚀 Downloading PyPI package...")
    download_path = Path(getattr(args, "folder", "downloads"))
    temp_dir, extracted_dirs = PyPIScanner(download_path).scan_package(
        args.package, getattr(args, "version", None), show_progress=not args.quiet
    )

    if not extracted_dirs:
        warning("Failed to download or extract package")
        return

    # Load ML models for scanning
    try:
        MalwiObject.load_models_into_memory(
            distilbert_model_path=getattr(args, "model_path", None),
            tokenizer_path=getattr(args, "tokenizer_path", None),
        )
    except Exception as e:
        model_warning("ML", e)

    # Scan each extracted directory and collect all reports
    all_malicious_files = []
    for extracted_dir in extracted_dirs:
        info(f"🔍 Scanning {extracted_dir}...")

        report: MalwiReport = MalwiReport.create(
            input_path=extracted_dir,
            accepted_extensions=[".py"],  # Focus on Python files for PyPI packages
            predict=True,
            silent=args.quiet,
            malicious_threshold=getattr(args, "threshold", 0.7),
        )

        # Generate output for this report
        format_type = getattr(args, "format", "demo")
        if format_type == "yaml":
            output = report.to_report_yaml()
        elif format_type == "json":
            output = report.to_report_json()
        elif format_type == "markdown":
            output = report.to_report_markdown()
        elif format_type == "tokens":
            output = report.to_tokens_text()
        elif format_type == "code":
            output = report.to_code_text()
        else:
            output = report.to_demo_text()

        # Save or display output
        if getattr(args, "save", None):
            save_path = Path(args.save)
            save_path.parent.mkdir(parents=True, exist_ok=True)
            save_path.write_text(output, encoding="utf-8")
            info(f"Output saved to {args.save}")
        else:
            result(output, force=True)

        # Collect malicious files from this report
        malicious_files = report.malicious_objects
        all_malicious_files.extend(malicious_files)

    # Triage: Move malicious files to suspicious folder
    suspicious_folder = Path(getattr(args, "suspicious", "suspicious"))
    suspicious_folder.mkdir(parents=True, exist_ok=True)

    if all_malicious_files:
        # Get unique file paths
        unique_files = list(set(Path(obj.file_path) for obj in all_malicious_files))
        moved_count = 0

        # Move unique files to suspicious folder
        for source_file in unique_files:
            try:
                package_name = args.package
                rel_path = source_file.relative_to(temp_dir)
                dest_file = suspicious_folder / package_name / rel_path
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_file, dest_file)
                moved_count += 1

            except Exception as e:
                warning(f"Failed to process {source_file}: {e}")

        # Generate concatenated content for LLM processing
        llm_content = concatenate_files(
            all_malicious_files, temp_dir, getattr(args, "threshold", 0.7)
        )
        llm_file = suspicious_folder / f"{args.package}_malicious_content_for_llm.txt"
        try:
            llm_file.write_text(llm_content, encoding="utf-8")
        except Exception as e:
            warning(f"Failed to save LLM content: {e}")

        # Run First Responder analysis
        from cli.agents.first_responder import FirstResponder

        api_key = getattr(args, "api_key", "demo")
        model = getattr(args, "model", "mistral-medium-2508")

        first_responder = FirstResponder(api_key, model)
        decisions = first_responder.analyze_files(llm_content)

        # Process triage decisions - move files to appropriate folders
        benign_folder = Path(getattr(args, "benign", "benign"))
        malicious_folder = Path(getattr(args, "malicious", "malicious"))
        # Note: suspicious_folder already defined above

        moved_files = first_responder.process_triage_decisions(
            decisions,
            unique_files,
            benign_folder,
            suspicious_folder,
            malicious_folder,
            temp_dir,
        )

        # Report results with reasoning summaries
        success(
            f"Triage: {len(moved_files['benign'])} benign, {len(moved_files['suspicious'])} suspicious, {len(moved_files['malicious'])} malicious"
        )

        # Show unique decision reasoning (avoid duplicates for same file)
        seen_decisions = set()
        for decision in decisions:
            decision_key = (decision.decision, decision.reasoning)
            if decision_key not in seen_decisions:
                seen_decisions.add(decision_key)
                from pathlib import Path

                filename = Path(decision.file_path).name
                info(f"\n📄 File: {filename}")
                info(f"   Path: {decision.file_path}")
                info(f"   Analysis: {decision.reasoning}\n")
    else:
        success("No malicious files found in PyPI package - nothing to triage")


def setup_triage_parser(subparsers):
    """Set up the triage subcommand parser with subcommands."""
    triage_parser = subparsers.add_parser(
        "triage", help="Triage with malwi integration"
    )

    # Create subparsers for triage subcommands
    triage_subparsers = triage_parser.add_subparsers(
        dest="triage_command",
        help="Triage operations",
        title="triage commands",
        description="Available triage operations",
    )

    # Common triage arguments for all subcommands
    def add_triage_args(parser):
        triage_group = parser.add_argument_group("Triage Options")
        triage_group.add_argument(
            "--api-key",
            default="demo",
            help="API key for the AI model service (use 'demo' for pattern-based analysis)",
        )
        triage_group.add_argument(
            "--model",
            default="mistral-medium-2508",
            choices=["mistral-medium-2508", "mistral-large-2411"],
            help="AI model to use for analysis (default: mistral-medium-2508)",
        )
        triage_group.add_argument(
            "--benign",
            type=str,
            default="benign",
            help="Path to folder for benign files (default: benign)",
        )
        triage_group.add_argument(
            "--malicious",
            type=str,
            default="malicious",
            help="Path to folder for malicious files (default: malicious)",
        )
        triage_group.add_argument(
            "--suspicious",
            type=str,
            default="suspicious",
            help="Path to folder for suspicious files (default: suspicious)",
        )

    # Import existing parser setup functions and command functions
    from cli.scan import setup_scan_parser
    from cli.pypi import setup_pypi_parser

    # Scan subcommand - reuse existing setup but with triage command
    setup_scan_parser(triage_subparsers)
    scan_parser = triage_subparsers.choices["scan"]
    scan_parser.description = "Scan files/directories with triage processing"
    add_triage_args(scan_parser)
    scan_parser.set_defaults(func=triage_scan_command)

    # PyPI subcommand - reuse existing setup but with triage command
    setup_pypi_parser(triage_subparsers)
    pypi_parser = triage_subparsers.choices["pypi"]
    pypi_parser.description = "Scan PyPI packages with triage processing"
    add_triage_args(pypi_parser)
    pypi_parser.set_defaults(func=triage_pypi_command)

    # Default behavior when no subcommand is provided
    def default_triage_command(args):
        if not args.triage_command:
            triage_parser.print_help()
            return

    triage_parser.set_defaults(func=default_triage_command)
