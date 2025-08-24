"""
Triage functionality for analyzing files with LLM models and organizing them.
"""

import shutil
from pathlib import Path

from tqdm import tqdm
from tabulate import tabulate
from common.messaging import info, warning, error, success
from cli.agents.first_responder import FirstResponder


def run_triage(
    input_path: str,
    llm_model: str,
    api_key: str,
    base_url: str = None,
    output_dir: str = "triaged",
    benign_folder: str = "benign",
    suspicious_folder: str = "suspicious",
    malicious_folder: str = "malicious",
    strategy: str = "concat",
) -> None:
    """
    Run triage on the specified input path using FirstResponder agent.
    Iterates through immediate child folders and organizes files into
    benign/suspicious/malicious folders.

    Args:
        input_path: Path to directory containing folders to triage
        llm_model: LLM model to use for analysis
        api_key: API key for the LLM service
        base_url: Base URL for the LLM API (auto-derived if None)
        output_dir: Output directory name for triage results
        benign_folder: Name of folder for benign files
        suspicious_folder: Name of folder for suspicious files
        malicious_folder: Name of folder for malicious files
        strategy: Triage strategy - 'concat' or 'single'
    """
    path = Path(input_path)

    if not path.exists():
        raise ValueError(f"Path does not exist: {input_path}")

    if not path.is_dir():
        raise ValueError(f"Path must be a directory: {input_path}")

    # Initialize FirstResponder agent
    first_responder = FirstResponder(api_key, llm_model, base_url)

    # Create output folders - independent from input directory
    output_base = Path(output_dir).resolve()
    benign_path = output_base / benign_folder
    suspicious_path = output_base / suspicious_folder
    malicious_path = output_base / malicious_folder

    # Clean and create folders
    if output_base.exists():
        shutil.rmtree(output_base)
    benign_path.mkdir(parents=True, exist_ok=True)
    suspicious_path.mkdir(parents=True, exist_ok=True)
    malicious_path.mkdir(parents=True, exist_ok=True)

    # Get immediate child directories
    child_dirs = [d for d in path.iterdir() if d.is_dir()]

    if not child_dirs:
        child_dirs = [path]

    total_stats = {"benign": 0, "suspicious": 0, "malicious": 0}
    files_created = {"suspicious": 0, "malicious": 0}

    # Process each child directory with progress bar
    for child_dir in tqdm(child_dirs, desc="Analyzing directories"):
        # Collect Python and JavaScript files
        files_to_analyze = []
        extensions = [".py", ".js", ".mjs", ".cjs"]

        for ext in extensions:
            files_to_analyze.extend(list(child_dir.rglob(f"*{ext}")))

        if not files_to_analyze:
            continue

        if strategy == "concat":
            decision = _analyze_folder_concat(
                first_responder, child_dir, files_to_analyze
            )
        elif strategy == "single":
            decision = _analyze_folder_single(
                first_responder, child_dir, files_to_analyze
            )
        else:  # smart
            decision = _analyze_folder_smart(
                first_responder, child_dir, files_to_analyze
            )

        # Determine target folder based on decision
        decision_lower = decision.decision.lower()
        if decision_lower == "benign":
            target_folder = benign_path
            total_stats["benign"] += 1
        elif decision_lower == "malicious":
            target_folder = malicious_path
            total_stats["malicious"] += 1
        else:  # suspicious
            target_folder = suspicious_path
            total_stats["suspicious"] += 1

        # Handle folder copying based on strategy
        if strategy == "smart":
            # Smart strategy: Create only individual malicious code files
            if decision_lower in ["suspicious", "malicious"] and decision.file_extracts:
                # Ensure target folder exists
                target_folder.mkdir(parents=True, exist_ok=True)

                # Create individual files with only malicious code for ML training
                for filename, malicious_code in decision.file_extracts.items():
                    try:
                        # Create file with original name and extension
                        dest_file = target_folder / filename

                        # If file exists, add folder prefix to avoid conflicts
                        if dest_file.exists():
                            file_path = Path(filename)
                            stem = file_path.stem
                            suffix = file_path.suffix
                            dest_file = (
                                target_folder / f"{child_dir.name}_{stem}{suffix}"
                            )

                        # Create parent directories if they don't exist
                        dest_file.parent.mkdir(parents=True, exist_ok=True)

                        # Write only the malicious code parts
                        with open(dest_file, "w", encoding="utf-8") as f:
                            # Convert \n escape sequences to actual line breaks
                            formatted_code = malicious_code.replace(
                                "\\n", "\n"
                            ).replace("\\t", "\t")
                            f.write(formatted_code)

                        files_created[decision_lower] += 1
                    except Exception as e:
                        error(f"  Failed to create malicious code file {filename}: {e}")
            # Skip logging for non-extracted files to reduce noise
        else:
            # Other strategies: Copy entire folder to target location
            try:
                dest_folder = target_folder / child_dir.name
                if dest_folder.exists():
                    shutil.rmtree(dest_folder)
                shutil.copytree(child_dir, dest_folder)
            except Exception as e:
                error(f"  Failed to copy folder {child_dir.name}: {e}")

    # Print summary table
    print(f"\nTriage Complete: {output_base}")

    # Prepare data for table
    table_data = [
        ["Benign", total_stats["benign"]],
        ["Suspicious", total_stats["suspicious"]],
        ["Malicious", total_stats["malicious"]],
    ]

    if strategy == "smart":
        total_files = files_created["suspicious"] + files_created["malicious"]
        table_data.extend(
            [
                ["", ""],  # Empty row separator
                ["Files Created", total_files],
                ["  - Suspicious", files_created["suspicious"]],
                ["  - Malicious", files_created["malicious"]],
            ]
        )

    print(tabulate(table_data, headers=["Category", "Count"], tablefmt="simple"))


def _analyze_folder_concat(first_responder, child_dir, files_to_analyze):
    """
    Analyze a folder by concatenating all files and sending them together to the LLM.

    Args:
        first_responder: FirstResponder agent instance
        child_dir: Path object for the directory being analyzed
        files_to_analyze: List of file paths to analyze

    Returns:
        TriageDecision object with the folder decision
    """
    # Read and concatenate file contents
    concatenated_content = ""
    file_map = {}  # Map file content markers to actual paths

    for file_path in files_to_analyze:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Clean content of control characters that can break JSON
                import re

                content = re.sub(r"[\x00-\x1f\x7f]", "", content)
                # Use relative path from child_dir for cleaner output
                rel_path = file_path.relative_to(child_dir)
                file_marker = f"{child_dir.name}/{rel_path}"
                concatenated_content += f"\n### FILE: {file_marker}\n{content}\n"
                file_map[file_marker] = file_path
        except Exception as e:
            error(f"  Error reading {file_path}: {e}")
            continue

    if concatenated_content:
        # Analyze folder with FirstResponder - gets single decision for entire folder
        return first_responder.analyze_files_sync(concatenated_content)
    else:
        from cli.agents.first_responder import TriageDecision

        return TriageDecision(
            decision="suspicious", reasoning="No readable files found"
        )


def _analyze_folder_single(first_responder, child_dir, files_to_analyze):
    """
    Analyze a folder by sending each file individually to the LLM and aggregating decisions.

    Args:
        first_responder: FirstResponder agent instance
        child_dir: Path object for the directory being analyzed
        files_to_analyze: List of file paths to analyze

    Returns:
        TriageDecision object with the aggregated folder decision
    """
    from cli.agents.first_responder import TriageDecision

    decisions = []
    malicious_files = []
    suspicious_files = []
    benign_files = []

    info(f"  Analyzing {len(files_to_analyze)} files individually...")

    for i, file_path in enumerate(files_to_analyze, 1):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Clean content of control characters that can break JSON
                import re

                content = re.sub(r"[\x00-\x1f\x7f]", "", content)

                # Use relative path for cleaner output
                rel_path = file_path.relative_to(child_dir)
                file_marker = f"{child_dir.name}/{rel_path}"
                file_content = f"### FILE: {file_marker}\n{content}\n"

                info(f"    [{i}/{len(files_to_analyze)}] {rel_path}")

                # Analyze single file
                decision = first_responder.analyze_files_sync(file_content)
                decisions.append(decision)

                # Categorize decision
                decision_lower = decision.decision.lower()
                if decision_lower == "malicious":
                    malicious_files.append(rel_path)
                elif decision_lower == "suspicious":
                    suspicious_files.append(rel_path)
                else:
                    benign_files.append(rel_path)

        except Exception as e:
            error(f"  Error reading {file_path}: {e}")
            # Treat unreadable files as suspicious
            suspicious_files.append(file_path.relative_to(child_dir))
            continue

    # Aggregate decisions using a simple priority system:
    # If any file is malicious -> folder is malicious
    # If no malicious but some suspicious -> folder is suspicious
    # If all benign -> folder is benign

    if malicious_files:
        reasoning = f"Contains {len(malicious_files)} malicious file(s): {', '.join(str(f) for f in malicious_files[:3])}"
        if len(malicious_files) > 3:
            reasoning += f" and {len(malicious_files) - 3} more"
        return TriageDecision(decision="malicious", reasoning=reasoning)
    elif suspicious_files:
        reasoning = f"Contains {len(suspicious_files)} suspicious file(s): {', '.join(str(f) for f in suspicious_files[:3])}"
        if len(suspicious_files) > 3:
            reasoning += f" and {len(suspicious_files) - 3} more"
        return TriageDecision(decision="suspicious", reasoning=reasoning)
    else:
        reasoning = f"All {len(benign_files)} files appear benign"
        return TriageDecision(decision="benign", reasoning=reasoning)


def _analyze_folder_smart(first_responder, child_dir, files_to_analyze):
    """
    Analyze a folder by concatenating all files and sending them together to the LLM
    with smart extraction of malicious code parts.

    Args:
        first_responder: FirstResponder agent instance
        child_dir: Path object for the directory being analyzed
        files_to_analyze: List of file paths to analyze

    Returns:
        TriageDecision object with the folder decision and extracted malicious code
    """
    # Read and concatenate file contents (same as concat strategy)
    concatenated_content = ""
    file_map = {}  # Map file content markers to actual paths

    for file_path in files_to_analyze:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Clean content of control characters that can break JSON
                import re

                content = re.sub(r"[\x00-\x1f\x7f]", "", content)
                # Use relative path from child_dir for cleaner output
                rel_path = file_path.relative_to(child_dir)
                file_marker = f"{child_dir.name}/{rel_path}"
                concatenated_content += f"\n### FILE: {file_marker}\n{content}\n"
                file_map[file_marker] = file_path
        except Exception as e:
            error(f"  Error reading {file_path}: {e}")
            continue

    if concatenated_content:
        # Analyze folder with FirstResponder using smart analysis
        return first_responder.analyze_files_sync_smart(concatenated_content)
    else:
        from cli.agents.first_responder import TriageDecision

        return TriageDecision(
            decision="suspicious", reasoning="No readable files found"
        )
