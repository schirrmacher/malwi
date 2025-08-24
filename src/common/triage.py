"""
Triage functionality for analyzing files with LLM models and organizing them.
"""

import asyncio
import re
import shutil
import time
from pathlib import Path

from tqdm import tqdm
from common.messaging import info, error
from common.files import collect_files_by_extension
from common.config import SUPPORTED_EXTENSIONS
from cli.agents.first_responder import FirstResponder


def _validate_input_path(input_path: str) -> Path:
    """Validate that the input path exists and is a directory."""
    path = Path(input_path)
    if not path.exists():
        raise ValueError(f"Path does not exist: {input_path}")
    if not path.is_dir():
        raise ValueError(f"Path must be a directory: {input_path}")
    return path


def _setup_output_directories(
    output_dir: str, benign_folder: str, suspicious_folder: str, malicious_folder: str
) -> tuple[Path, Path, Path, Path]:
    """Create and clean output directories for triage results."""
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

    return output_base, benign_path, suspicious_path, malicious_path


def _get_child_directories(path: Path) -> list[Path]:
    """Get immediate child directories or return the path itself if no children."""
    child_dirs = [d for d in path.iterdir() if d.is_dir()]
    return child_dirs if child_dirs else [path]


def _collect_analyzable_files(child_dir: Path) -> list[Path]:
    """Collect files for analysis using supported extensions."""
    files_to_analyze, _ = collect_files_by_extension(
        child_dir, SUPPORTED_EXTENSIONS, silent=True
    )
    return files_to_analyze


def _get_analysis_strategy(
    strategy: str, first_responder, child_dir: Path, files_to_analyze: list[Path]
):
    """Execute the appropriate analysis strategy."""
    if strategy == "concat":
        return _analyze_folder_concat(first_responder, child_dir, files_to_analyze)
    elif strategy == "single":
        return _analyze_folder_single(first_responder, child_dir, files_to_analyze)
    else:  # smart
        return _analyze_folder_smart(first_responder, child_dir, files_to_analyze)


def _determine_target_folder(
    decision_lower: str, benign_path: Path, suspicious_path: Path, malicious_path: Path
) -> Path:
    """Determine the target folder based on the decision."""
    if decision_lower == "benign":
        return benign_path
    elif decision_lower == "malicious":
        return malicious_path
    else:  # suspicious
        return suspicious_path


def _create_unique_filename(target_folder: Path, filename: str) -> Path:
    """Create a unique filename to avoid conflicts."""
    dest_file = target_folder / filename

    if dest_file.exists():
        file_path = Path(filename)
        stem = file_path.stem
        suffix = file_path.suffix
        counter = 1
        while dest_file.exists():
            dest_file = target_folder / f"{stem}_{counter}{suffix}"
            counter += 1

    return dest_file


def _handle_smart_strategy(
    decision, decision_lower: str, target_folder: Path, files_created: dict
) -> None:
    """Handle file creation for smart strategy."""
    if decision_lower not in ["suspicious", "malicious"]:
        return

    target_folder.mkdir(parents=True, exist_ok=True)

    if not decision.file_extracts:
        return

    for filename, malicious_code in decision.file_extracts.items():
        try:
            dest_file = _create_unique_filename(target_folder, filename)
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            # Write only the malicious code parts
            with open(dest_file, "w", encoding="utf-8") as f:
                # Convert escape sequences to actual characters
                formatted_code = malicious_code.replace("\\n", "\n").replace(
                    "\\t", "\t"
                )
                f.write(formatted_code)

            files_created[decision_lower] += 1
        except Exception as e:
            error(f"  Failed to create malicious code file {filename}: {e}")


def _handle_standard_strategy(child_dir: Path, target_folder: Path) -> None:
    """Handle folder copying for standard strategies."""
    try:
        dest_folder = target_folder / child_dir.name
        if dest_folder.exists():
            shutil.rmtree(dest_folder)
        shutil.copytree(child_dir, dest_folder)
    except Exception as e:
        error(f"  Failed to copy folder {child_dir.name}: {e}")


def _print_triage_summary(
    input_path: str, elapsed_time: float, total_files_analyzed: int, total_stats: dict
) -> None:
    """Print the final triage summary."""
    total_folders = (
        total_stats["malicious"] + total_stats["suspicious"] + total_stats["benign"]
    )

    print()
    print(f"- target: {input_path}")
    print(f"- seconds: {elapsed_time:.2f}")
    print(f"- triaged: {total_folders} folders")
    print(f"  ├── malicious: {total_stats['malicious']}")
    print(f"  ├── suspicious: {total_stats['suspicious']}")
    print(f"  └── benign: {total_stats['benign']}")


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
        strategy: Triage strategy - 'concat', 'single', or 'smart'
    """
    # Validate input and setup
    path = _validate_input_path(input_path)
    first_responder = FirstResponder(api_key, llm_model, base_url)
    output_base, benign_path, suspicious_path, malicious_path = (
        _setup_output_directories(
            output_dir, benign_folder, suspicious_folder, malicious_folder
        )
    )

    # Initialize tracking variables
    child_dirs = _get_child_directories(path)
    total_stats = {"benign": 0, "suspicious": 0, "malicious": 0}
    files_created = {"suspicious": 0, "malicious": 0}
    total_files_analyzed = 0
    start_time = time.time()

    # Process each directory
    for child_dir in tqdm(child_dirs, desc="Analyzing directories"):
        files_to_analyze = _collect_analyzable_files(child_dir)

        if not files_to_analyze:
            continue

        total_files_analyzed += len(files_to_analyze)

        # Analyze files using selected strategy
        decision = _get_analysis_strategy(
            strategy, first_responder, child_dir, files_to_analyze
        )

        # Update statistics and determine target folder
        decision_lower = decision.decision.lower()
        target_folder = _determine_target_folder(
            decision_lower, benign_path, suspicious_path, malicious_path
        )
        total_stats[decision_lower] += 1

        # Handle file/folder creation based on strategy
        if strategy == "smart":
            _handle_smart_strategy(
                decision, decision_lower, target_folder, files_created
            )
        else:
            _handle_standard_strategy(child_dir, target_folder)

    # Print final summary
    elapsed_time = time.time() - start_time
    _print_triage_summary(input_path, elapsed_time, total_files_analyzed, total_stats)


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
        result = first_responder.analyze_files_sync(concatenated_content)
        # Handle both sync and async returns for testing compatibility
        if asyncio.iscoroutine(result):
            return asyncio.run(result)
        else:
            return result
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

    # Create sub-progress bar for individual file analysis
    for file_path in tqdm(
        files_to_analyze, desc=f"  Files in {child_dir.name}", leave=False
    ):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Clean content of control characters that can break JSON
                content = re.sub(r"[\x00-\x1f\x7f]", "", content)

                # Use relative path for cleaner output
                rel_path = file_path.relative_to(child_dir)
                file_marker = f"{child_dir.name}/{rel_path}"
                file_content = f"### FILE: {file_marker}\n{content}\n"

                # Analyze single file
                result = first_responder.analyze_files_sync(file_content)
                # Handle both sync and async returns for testing compatibility
                if asyncio.iscoroutine(result):
                    decision = asyncio.run(result)
                else:
                    decision = result
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
        result = first_responder.analyze_files_sync_smart(concatenated_content)
        # Handle both sync and async returns for testing compatibility
        if asyncio.iscoroutine(result):
            return asyncio.run(result)
        else:
            return result
    else:
        from cli.agents.first_responder import TriageDecision

        return TriageDecision(
            decision="suspicious", reasoning="No readable files found"
        )
